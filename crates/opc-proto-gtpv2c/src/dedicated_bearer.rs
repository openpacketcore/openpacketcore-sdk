//! Typed S2b Create Bearer and Delete Bearer procedure models.
//!
//! This module implements TS 29.274 Release 18 procedure tables 7.2.3,
//! 7.2.4, 7.2.9.2, and 7.2.10.2 for the S2b interface. Product policy,
//! identifier allocation, and dataplane programming remain outside the
//! protocol boundary.

use core::fmt;

use opc_proto_tft::TrafficFlowTemplate;
use opc_protocol::{DecodeError, DecodeErrorCode, SpecRef};

use crate::ie::{
    BearerContext, BearerQos, CauseValue, ChargingId, EpsBearerId, FullyQualifiedTeid, TypedIe,
    TypedIeValue, IE_TYPE_BEARER_CONTEXT, IE_TYPE_BEARER_QOS, IE_TYPE_BEARER_TFT, IE_TYPE_CAUSE,
    IE_TYPE_CHARGING_ID, IE_TYPE_EBI, IE_TYPE_F_TEID,
};
use crate::s2b::{
    build_s2b_profile_message, cause, typed_ie, MessageDirection, Procedure, S2bProcedureMessage,
    S2bProfileBuildResult, CREATE_BEARER_REQUEST, CREATE_BEARER_RESPONSE, DELETE_BEARER_REQUEST,
    DELETE_BEARER_RESPONSE, INTERFACE_TYPE_S2B_U_EPDG_GTP_U, INTERFACE_TYPE_S2B_U_PGW_GTP_U,
};
use crate::{Header, OwnedMessage};

/// Maximum bearer contexts retained by one dedicated-bearer procedure.
///
/// The EBI field is four bits and value zero is reserved by Create Bearer
/// Request as the "allocate" marker. This bound also prevents a procedure
/// model from allocating an unbounded list independently of `DecodeContext`.
pub const MAX_DEDICATED_BEARER_CONTEXTS: usize = 15;

/// Stable validation category for a dedicated-bearer message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedicatedBearerErrorKind {
    /// Message is not the expected procedure and direction.
    WrongProcedure,
    /// EPC-specific message omitted the mandatory TEID header field.
    MissingHeaderTeid,
    /// A request used TEID zero where TS 29.274 does not permit it.
    ZeroRequestTeid,
    /// An accepted response used TEID zero.
    ZeroAcceptedResponseTeid,
    /// Linked EBI is missing.
    MissingLinkedEbi,
    /// EBI value is outside the non-zero 1 through 15 range.
    InvalidEbi,
    /// Create Bearer Request nested EBI was not zero.
    CreateRequestEbiNotZero,
    /// A required bearer-context list is empty.
    MissingBearerContexts,
    /// Bearer-context list exceeds the bounded EBI space.
    TooManyBearerContexts,
    /// A required nested EBI is missing.
    MissingBearerEbi,
    /// A required TFT is missing.
    MissingBearerTft,
    /// A required Bearer QoS is missing.
    MissingBearerQos,
    /// A required S2b-U PGW F-TEID is missing.
    MissingPgwFTeid,
    /// The S2b Create Bearer Request omitted its Charging ID.
    MissingChargingId,
    /// A required S2b-U ePDG F-TEID is missing.
    MissingEpdgFTeid,
    /// An IE used an instance not assigned by the S2b procedure table.
    WrongIeInstance,
    /// An F-TEID used an interface type not assigned to its S2b position.
    WrongFTeidInterface,
    /// A known singleton appeared more than once.
    DuplicateSingleton,
    /// A bearer identifier or correlation F-TEID appeared more than once.
    DuplicateBearerCorrelation,
    /// Message-level or bearer-level Cause is missing.
    MissingCause,
    /// Cause is not legal in a response position.
    InvalidResponseCause,
    /// A rejected bearer unexpectedly allocated an ePDG F-TEID.
    RejectedBearerHasEpdgFTeid,
    /// Message-level Cause disagrees with bearer-level outcomes.
    InconsistentResponseOutcome,
    /// Delete Bearer Request/Response combined linked and dedicated forms.
    ConflictingDeleteForms,
    /// Delete Bearer Request/Response contains neither legal form.
    MissingDeleteForm,
    /// Delete Bearer Request contains an invalid initial-message Cause.
    InvalidDeleteRequestCause,
    /// Response has a different number of bearer results than the request.
    CorrelationCountMismatch,
    /// Response bearer result cannot be correlated with the request.
    CorrelationMismatch,
}

impl DedicatedBearerErrorKind {
    /// Stable machine-readable code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WrongProcedure => "gtpv2c_dedicated_wrong_procedure",
            Self::MissingHeaderTeid => "gtpv2c_dedicated_header_teid_missing",
            Self::ZeroRequestTeid => "gtpv2c_dedicated_request_teid_zero",
            Self::ZeroAcceptedResponseTeid => "gtpv2c_dedicated_accepted_response_teid_zero",
            Self::MissingLinkedEbi => "gtpv2c_dedicated_linked_ebi_missing",
            Self::InvalidEbi => "gtpv2c_dedicated_ebi_invalid",
            Self::CreateRequestEbiNotZero => "gtpv2c_create_bearer_request_ebi_not_zero",
            Self::MissingBearerContexts => "gtpv2c_dedicated_bearer_context_missing",
            Self::TooManyBearerContexts => "gtpv2c_dedicated_bearer_context_count_exceeded",
            Self::MissingBearerEbi => "gtpv2c_dedicated_bearer_ebi_missing",
            Self::MissingBearerTft => "gtpv2c_create_bearer_tft_missing",
            Self::MissingBearerQos => "gtpv2c_create_bearer_qos_missing",
            Self::MissingPgwFTeid => "gtpv2c_create_bearer_pgw_fteid_missing",
            Self::MissingChargingId => "gtpv2c_create_bearer_charging_id_missing",
            Self::MissingEpdgFTeid => "gtpv2c_create_bearer_epdg_fteid_missing",
            Self::WrongIeInstance => "gtpv2c_dedicated_ie_instance_invalid",
            Self::WrongFTeidInterface => "gtpv2c_dedicated_fteid_interface_invalid",
            Self::DuplicateSingleton => "gtpv2c_dedicated_singleton_duplicate",
            Self::DuplicateBearerCorrelation => "gtpv2c_dedicated_correlation_duplicate",
            Self::MissingCause => "gtpv2c_dedicated_cause_missing",
            Self::InvalidResponseCause => "gtpv2c_dedicated_response_cause_invalid",
            Self::RejectedBearerHasEpdgFTeid => "gtpv2c_create_bearer_rejected_epdg_fteid_present",
            Self::InconsistentResponseOutcome => "gtpv2c_dedicated_response_outcome_inconsistent",
            Self::ConflictingDeleteForms => "gtpv2c_delete_bearer_forms_conflict",
            Self::MissingDeleteForm => "gtpv2c_delete_bearer_form_missing",
            Self::InvalidDeleteRequestCause => "gtpv2c_delete_bearer_request_cause_invalid",
            Self::CorrelationCountMismatch => "gtpv2c_dedicated_correlation_count_mismatch",
            Self::CorrelationMismatch => "gtpv2c_dedicated_correlation_mismatch",
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::WrongProcedure => "unexpected dedicated-bearer procedure or direction",
            Self::MissingHeaderTeid => "dedicated-bearer message requires the TEID header field",
            Self::ZeroRequestTeid => "dedicated-bearer request TEID must be non-zero",
            Self::ZeroAcceptedResponseTeid => {
                "accepted dedicated-bearer response TEID must be non-zero"
            }
            Self::MissingLinkedEbi => "Create Bearer Request requires linked EBI instance 0",
            Self::InvalidEbi => "dedicated-bearer EBI must be in the range 1 through 15",
            Self::CreateRequestEbiNotZero => {
                "Create Bearer Request bearer-context EBI must be zero"
            }
            Self::MissingBearerContexts => "dedicated-bearer message requires bearer contexts",
            Self::TooManyBearerContexts => "dedicated-bearer context count exceeds EBI space",
            Self::MissingBearerEbi => "dedicated-bearer context requires EBI instance 0",
            Self::MissingBearerTft => {
                "Create Bearer Request context requires Bearer TFT instance 0"
            }
            Self::MissingBearerQos => {
                "Create Bearer Request context requires Bearer QoS instance 0"
            }
            Self::MissingPgwFTeid => "dedicated-bearer context requires S2b-U PGW F-TEID",
            Self::MissingChargingId => {
                "S2b Create Bearer Request context requires Charging ID instance 0"
            }
            Self::MissingEpdgFTeid => {
                "accepted Create Bearer Response context requires S2b-U ePDG F-TEID"
            }
            Self::WrongIeInstance => "dedicated-bearer IE uses an invalid instance",
            Self::WrongFTeidInterface => "dedicated-bearer F-TEID interface type is invalid",
            Self::DuplicateSingleton => "dedicated-bearer singleton IE is duplicated",
            Self::DuplicateBearerCorrelation => {
                "dedicated-bearer identifier or correlation F-TEID is duplicated"
            }
            Self::MissingCause => "dedicated-bearer response requires Cause instance 0",
            Self::InvalidResponseCause => "dedicated-bearer response Cause is invalid",
            Self::RejectedBearerHasEpdgFTeid => {
                "rejected Create Bearer result must not allocate an ePDG F-TEID"
            }
            Self::InconsistentResponseOutcome => {
                "message Cause is inconsistent with bearer-level results"
            }
            Self::ConflictingDeleteForms => {
                "Delete Bearer linked and dedicated forms are mutually exclusive"
            }
            Self::MissingDeleteForm => "Delete Bearer message requires one target form",
            Self::InvalidDeleteRequestCause => "Delete Bearer Request Cause is invalid",
            Self::CorrelationCountMismatch => {
                "dedicated-bearer response count differs from request"
            }
            Self::CorrelationMismatch => {
                "dedicated-bearer response does not correlate with request"
            }
        }
    }
}

/// Structured, redaction-safe dedicated-bearer validation error.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DedicatedBearerError {
    kind: DedicatedBearerErrorKind,
    bearer_index: Option<usize>,
}

impl DedicatedBearerError {
    fn message(kind: DedicatedBearerErrorKind) -> Self {
        Self {
            kind,
            bearer_index: None,
        }
    }

    fn bearer(kind: DedicatedBearerErrorKind, bearer_index: usize) -> Self {
        Self {
            kind,
            bearer_index: Some(bearer_index),
        }
    }

    /// Stable validation category.
    #[must_use]
    pub const fn kind(self) -> DedicatedBearerErrorKind {
        self.kind
    }

    /// Zero-based bearer-context index, if the failure is context-specific.
    #[must_use]
    pub const fn bearer_index(self) -> Option<usize> {
        self.bearer_index
    }

    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.kind.as_str()
    }

    pub(crate) fn to_decode_error(self) -> DecodeError {
        DecodeError::new(
            DecodeErrorCode::Structural {
                reason: self.kind.reason(),
            },
            0,
        )
        .with_spec_ref(spec_ref())
    }
}

impl fmt::Debug for DedicatedBearerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DedicatedBearerError")
            .field("kind", &self.kind)
            .field("bearer_index", &self.bearer_index)
            .finish()
    }
}

impl fmt::Display for DedicatedBearerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for DedicatedBearerError {}

fn spec_ref() -> SpecRef {
    SpecRef::new("3gpp", "TS29274", "7.2.3-7.2.10.2")
}

/// One Bearer Context in an S2b Create Bearer Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S2bCreateBearerRequestContext<'a> {
    /// Canonical TS 24.008 TFT value.
    pub tft: TrafficFlowTemplate,
    /// Requested bearer-level QoS.
    pub bearer_qos: BearerQos,
    /// PGW-owned S2b-U tunnel endpoint (F-TEID instance 4, interface 33).
    pub pgw_f_teid: FullyQualifiedTeid,
    /// Charging ID required by the S2a/S2b row of Table 7.2.3-2.
    pub charging_id: ChargingId,
    /// Other conditional or extension IEs retained in original order.
    pub additional_ies: Vec<TypedIe<'a>>,
}

/// Typed S2b Create Bearer Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S2bCreateBearerRequest<'a> {
    /// GTPv2-C sequence number.
    pub sequence_number: u32,
    /// Receiver control-plane TEID in the request header.
    pub teid: u32,
    /// Default bearer associated with the PDN connection (EBI instance 0).
    pub linked_ebi: EpsBearerId,
    /// One or more requested dedicated bearer contexts.
    pub bearer_contexts: Vec<S2bCreateBearerRequestContext<'a>>,
    /// Other conditional or extension top-level IEs retained in order.
    pub additional_ies: Vec<TypedIe<'a>>,
}

/// One bearer-level result in an S2b Create Bearer Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S2bCreateBearerResult<'a> {
    /// Bearer was installed successfully.
    Accepted {
        /// Allocated dedicated EBI.
        ebi: EpsBearerId,
        /// ePDG-owned S2b-U endpoint (F-TEID instance 8, interface 31).
        epdg_f_teid: FullyQualifiedTeid,
        /// Request PGW endpoint echoed for correlation (instance 9, interface 33).
        pgw_f_teid: FullyQualifiedTeid,
        /// Other conditional or extension nested IEs.
        additional_ies: Vec<TypedIe<'a>>,
    },
    /// Bearer was rejected without allocating an ePDG user-plane endpoint.
    Rejected {
        /// Bearer EBI reported by the application.
        ebi: EpsBearerId,
        /// Bearer-level rejection Cause.
        cause: CauseValue,
        /// Request PGW endpoint echoed for correlation (instance 9, interface 33).
        pgw_f_teid: FullyQualifiedTeid,
        /// Other conditional or extension nested IEs.
        additional_ies: Vec<TypedIe<'a>>,
    },
}

impl S2bCreateBearerResult<'_> {
    /// Return this result's EBI.
    #[must_use]
    pub const fn ebi(&self) -> EpsBearerId {
        match self {
            Self::Accepted { ebi, .. } | Self::Rejected { ebi, .. } => *ebi,
        }
    }

    /// Return the PGW F-TEID used to correlate the request context.
    #[must_use]
    pub const fn pgw_f_teid(&self) -> &FullyQualifiedTeid {
        match self {
            Self::Accepted { pgw_f_teid, .. } | Self::Rejected { pgw_f_teid, .. } => pgw_f_teid,
        }
    }

    /// Return the normative bearer-level Cause.
    #[must_use]
    pub const fn cause(&self) -> CauseValue {
        match self {
            Self::Accepted { .. } => CauseValue::RequestAccepted,
            Self::Rejected { cause, .. } => *cause,
        }
    }

    /// Return `true` when this bearer was accepted.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }
}

/// Typed S2b Create Bearer Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S2bCreateBearerResponse<'a> {
    /// GTPv2-C sequence number copied from the request.
    pub sequence_number: u32,
    /// Receiver control-plane TEID in the response header.
    pub teid: u32,
    /// Message-level acceptance, partial acceptance, or rejection Cause.
    pub cause: CauseValue,
    /// One result for every request Bearer Context.
    pub bearer_contexts: Vec<S2bCreateBearerResult<'a>>,
    /// Other conditional or extension top-level IEs retained in order.
    pub additional_ies: Vec<TypedIe<'a>>,
}

/// Mutually exclusive Delete Bearer Request target form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S2bDeleteBearerTarget {
    /// Delete the default bearer and all bearers in the PDN connection.
    Linked(EpsBearerId),
    /// Delete one or more dedicated bearers, encoded as EBI instance 1.
    Dedicated(Vec<EpsBearerId>),
}

/// Typed S2b Delete Bearer Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S2bDeleteBearerRequest<'a> {
    /// GTPv2-C sequence number.
    pub sequence_number: u32,
    /// Receiver control-plane TEID in the request header.
    pub teid: u32,
    /// Exactly one delete target form.
    pub target: S2bDeleteBearerTarget,
    /// Optional initial-message Cause defined by Table 7.2.9.2-1.
    pub cause: Option<CauseValue>,
    /// Other conditional or extension top-level IEs retained in order.
    pub additional_ies: Vec<TypedIe<'a>>,
}

/// One dedicated bearer result in Delete Bearer Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S2bDeleteBearerResult<'a> {
    /// Dedicated EBI from the request.
    pub ebi: EpsBearerId,
    /// Bearer-level acceptance or rejection Cause.
    pub cause: CauseValue,
    /// Other conditional or extension nested IEs retained in order.
    pub additional_ies: Vec<TypedIe<'a>>,
}

/// Mutually exclusive Delete Bearer Response form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S2bDeleteBearerResponseBody<'a> {
    /// Response for deleting a default bearer/PDN connection.
    Linked(EpsBearerId),
    /// One result for every dedicated bearer in the request.
    Dedicated(Vec<S2bDeleteBearerResult<'a>>),
}

/// Typed S2b Delete Bearer Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S2bDeleteBearerResponse<'a> {
    /// GTPv2-C sequence number copied from the request.
    pub sequence_number: u32,
    /// Receiver control-plane TEID in the response header.
    pub teid: u32,
    /// Message-level acceptance, partial acceptance, or rejection Cause.
    pub cause: CauseValue,
    /// Response form corresponding to the request form.
    pub body: S2bDeleteBearerResponseBody<'a>,
    /// Other conditional or extension top-level IEs retained in order.
    pub additional_ies: Vec<TypedIe<'a>>,
}

impl S2bProcedureMessage<'_> {
    /// Project a validated S2b Create Bearer Request.
    ///
    /// # Errors
    ///
    /// Returns a structured error for an incorrect procedure/header, missing
    /// or mis-instanced mandatory IE, invalid S2b F-TEID, or duplicate
    /// correlation key.
    pub fn create_bearer_request(
        &self,
    ) -> Result<S2bCreateBearerRequest<'_>, DedicatedBearerError> {
        project_create_bearer_request(self)
    }

    /// Project a validated S2b Create Bearer Response.
    ///
    /// # Errors
    ///
    /// Returns a structured error for an incorrect procedure/header, invalid
    /// message/bearer Cause relationship, malformed S2b F-TEID correlation,
    /// or invalid EBI assignment.
    pub fn create_bearer_response(
        &self,
    ) -> Result<S2bCreateBearerResponse<'_>, DedicatedBearerError> {
        project_create_bearer_response(self)
    }

    /// Project a validated S2b Delete Bearer Request.
    ///
    /// # Errors
    ///
    /// Returns a structured error when the linked and dedicated forms are
    /// absent, combined, duplicated, or otherwise invalid.
    pub fn delete_bearer_request(
        &self,
    ) -> Result<S2bDeleteBearerRequest<'_>, DedicatedBearerError> {
        project_delete_bearer_request(self)
    }

    /// Project a validated S2b Delete Bearer Response.
    ///
    /// # Errors
    ///
    /// Returns a structured error when the response form or Cause hierarchy
    /// violates TS 29.274.
    pub fn delete_bearer_response(
        &self,
    ) -> Result<S2bDeleteBearerResponse<'_>, DedicatedBearerError> {
        project_delete_bearer_response(self)
    }
}

fn ensure_procedure(
    view: &S2bProcedureMessage<'_>,
    procedure: Procedure,
    direction: MessageDirection,
) -> Result<u32, DedicatedBearerError> {
    if view.procedure != procedure || view.direction != direction {
        return Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::WrongProcedure,
        ));
    }
    if !view.header.teid_flag {
        return Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::MissingHeaderTeid,
        ));
    }
    view.header
        .teid
        .ok_or_else(|| DedicatedBearerError::message(DedicatedBearerErrorKind::MissingHeaderTeid))
}

fn ensure_request_header(
    view: &S2bProcedureMessage<'_>,
    procedure: Procedure,
) -> Result<u32, DedicatedBearerError> {
    let teid = ensure_procedure(view, procedure, MessageDirection::Request)?;
    if teid == 0 {
        return Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::ZeroRequestTeid,
        ));
    }
    Ok(teid)
}

fn single_ie<'b, 'a>(
    ies: &'b [TypedIe<'a>],
    ie_type: u8,
    instance: u8,
    missing: DedicatedBearerErrorKind,
    bearer_index: Option<usize>,
) -> Result<&'b TypedIe<'a>, DedicatedBearerError> {
    let mut found = None;
    for ie in ies.iter().filter(|ie| ie.ie_type() == ie_type) {
        if ie.instance != instance {
            return Err(context_error(
                DedicatedBearerErrorKind::WrongIeInstance,
                bearer_index,
            ));
        }
        if found.replace(ie).is_some() {
            return Err(context_error(
                DedicatedBearerErrorKind::DuplicateSingleton,
                bearer_index,
            ));
        }
    }
    found.ok_or_else(|| context_error(missing, bearer_index))
}

fn optional_single_ie<'b, 'a>(
    ies: &'b [TypedIe<'a>],
    ie_type: u8,
    instance: u8,
    bearer_index: Option<usize>,
) -> Result<Option<&'b TypedIe<'a>>, DedicatedBearerError> {
    let mut found = None;
    for ie in ies.iter().filter(|ie| ie.ie_type() == ie_type) {
        if ie.instance != instance {
            return Err(context_error(
                DedicatedBearerErrorKind::WrongIeInstance,
                bearer_index,
            ));
        }
        if found.replace(ie).is_some() {
            return Err(context_error(
                DedicatedBearerErrorKind::DuplicateSingleton,
                bearer_index,
            ));
        }
    }
    Ok(found)
}

fn context_error(
    kind: DedicatedBearerErrorKind,
    bearer_index: Option<usize>,
) -> DedicatedBearerError {
    match bearer_index {
        Some(index) => DedicatedBearerError::bearer(kind, index),
        None => DedicatedBearerError::message(kind),
    }
}

fn nonzero_ebi(
    ebi: EpsBearerId,
    bearer_index: Option<usize>,
) -> Result<EpsBearerId, DedicatedBearerError> {
    if (1..=15).contains(&ebi.value) {
        Ok(ebi)
    } else {
        Err(context_error(
            DedicatedBearerErrorKind::InvalidEbi,
            bearer_index,
        ))
    }
}

fn bearer_contexts<'b, 'a>(
    ies: &'b [TypedIe<'a>],
) -> Result<Vec<&'b BearerContext<'a>>, DedicatedBearerError> {
    let mut contexts = Vec::new();
    for ie in ies
        .iter()
        .filter(|ie| ie.ie_type() == IE_TYPE_BEARER_CONTEXT)
    {
        if ie.instance != 0 {
            return Err(DedicatedBearerError::message(
                DedicatedBearerErrorKind::WrongIeInstance,
            ));
        }
        let TypedIeValue::BearerContext(context) = &ie.value else {
            return Err(DedicatedBearerError::message(
                DedicatedBearerErrorKind::MissingBearerContexts,
            ));
        };
        contexts.push(context);
    }
    if contexts.is_empty() {
        return Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::MissingBearerContexts,
        ));
    }
    if contexts.len() > MAX_DEDICATED_BEARER_CONTEXTS {
        return Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::TooManyBearerContexts,
        ));
    }
    Ok(contexts)
}

fn top_level_additional<'a>(ies: &[TypedIe<'a>], excluded_types: &[u8]) -> Vec<TypedIe<'a>> {
    ies.iter()
        .filter(|ie| !excluded_types.contains(&ie.ie_type()))
        .cloned()
        .collect()
}

fn nested_additional<'a>(members: &[TypedIe<'a>], excluded_types: &[u8]) -> Vec<TypedIe<'a>> {
    members
        .iter()
        .filter(|ie| !excluded_types.contains(&ie.ie_type()))
        .cloned()
        .collect()
}

fn typed_ebi(
    ie: &TypedIe<'_>,
    bearer_index: Option<usize>,
) -> Result<EpsBearerId, DedicatedBearerError> {
    match &ie.value {
        TypedIeValue::EpsBearerId(ebi) => Ok(*ebi),
        _ => Err(context_error(
            DedicatedBearerErrorKind::MissingBearerEbi,
            bearer_index,
        )),
    }
}

fn typed_cause(
    ie: &TypedIe<'_>,
    bearer_index: Option<usize>,
) -> Result<CauseValue, DedicatedBearerError> {
    match &ie.value {
        TypedIeValue::Cause(cause) => Ok(cause.value),
        _ => Err(context_error(
            DedicatedBearerErrorKind::MissingCause,
            bearer_index,
        )),
    }
}

const fn is_common_response_rejection(cause: CauseValue) -> bool {
    // TS 29.274 R18 clause 7.7 requires the four protocol-error responses
    // below. Table 8.4-1 also defines the general feature, operational, and
    // unspecified-rejection causes that can apply to any request. Keep this
    // list explicit: `CauseValue::is_rejection` intentionally classifies the
    // full 64..=239 wire range, which includes reserved/spare values and
    // procedure-specific causes that must not be emitted here.
    matches!(
        cause,
        CauseValue::InvalidMessageFormat
            | CauseValue::InvalidLength
            | CauseValue::ServiceNotSupported
            | CauseValue::MandatoryIeIncorrect
            | CauseValue::MandatoryIeMissing
            | CauseValue::SystemFailure
            | CauseValue::NoResourcesAvailable
            | CauseValue::RequestRejected
            | CauseValue::ConditionalIeMissing
    )
}

const fn is_create_bearer_response_rejection(cause: CauseValue) -> bool {
    // TS 29.274 R18 clause 7.2.4 plus the common response causes above.
    is_common_response_rejection(cause)
        || matches!(
            cause,
            CauseValue::ContextNotFound
                | CauseValue::SemanticErrorInTftOperation
                | CauseValue::SyntacticErrorInTftOperation
                | CauseValue::SemanticErrorsInPacketFilters
                | CauseValue::SyntacticErrorsInPacketFilters
                | CauseValue::UnableToPageUe
                | CauseValue::UeNotResponding
                | CauseValue::UnableToPageUeDueToSuspension
                | CauseValue::UeRefuses
                | CauseValue::DeniedInRat
                | CauseValue::TemporarilyRejectedForMobilityProcedure
                | CauseValue::RefusedDueToVplmnPolicy
                | CauseValue::UeTemporarilyUnreachableDueToPowerSaving
                | CauseValue::RequestRejectedDueToUeCapability
        )
}

const fn valid_create_bearer_message_cause(cause: CauseValue) -> bool {
    matches!(
        cause,
        CauseValue::RequestAccepted | CauseValue::RequestAcceptedPartially
    ) || is_create_bearer_response_rejection(cause)
}

const fn valid_create_bearer_context_cause(cause: CauseValue) -> bool {
    matches!(cause, CauseValue::RequestAccepted) || is_create_bearer_response_rejection(cause)
}

const fn is_delete_bearer_response_rejection(cause: CauseValue) -> bool {
    // TS 29.274 R18 clause 7.2.10.2 plus the common response causes above.
    is_common_response_rejection(cause)
        || matches!(
            cause,
            CauseValue::ContextNotFound | CauseValue::TemporarilyRejectedForMobilityProcedure
        )
}

const fn valid_delete_bearer_message_cause(cause: CauseValue) -> bool {
    matches!(
        cause,
        CauseValue::RequestAccepted | CauseValue::RequestAcceptedPartially
    ) || is_delete_bearer_response_rejection(cause)
}

const fn valid_delete_bearer_context_cause(cause: CauseValue) -> bool {
    matches!(cause, CauseValue::RequestAccepted) || is_delete_bearer_response_rejection(cause)
}

fn ensure_outcome_consistency(
    message_cause: CauseValue,
    bearer_causes: impl Iterator<Item = CauseValue>,
) -> Result<(), DedicatedBearerError> {
    let mut total = 0usize;
    let mut accepted = 0usize;
    for cause in bearer_causes {
        total = total.saturating_add(1);
        if cause == CauseValue::RequestAccepted {
            accepted = accepted.saturating_add(1);
        }
    }
    let consistent = match message_cause {
        CauseValue::RequestAccepted => accepted == total,
        CauseValue::RequestAcceptedPartially => accepted > 0 && accepted < total,
        cause if cause.is_rejection() => accepted == 0,
        _ => false,
    };
    if consistent {
        Ok(())
    } else {
        Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::InconsistentResponseOutcome,
        ))
    }
}

fn project_create_bearer_request<'a>(
    view: &S2bProcedureMessage<'a>,
) -> Result<S2bCreateBearerRequest<'a>, DedicatedBearerError> {
    let teid = ensure_request_header(view, Procedure::CreateBearer)?;
    let linked_ebi = nonzero_ebi(
        typed_ebi(
            single_ie(
                &view.ies,
                IE_TYPE_EBI,
                0,
                DedicatedBearerErrorKind::MissingLinkedEbi,
                None,
            )?,
            None,
        )?,
        None,
    )?;
    let contexts = bearer_contexts(&view.ies)?;
    let mut projected = Vec::with_capacity(contexts.len());
    let mut correlation_keys = Vec::with_capacity(contexts.len());

    for (index, context) in contexts.into_iter().enumerate() {
        ensure_only_f_teid_instances(&context.members, &[4], index)?;
        let ebi = typed_ebi(
            single_ie(
                &context.members,
                IE_TYPE_EBI,
                0,
                DedicatedBearerErrorKind::MissingBearerEbi,
                Some(index),
            )?,
            Some(index),
        )?;
        if ebi.value != 0 {
            return Err(DedicatedBearerError::bearer(
                DedicatedBearerErrorKind::CreateRequestEbiNotZero,
                index,
            ));
        }

        let tft = match &single_ie(
            &context.members,
            IE_TYPE_BEARER_TFT,
            0,
            DedicatedBearerErrorKind::MissingBearerTft,
            Some(index),
        )?
        .value
        {
            TypedIeValue::BearerTft(tft) => tft.clone(),
            _ => {
                return Err(DedicatedBearerError::bearer(
                    DedicatedBearerErrorKind::MissingBearerTft,
                    index,
                ));
            }
        };
        let bearer_qos = match &single_ie(
            &context.members,
            IE_TYPE_BEARER_QOS,
            0,
            DedicatedBearerErrorKind::MissingBearerQos,
            Some(index),
        )?
        .value
        {
            TypedIeValue::BearerQos(qos) => qos.clone(),
            _ => {
                return Err(DedicatedBearerError::bearer(
                    DedicatedBearerErrorKind::MissingBearerQos,
                    index,
                ));
            }
        };
        let pgw_f_teid = f_teid_at(
            &context.members,
            4,
            INTERFACE_TYPE_S2B_U_PGW_GTP_U,
            DedicatedBearerErrorKind::MissingPgwFTeid,
            index,
        )?;
        if correlation_keys.contains(&pgw_f_teid) {
            return Err(DedicatedBearerError::bearer(
                DedicatedBearerErrorKind::DuplicateBearerCorrelation,
                index,
            ));
        }
        correlation_keys.push(pgw_f_teid.clone());
        let charging_id = match &single_ie(
            &context.members,
            IE_TYPE_CHARGING_ID,
            0,
            DedicatedBearerErrorKind::MissingChargingId,
            Some(index),
        )?
        .value
        {
            TypedIeValue::ChargingId(charging_id) => *charging_id,
            _ => {
                return Err(DedicatedBearerError::bearer(
                    DedicatedBearerErrorKind::MissingChargingId,
                    index,
                ));
            }
        };

        projected.push(S2bCreateBearerRequestContext {
            tft,
            bearer_qos,
            pgw_f_teid,
            charging_id,
            additional_ies: nested_additional(
                &context.members,
                &[
                    IE_TYPE_EBI,
                    IE_TYPE_BEARER_TFT,
                    IE_TYPE_BEARER_QOS,
                    IE_TYPE_F_TEID,
                    IE_TYPE_CHARGING_ID,
                ],
            ),
        });
    }

    Ok(S2bCreateBearerRequest {
        sequence_number: view.header.sequence_number,
        teid,
        linked_ebi,
        bearer_contexts: projected,
        additional_ies: top_level_additional(&view.ies, &[IE_TYPE_EBI, IE_TYPE_BEARER_CONTEXT]),
    })
}

fn f_teid_at(
    members: &[TypedIe<'_>],
    instance: u8,
    interface_type: u8,
    missing: DedicatedBearerErrorKind,
    bearer_index: usize,
) -> Result<FullyQualifiedTeid, DedicatedBearerError> {
    let mut expected = None;
    for ie in members.iter().filter(|ie| ie.ie_type() == IE_TYPE_F_TEID) {
        if ie.instance != instance {
            continue;
        }
        if expected.is_some() {
            return Err(DedicatedBearerError::bearer(
                DedicatedBearerErrorKind::DuplicateSingleton,
                bearer_index,
            ));
        }
        let TypedIeValue::FullyQualifiedTeid(f_teid) = &ie.value else {
            return Err(DedicatedBearerError::bearer(missing, bearer_index));
        };
        if f_teid.interface_type != interface_type {
            return Err(DedicatedBearerError::bearer(
                DedicatedBearerErrorKind::WrongFTeidInterface,
                bearer_index,
            ));
        }
        expected = Some(f_teid.clone());
    }
    expected.ok_or_else(|| DedicatedBearerError::bearer(missing, bearer_index))
}

fn ensure_only_f_teid_instances(
    members: &[TypedIe<'_>],
    allowed: &[u8],
    bearer_index: usize,
) -> Result<(), DedicatedBearerError> {
    if members
        .iter()
        .filter(|ie| ie.ie_type() == IE_TYPE_F_TEID)
        .any(|ie| !allowed.contains(&ie.instance))
    {
        Err(DedicatedBearerError::bearer(
            DedicatedBearerErrorKind::WrongIeInstance,
            bearer_index,
        ))
    } else {
        Ok(())
    }
}

fn project_create_bearer_response<'a>(
    view: &S2bProcedureMessage<'a>,
) -> Result<S2bCreateBearerResponse<'a>, DedicatedBearerError> {
    let teid = ensure_procedure(view, Procedure::CreateBearer, MessageDirection::Response)?;
    let message_cause = typed_cause(
        single_ie(
            &view.ies,
            IE_TYPE_CAUSE,
            0,
            DedicatedBearerErrorKind::MissingCause,
            None,
        )?,
        None,
    )?;
    if !valid_create_bearer_message_cause(message_cause) {
        return Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::InvalidResponseCause,
        ));
    }
    if message_cause.is_accepted() && teid == 0 {
        return Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::ZeroAcceptedResponseTeid,
        ));
    }

    let contexts = bearer_contexts(&view.ies)?;
    let mut projected = Vec::with_capacity(contexts.len());
    let mut response_ebis = Vec::with_capacity(contexts.len());
    let mut correlation_keys = Vec::with_capacity(contexts.len());
    for (index, context) in contexts.into_iter().enumerate() {
        ensure_only_f_teid_instances(&context.members, &[8, 9], index)?;
        let ebi = nonzero_ebi(
            typed_ebi(
                single_ie(
                    &context.members,
                    IE_TYPE_EBI,
                    0,
                    DedicatedBearerErrorKind::MissingBearerEbi,
                    Some(index),
                )?,
                Some(index),
            )?,
            Some(index),
        )?;
        if response_ebis.contains(&ebi) {
            return Err(DedicatedBearerError::bearer(
                DedicatedBearerErrorKind::DuplicateBearerCorrelation,
                index,
            ));
        }
        response_ebis.push(ebi);

        let bearer_cause = typed_cause(
            single_ie(
                &context.members,
                IE_TYPE_CAUSE,
                0,
                DedicatedBearerErrorKind::MissingCause,
                Some(index),
            )?,
            Some(index),
        )?;
        if !valid_create_bearer_context_cause(bearer_cause) {
            return Err(DedicatedBearerError::bearer(
                DedicatedBearerErrorKind::InvalidResponseCause,
                index,
            ));
        }
        let pgw_f_teid = f_teid_at(
            &context.members,
            9,
            INTERFACE_TYPE_S2B_U_PGW_GTP_U,
            DedicatedBearerErrorKind::MissingPgwFTeid,
            index,
        )?;
        if correlation_keys.contains(&pgw_f_teid) {
            return Err(DedicatedBearerError::bearer(
                DedicatedBearerErrorKind::DuplicateBearerCorrelation,
                index,
            ));
        }
        correlation_keys.push(pgw_f_teid.clone());
        let additional_ies = nested_additional(
            &context.members,
            &[IE_TYPE_EBI, IE_TYPE_CAUSE, IE_TYPE_F_TEID],
        );

        if bearer_cause == CauseValue::RequestAccepted {
            let epdg_f_teid = f_teid_at(
                &context.members,
                8,
                INTERFACE_TYPE_S2B_U_EPDG_GTP_U,
                DedicatedBearerErrorKind::MissingEpdgFTeid,
                index,
            )?;
            projected.push(S2bCreateBearerResult::Accepted {
                ebi,
                epdg_f_teid,
                pgw_f_teid,
                additional_ies,
            });
        } else {
            if context
                .members
                .iter()
                .any(|ie| ie.ie_type() == IE_TYPE_F_TEID && ie.instance == 8)
            {
                return Err(DedicatedBearerError::bearer(
                    DedicatedBearerErrorKind::RejectedBearerHasEpdgFTeid,
                    index,
                ));
            }
            projected.push(S2bCreateBearerResult::Rejected {
                ebi,
                cause: bearer_cause,
                pgw_f_teid,
                additional_ies,
            });
        }
    }
    ensure_outcome_consistency(message_cause, projected.iter().map(|result| result.cause()))?;

    Ok(S2bCreateBearerResponse {
        sequence_number: view.header.sequence_number,
        teid,
        cause: message_cause,
        bearer_contexts: projected,
        additional_ies: top_level_additional(&view.ies, &[IE_TYPE_CAUSE, IE_TYPE_BEARER_CONTEXT]),
    })
}

fn valid_delete_request_cause(cause: CauseValue) -> bool {
    // TS 29.274 Table 7.2.9.2-1 calls the S2a/S2b procedure reason "Local
    // release", while Table 8.4-1 assigns its wire value 2 the initial-Cause
    // name "Local Detach". `LocalDetach` is therefore the typed representation
    // of that S2b local-release request reason.
    matches!(
        cause,
        CauseValue::LocalDetach
            | CauseValue::RatChangedFrom3gppToNon3gpp
            | CauseValue::IsrDeactivation
            | CauseValue::ReactivationRequested
            | CauseValue::PdnReconnectionDisallowed
            | CauseValue::AccessChangedFromNon3gppTo3gpp
            | CauseValue::PdnConnectionInactivityTimerExpires
            | CauseValue::EpsTo5gsMobility
            | CauseValue::MultipleAccessesToPdnConnectionNotAllowed
    )
}

fn project_delete_bearer_request<'a>(
    view: &S2bProcedureMessage<'a>,
) -> Result<S2bDeleteBearerRequest<'a>, DedicatedBearerError> {
    let teid = ensure_request_header(view, Procedure::DeleteBearer)?;
    let mut linked = None;
    let mut dedicated = Vec::new();
    for ie in view.ies.iter().filter(|ie| ie.ie_type() == IE_TYPE_EBI) {
        let ebi = nonzero_ebi(typed_ebi(ie, None)?, None)?;
        match ie.instance {
            0 => {
                if linked.replace(ebi).is_some() {
                    return Err(DedicatedBearerError::message(
                        DedicatedBearerErrorKind::DuplicateSingleton,
                    ));
                }
            }
            1 => {
                if dedicated.contains(&ebi) {
                    return Err(DedicatedBearerError::message(
                        DedicatedBearerErrorKind::DuplicateBearerCorrelation,
                    ));
                }
                dedicated.push(ebi);
            }
            _ => {
                return Err(DedicatedBearerError::message(
                    DedicatedBearerErrorKind::WrongIeInstance,
                ));
            }
        }
    }
    let target = match (linked, dedicated.is_empty()) {
        (Some(_), false) => {
            return Err(DedicatedBearerError::message(
                DedicatedBearerErrorKind::ConflictingDeleteForms,
            ));
        }
        (Some(linked_ebi), true) => S2bDeleteBearerTarget::Linked(linked_ebi),
        (None, false) => {
            if dedicated.len() > MAX_DEDICATED_BEARER_CONTEXTS {
                return Err(DedicatedBearerError::message(
                    DedicatedBearerErrorKind::TooManyBearerContexts,
                ));
            }
            S2bDeleteBearerTarget::Dedicated(dedicated)
        }
        (None, true) => {
            return Err(DedicatedBearerError::message(
                DedicatedBearerErrorKind::MissingDeleteForm,
            ));
        }
    };
    let request_cause = optional_single_ie(&view.ies, IE_TYPE_CAUSE, 0, None)?
        .map(|ie| typed_cause(ie, None))
        .transpose()?;
    if request_cause.is_some_and(|cause| !valid_delete_request_cause(cause)) {
        return Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::InvalidDeleteRequestCause,
        ));
    }

    Ok(S2bDeleteBearerRequest {
        sequence_number: view.header.sequence_number,
        teid,
        target,
        cause: request_cause,
        additional_ies: top_level_additional(&view.ies, &[IE_TYPE_EBI, IE_TYPE_CAUSE]),
    })
}

fn optional_bearer_contexts<'b, 'a>(
    ies: &'b [TypedIe<'a>],
) -> Result<Vec<&'b BearerContext<'a>>, DedicatedBearerError> {
    let mut contexts = Vec::new();
    for ie in ies
        .iter()
        .filter(|ie| ie.ie_type() == IE_TYPE_BEARER_CONTEXT)
    {
        if ie.instance != 0 {
            return Err(DedicatedBearerError::message(
                DedicatedBearerErrorKind::WrongIeInstance,
            ));
        }
        let TypedIeValue::BearerContext(context) = &ie.value else {
            return Err(DedicatedBearerError::message(
                DedicatedBearerErrorKind::MissingBearerContexts,
            ));
        };
        contexts.push(context);
    }
    if contexts.len() > MAX_DEDICATED_BEARER_CONTEXTS {
        return Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::TooManyBearerContexts,
        ));
    }
    Ok(contexts)
}

fn project_delete_bearer_response<'a>(
    view: &S2bProcedureMessage<'a>,
) -> Result<S2bDeleteBearerResponse<'a>, DedicatedBearerError> {
    let teid = ensure_procedure(view, Procedure::DeleteBearer, MessageDirection::Response)?;
    let message_cause = typed_cause(
        single_ie(
            &view.ies,
            IE_TYPE_CAUSE,
            0,
            DedicatedBearerErrorKind::MissingCause,
            None,
        )?,
        None,
    )?;
    if !valid_delete_bearer_message_cause(message_cause) {
        return Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::InvalidResponseCause,
        ));
    }
    if message_cause.is_accepted() && teid == 0 {
        return Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::ZeroAcceptedResponseTeid,
        ));
    }

    let linked = optional_single_ie(&view.ies, IE_TYPE_EBI, 0, None)?
        .map(|ie| nonzero_ebi(typed_ebi(ie, None)?, None))
        .transpose()?;
    if view
        .ies
        .iter()
        .any(|ie| ie.ie_type() == IE_TYPE_EBI && ie.instance != 0)
    {
        return Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::WrongIeInstance,
        ));
    }
    let contexts = optional_bearer_contexts(&view.ies)?;
    let body = match (linked, contexts.is_empty()) {
        (Some(_), false) => {
            return Err(DedicatedBearerError::message(
                DedicatedBearerErrorKind::ConflictingDeleteForms,
            ));
        }
        (Some(linked_ebi), true) => {
            ensure_outcome_consistency(message_cause, [message_cause].into_iter())?;
            S2bDeleteBearerResponseBody::Linked(linked_ebi)
        }
        (None, false) => {
            let mut results = Vec::with_capacity(contexts.len());
            let mut ebis = Vec::with_capacity(contexts.len());
            for (index, context) in contexts.into_iter().enumerate() {
                let ebi = nonzero_ebi(
                    typed_ebi(
                        single_ie(
                            &context.members,
                            IE_TYPE_EBI,
                            0,
                            DedicatedBearerErrorKind::MissingBearerEbi,
                            Some(index),
                        )?,
                        Some(index),
                    )?,
                    Some(index),
                )?;
                if ebis.contains(&ebi) {
                    return Err(DedicatedBearerError::bearer(
                        DedicatedBearerErrorKind::DuplicateBearerCorrelation,
                        index,
                    ));
                }
                ebis.push(ebi);
                let bearer_cause = typed_cause(
                    single_ie(
                        &context.members,
                        IE_TYPE_CAUSE,
                        0,
                        DedicatedBearerErrorKind::MissingCause,
                        Some(index),
                    )?,
                    Some(index),
                )?;
                if !valid_delete_bearer_context_cause(bearer_cause) {
                    return Err(DedicatedBearerError::bearer(
                        DedicatedBearerErrorKind::InvalidResponseCause,
                        index,
                    ));
                }
                results.push(S2bDeleteBearerResult {
                    ebi,
                    cause: bearer_cause,
                    additional_ies: nested_additional(
                        &context.members,
                        &[IE_TYPE_EBI, IE_TYPE_CAUSE],
                    ),
                });
            }
            ensure_outcome_consistency(message_cause, results.iter().map(|result| result.cause))?;
            S2bDeleteBearerResponseBody::Dedicated(results)
        }
        (None, true) => {
            return Err(DedicatedBearerError::message(
                DedicatedBearerErrorKind::MissingDeleteForm,
            ));
        }
    };

    Ok(S2bDeleteBearerResponse {
        sequence_number: view.header.sequence_number,
        teid,
        cause: message_cause,
        body,
        additional_ies: top_level_additional(
            &view.ies,
            &[IE_TYPE_CAUSE, IE_TYPE_EBI, IE_TYPE_BEARER_CONTEXT],
        ),
    })
}

/// Build and procedure-validate an S2b Create Bearer Request.
///
/// # Errors
///
/// Returns [`crate::s2b::S2bProfileBuildError`] when an IE cannot encode or
/// the complete request violates the Release 18 S2b procedure table.
pub fn s2b_create_bearer_request(
    request: S2bCreateBearerRequest<'_>,
) -> S2bProfileBuildResult<OwnedMessage> {
    let mut ies = vec![typed_ie(0, TypedIeValue::EpsBearerId(request.linked_ebi))];
    for context in request.bearer_contexts {
        let mut members = vec![
            typed_ie(0, TypedIeValue::EpsBearerId(EpsBearerId { value: 0 })),
            typed_ie(0, TypedIeValue::BearerTft(context.tft)),
            typed_ie(0, TypedIeValue::BearerQos(context.bearer_qos)),
            typed_ie(4, TypedIeValue::FullyQualifiedTeid(context.pgw_f_teid)),
        ];
        members.push(typed_ie(0, TypedIeValue::ChargingId(context.charging_id)));
        members.extend(context.additional_ies);
        ies.push(typed_ie(
            0,
            TypedIeValue::BearerContext(BearerContext { members }),
        ));
    }
    ies.extend(request.additional_ies);
    build_s2b_profile_message(
        Header::with_teid(CREATE_BEARER_REQUEST, request.teid, request.sequence_number),
        ies,
    )
}

/// Build and procedure-validate an S2b Create Bearer Response.
///
/// # Errors
///
/// Returns [`crate::s2b::S2bProfileBuildError`] when an IE cannot encode or
/// the message/bearer Cause hierarchy, F-TEID correlation, or EBI assignment
/// is invalid.
pub fn s2b_create_bearer_response(
    response: S2bCreateBearerResponse<'_>,
) -> S2bProfileBuildResult<OwnedMessage> {
    let mut ies = vec![typed_ie(0, TypedIeValue::Cause(cause(response.cause)))];
    for result in response.bearer_contexts {
        let (ebi, bearer_cause, epdg_f_teid, pgw_f_teid, additional_ies) = match result {
            S2bCreateBearerResult::Accepted {
                ebi,
                epdg_f_teid,
                pgw_f_teid,
                additional_ies,
            } => (
                ebi,
                CauseValue::RequestAccepted,
                Some(epdg_f_teid),
                pgw_f_teid,
                additional_ies,
            ),
            S2bCreateBearerResult::Rejected {
                ebi,
                cause,
                pgw_f_teid,
                additional_ies,
            } => (ebi, cause, None, pgw_f_teid, additional_ies),
        };
        let mut members = vec![
            typed_ie(0, TypedIeValue::EpsBearerId(ebi)),
            typed_ie(0, TypedIeValue::Cause(cause(bearer_cause))),
        ];
        if let Some(epdg_f_teid) = epdg_f_teid {
            members.push(typed_ie(8, TypedIeValue::FullyQualifiedTeid(epdg_f_teid)));
        }
        members.push(typed_ie(9, TypedIeValue::FullyQualifiedTeid(pgw_f_teid)));
        members.extend(additional_ies);
        ies.push(typed_ie(
            0,
            TypedIeValue::BearerContext(BearerContext { members }),
        ));
    }
    ies.extend(response.additional_ies);
    build_s2b_profile_message(
        Header::with_teid(
            CREATE_BEARER_RESPONSE,
            response.teid,
            response.sequence_number,
        ),
        ies,
    )
}

/// Build and procedure-validate an S2b Delete Bearer Request.
///
/// # Errors
///
/// Returns [`crate::s2b::S2bProfileBuildError`] when the mutually exclusive
/// target form, optional Cause, or another IE violates Table 7.2.9.2-1.
pub fn s2b_delete_bearer_request(
    request: S2bDeleteBearerRequest<'_>,
) -> S2bProfileBuildResult<OwnedMessage> {
    let mut ies = match request.target {
        S2bDeleteBearerTarget::Linked(ebi) => {
            vec![typed_ie(0, TypedIeValue::EpsBearerId(ebi))]
        }
        S2bDeleteBearerTarget::Dedicated(ebis) => ebis
            .into_iter()
            .map(|ebi| typed_ie(1, TypedIeValue::EpsBearerId(ebi)))
            .collect(),
    };
    if let Some(request_cause) = request.cause {
        ies.push(typed_ie(0, TypedIeValue::Cause(cause(request_cause))));
    }
    ies.extend(request.additional_ies);
    build_s2b_profile_message(
        Header::with_teid(DELETE_BEARER_REQUEST, request.teid, request.sequence_number),
        ies,
    )
}

/// Build and procedure-validate an S2b Delete Bearer Response.
///
/// # Errors
///
/// Returns [`crate::s2b::S2bProfileBuildError`] when response form,
/// correlation fields, or Cause hierarchy is invalid.
pub fn s2b_delete_bearer_response(
    response: S2bDeleteBearerResponse<'_>,
) -> S2bProfileBuildResult<OwnedMessage> {
    let mut ies = vec![typed_ie(0, TypedIeValue::Cause(cause(response.cause)))];
    match response.body {
        S2bDeleteBearerResponseBody::Linked(ebi) => {
            ies.push(typed_ie(0, TypedIeValue::EpsBearerId(ebi)));
        }
        S2bDeleteBearerResponseBody::Dedicated(results) => {
            for result in results {
                let mut members = vec![
                    typed_ie(0, TypedIeValue::EpsBearerId(result.ebi)),
                    typed_ie(0, TypedIeValue::Cause(cause(result.cause))),
                ];
                members.extend(result.additional_ies);
                ies.push(typed_ie(
                    0,
                    TypedIeValue::BearerContext(BearerContext { members }),
                ));
            }
        }
    }
    ies.extend(response.additional_ies);
    build_s2b_profile_message(
        Header::with_teid(
            DELETE_BEARER_RESPONSE,
            response.teid,
            response.sequence_number,
        ),
        ies,
    )
}

/// Correlate every Create Bearer result with one request context.
///
/// Correlation uses the PGW F-TEID copied from request instance 4 into
/// response instance 9, as required by Table 7.2.4-2. Each request context
/// and response context must participate exactly once.
///
/// # Errors
///
/// Returns a stable correlation error for sequence/count/key mismatches.
pub fn correlate_create_bearer_response(
    request: &S2bCreateBearerRequest<'_>,
    response: &S2bCreateBearerResponse<'_>,
) -> Result<(), DedicatedBearerError> {
    if request.sequence_number != response.sequence_number {
        return Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::CorrelationMismatch,
        ));
    }
    if request.bearer_contexts.len() != response.bearer_contexts.len() {
        return Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::CorrelationCountMismatch,
        ));
    }
    let mut matched = vec![false; request.bearer_contexts.len()];
    for result in &response.bearer_contexts {
        if result.ebi() == request.linked_ebi {
            return Err(DedicatedBearerError::message(
                DedicatedBearerErrorKind::CorrelationMismatch,
            ));
        }
        let Some((index, _)) =
            request
                .bearer_contexts
                .iter()
                .enumerate()
                .find(|(index, context)| {
                    !matched[*index] && &context.pgw_f_teid == result.pgw_f_teid()
                })
        else {
            return Err(DedicatedBearerError::message(
                DedicatedBearerErrorKind::CorrelationMismatch,
            ));
        };
        matched[index] = true;
    }
    if matched.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::CorrelationMismatch,
        ))
    }
}

/// Correlate a Delete Bearer Response with the request target form.
///
/// # Errors
///
/// Returns a stable error if forms, sequence numbers, counts, or EBIs differ.
pub fn correlate_delete_bearer_response(
    request: &S2bDeleteBearerRequest<'_>,
    response: &S2bDeleteBearerResponse<'_>,
) -> Result<(), DedicatedBearerError> {
    if request.sequence_number != response.sequence_number {
        return Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::CorrelationMismatch,
        ));
    }
    match (&request.target, &response.body) {
        (S2bDeleteBearerTarget::Linked(request_ebi), S2bDeleteBearerResponseBody::Linked(ebi))
            if request_ebi == ebi =>
        {
            Ok(())
        }
        (
            S2bDeleteBearerTarget::Dedicated(request_ebis),
            S2bDeleteBearerResponseBody::Dedicated(results),
        ) => {
            if request_ebis.len() != results.len() {
                return Err(DedicatedBearerError::message(
                    DedicatedBearerErrorKind::CorrelationCountMismatch,
                ));
            }
            if request_ebis
                .iter()
                .all(|ebi| results.iter().any(|result| result.ebi == *ebi))
            {
                Ok(())
            } else {
                Err(DedicatedBearerError::message(
                    DedicatedBearerErrorKind::CorrelationMismatch,
                ))
            }
        }
        _ => Err(DedicatedBearerError::message(
            DedicatedBearerErrorKind::CorrelationMismatch,
        )),
    }
}

pub(crate) fn validate_procedure_message(
    view: &S2bProcedureMessage<'_>,
) -> Result<(), DecodeError> {
    let result = match (view.procedure, view.direction) {
        (Procedure::CreateBearer, MessageDirection::Request) => {
            project_create_bearer_request(view).map(|_| ())
        }
        (Procedure::CreateBearer, MessageDirection::Response) => {
            project_create_bearer_response(view).map(|_| ())
        }
        (Procedure::DeleteBearer, MessageDirection::Request) => {
            project_delete_bearer_request(view).map(|_| ())
        }
        (Procedure::DeleteBearer, MessageDirection::Response) => {
            project_delete_bearer_response(view).map(|_| ())
        }
        _ => Ok(()),
    };
    result.map_err(DedicatedBearerError::to_decode_error)
}
