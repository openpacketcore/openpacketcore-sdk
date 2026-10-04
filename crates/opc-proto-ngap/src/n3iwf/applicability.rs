//! N3IWF receive routing and local wire-codec gates (TS 29.413 5.1–5.4).
//!
//! Call [`inspect`](crate::n3iwf::applicability::inspect) before generic decoding.
//! Its result classifies a completely
//! framed envelope, not its fields. A qualified route still requires generic
//! decoding and the corresponding typed admission with the same context.
//! Applicable procedures without a qualified codec require an external handler;
//! they never become the unsupported-procedure fallback. Local triggers for
//! those messages remain disabled in this SDK boundary.
//!
//! Direction and signalling describe the protocol, not association ownership.
//! The caller supplies transport context, request correlation, state, timers and
//! resource effects. No function here sends a packet or changes endpoint state.

use super::reset_fields::{CriticalityDiagnostics, TriggeringOutcome};
use super::*;
use crate::{MessageType, Outcome};

/// The local end of an N3IWF–AMF interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// Non-3GPP interworking function.
    N3iwf,
    /// Access and mobility management function.
    Amf,
}

/// Permitted message direction, independent of received identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// N3IWF to AMF.
    ToAmf,
    /// AMF to N3IWF.
    ToN3iwf,
    /// Either endpoint may initiate or respond.
    Either,
}
impl Direction {
    fn permits_receiver(self, receiver: Endpoint) -> bool {
        matches!(
            (self, receiver),
            (Self::Either, _) | (Self::ToAmf, Endpoint::Amf) | (Self::ToN3iwf, Endpoint::N3iwf)
        )
    }
}

/// Required signalling category; it does not prove a logical association exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Association {
    /// UE-associated signalling, including procedures that establish it.
    Ue,
    /// Non-UE-associated signalling.
    NonUe,
    /// Error Indication uses the caller's actual signalling context.
    Either,
}

/// Static metadata for one applicable outcome. The codec entry refers only to
/// its documented admitted field subset; it does not imply endpoint readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageRule {
    /// ASN.1 message name from the pinned Release 18 schema.
    pub name: &'static str,
    /// Elementary procedure code.
    pub procedure_code: u8,
    /// Permitted outcome for this message.
    pub outcome: Outcome,
    /// Assigned procedure criticality, never inferred from a peer's choice.
    pub criticality: Criticality,
    /// Permitted interface direction.
    pub direction: Direction,
    /// Required signalling category.
    pub association: Association,
    /// Qualified structural codec with separate typed field admission.
    pub codec: Option<MessageType>,
    /// TS 38.413 procedure clause; TS 29.413 5.3 exceptions also apply.
    pub clause: &'static str,
}

macro_rules! messages {
    ($($variant:ident, $name:literal, $code:literal, $outcome:ident, $crit:ident,
       $direction:ident, $association:ident, $codec:expr, $clause:literal;)+) => {
        /// The complete TS 29.413 5.2 N3IWF message applicability list.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum ApplicableMessage {
            $(#[doc = $name] $variant,)+
        }
        /// All 40 applicable outcomes, including the 17 requiring a handler.
        pub const APPLICABLE_MESSAGES: &[ApplicableMessage] = &[
            $(ApplicableMessage::$variant,)+
        ];
        impl ApplicableMessage {
            /// Protocol metadata and the current qualified codec boundary.
            pub const fn rule(self) -> &'static MessageRule {
                match self {
                    $(Self::$variant => &MessageRule {
                        name: $name, procedure_code: $code, outcome: Outcome::$outcome,
                        criticality: Criticality::$crit, direction: Direction::$direction,
                        association: Association::$association, codec: $codec, clause: $clause,
                    },)+
                }
            }
        }
    };
}

messages! {
    PduSessionResourceSetupRequest, "PDUSessionResourceSetupRequest", 29, Initiating, reject, ToN3iwf, Ue, Some(MessageType::PduSessionResourceSetupRequest), "8.2.1";
    PduSessionResourceSetupResponse, "PDUSessionResourceSetupResponse", 29, Successful, reject, ToAmf, Ue, Some(MessageType::PduSessionResourceSetupResponse), "8.2.1";
    PduSessionResourceReleaseCommand, "PDUSessionResourceReleaseCommand", 28, Initiating, reject, ToN3iwf, Ue, Some(MessageType::PduSessionResourceReleaseCommand), "8.2.2";
    PduSessionResourceReleaseResponse, "PDUSessionResourceReleaseResponse", 28, Successful, reject, ToAmf, Ue, Some(MessageType::PduSessionResourceReleaseResponse), "8.2.2";
    PduSessionResourceModifyRequest, "PDUSessionResourceModifyRequest", 26, Initiating, reject, ToN3iwf, Ue, Some(MessageType::PduSessionResourceModifyRequest), "8.2.3";
    PduSessionResourceModifyResponse, "PDUSessionResourceModifyResponse", 26, Successful, reject, ToAmf, Ue, Some(MessageType::PduSessionResourceModifyResponse), "8.2.3";
    PduSessionResourceNotify, "PDUSessionResourceNotify", 30, Initiating, ignore, ToAmf, Ue, Some(MessageType::PduSessionResourceNotify), "8.2.4";
    InitialContextSetupRequest, "InitialContextSetupRequest", 14, Initiating, reject, ToN3iwf, Ue, Some(MessageType::InitialContextSetupRequest), "8.3.1";
    InitialContextSetupResponse, "InitialContextSetupResponse", 14, Successful, reject, ToAmf, Ue, Some(MessageType::InitialContextSetupResponse), "8.3.1";
    InitialContextSetupFailure, "InitialContextSetupFailure", 14, Unsuccessful, reject, ToAmf, Ue, Some(MessageType::InitialContextSetupFailure), "8.3.1";
    UeContextReleaseRequest, "UEContextReleaseRequest", 42, Initiating, ignore, ToAmf, Ue, Some(MessageType::UeContextReleaseRequest), "8.3.2";
    UeContextReleaseCommand, "UEContextReleaseCommand", 41, Initiating, reject, ToN3iwf, Ue, Some(MessageType::UeContextReleaseCommand), "8.3.3";
    UeContextReleaseComplete, "UEContextReleaseComplete", 41, Successful, reject, ToAmf, Ue, Some(MessageType::UeContextReleaseComplete), "8.3.3";
    UeContextModificationRequest, "UEContextModificationRequest", 40, Initiating, reject, ToN3iwf, Ue, None, "8.3.4";
    UeContextModificationResponse, "UEContextModificationResponse", 40, Successful, reject, ToAmf, Ue, None, "8.3.4";
    UeContextModificationFailure, "UEContextModificationFailure", 40, Unsuccessful, reject, ToAmf, Ue, None, "8.3.4";
    InitialUeMessage, "InitialUEMessage", 15, Initiating, ignore, ToAmf, Ue, Some(MessageType::InitialUeMessage), "8.6.1";
    DownlinkNasTransport, "DownlinkNASTransport", 4, Initiating, ignore, ToN3iwf, Ue, Some(MessageType::DownlinkNasTransport), "8.6.2";
    UplinkNasTransport, "UplinkNASTransport", 46, Initiating, ignore, ToAmf, Ue, Some(MessageType::UplinkNasTransport), "8.6.3";
    NasNonDeliveryIndication, "NASNonDeliveryIndication", 19, Initiating, ignore, ToAmf, Ue, Some(MessageType::NasNonDeliveryIndication), "8.6.4";
    RerouteNasRequest, "RerouteNASRequest", 36, Initiating, reject, ToN3iwf, Ue, None, "8.6.5";
    NgSetupRequest, "NGSetupRequest", 21, Initiating, reject, ToAmf, NonUe, Some(MessageType::NgSetupRequest), "8.7.1";
    NgSetupResponse, "NGSetupResponse", 21, Successful, reject, ToN3iwf, NonUe, Some(MessageType::NgSetupResponse), "8.7.1";
    NgSetupFailure, "NGSetupFailure", 21, Unsuccessful, reject, ToN3iwf, NonUe, Some(MessageType::NgSetupFailure), "8.7.1";
    RanConfigurationUpdate, "RANConfigurationUpdate", 35, Initiating, reject, ToAmf, NonUe, None, "8.7.2";
    RanConfigurationUpdateAcknowledge, "RANConfigurationUpdateAcknowledge", 35, Successful, reject, ToN3iwf, NonUe, None, "8.7.2";
    RanConfigurationUpdateFailure, "RANConfigurationUpdateFailure", 35, Unsuccessful, reject, ToN3iwf, NonUe, None, "8.7.2";
    AmfConfigurationUpdate, "AMFConfigurationUpdate", 0, Initiating, reject, ToN3iwf, NonUe, None, "8.7.3";
    AmfConfigurationUpdateAcknowledge, "AMFConfigurationUpdateAcknowledge", 0, Successful, reject, ToAmf, NonUe, None, "8.7.3";
    AmfConfigurationUpdateFailure, "AMFConfigurationUpdateFailure", 0, Unsuccessful, reject, ToAmf, NonUe, None, "8.7.3";
    NgReset, "NGReset", 20, Initiating, reject, Either, NonUe, Some(MessageType::NgReset), "8.7.4";
    NgResetAcknowledge, "NGResetAcknowledge", 20, Successful, reject, Either, NonUe, Some(MessageType::NgResetAcknowledge), "8.7.4";
    ErrorIndication, "ErrorIndication", 9, Initiating, ignore, Either, Either, Some(MessageType::ErrorIndication), "8.7.5";
    AmfStatusIndication, "AMFStatusIndication", 1, Initiating, ignore, ToN3iwf, NonUe, None, "8.7.6";
    OverloadStart, "OverloadStart", 22, Initiating, ignore, ToN3iwf, NonUe, None, "8.7.7";
    OverloadStop, "OverloadStop", 23, Initiating, reject, ToN3iwf, NonUe, None, "8.7.8";
    UeTnlaBindingReleaseRequest, "UETNLABindingReleaseRequest", 45, Initiating, ignore, ToN3iwf, Ue, None, "8.13.1";
    TraceStart, "TraceStart", 39, Initiating, ignore, ToN3iwf, Ue, None, "8.11.1";
    TraceFailureIndication, "TraceFailureIndication", 38, Initiating, ignore, ToAmf, Ue, None, "8.11.2";
    DeactivateTrace, "DeactivateTrace", 3, Initiating, ignore, ToN3iwf, Ue, None, "8.11.3";
}

/// Wire capability for a local trigger. Even available codecs require the
/// caller's procedure, transport and state prerequisites in the conformance matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerGate {
    /// The documented field subset has a qualified codec and typed admission.
    CodecAvailable(MessageType),
    /// No qualified codec here; no local trigger is enabled by this boundary.
    DisabledPendingHandler,
    /// This endpoint cannot send this outcome in this interface direction.
    WrongDirection,
}
impl ApplicableMessage {
    /// Gate wire capability only; this never authorizes a procedure or response.
    pub fn local_trigger(self, sender: Endpoint) -> TriggerGate {
        let receiver = match sender {
            Endpoint::N3iwf => Endpoint::Amf,
            Endpoint::Amf => Endpoint::N3iwf,
        };
        let rule = self.rule();
        if !rule.direction.permits_receiver(receiver) {
            return TriggerGate::WrongDirection;
        }
        match rule.codec {
            Some(codec) => TriggerGate::CodecAvailable(codec),
            None => TriggerGate::DisabledPendingHandler,
        }
    }
}

/// TS 38.413 10.3.4.1 action for a procedure absent from N3IWF applicability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsupportedAction {
    /// Ignore the procedure; no unsupported-procedure error response.
    Ignore,
    /// Reject the procedure and initiate Error Indication.
    RejectAndReport,
    /// Ignore the procedure and initiate Error Indication.
    IgnoreAndReport,
}

/// Value-free reporting metadata for a framed, non-applicable procedure.
/// Fields are private so applicable messages cannot construct this disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedProcedure {
    procedure_code: u8,
    outcome: Outcome,
    criticality: Criticality,
    reference_known: bool,
}
impl UnsupportedProcedure {
    /// Whether the procedure code occurs in the pinned Release 18 schema.
    pub const fn reference_known(self) -> bool {
        self.reference_known
    }
    /// Required disposition; no side effect is performed here.
    pub const fn action(self) -> UnsupportedAction {
        match self.criticality {
            Criticality::reject => UnsupportedAction::RejectAndReport,
            Criticality::ignore => UnsupportedAction::Ignore,
            Criticality::notify => UnsupportedAction::IgnoreAndReport,
        }
    }
    /// Required Error Indication diagnostic header for reject/notify. No
    /// offending body or IE value is copied. The caller supplies signalling,
    /// identifiers and an appropriate Cause when constructing the report.
    pub fn diagnostics(self) -> Option<CriticalityDiagnostics> {
        if self.action() == UnsupportedAction::Ignore {
            return None;
        }
        Some(CriticalityDiagnostics {
            procedure_code: Some(self.procedure_code),
            triggering_outcome: Some(match self.outcome {
                Outcome::Initiating => TriggeringOutcome::Initiating,
                Outcome::Successful => TriggeringOutcome::Successful,
                Outcome::Unsuccessful => TriggeringOutcome::Unsuccessful,
            }),
            procedure_criticality: Some(self.criticality),
            ies: None,
        })
    }
}

/// The next receive boundary, after envelope framing and metadata validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveDisposition {
    /// Apply generic decoding and this message's typed field admission next.
    Qualified(ApplicableMessage),
    /// Applicable but requires a handler with its own qualified field codec and
    /// procedure behavior. Absence of that handler is an integration gap.
    HandlerRequired(ApplicableMessage),
    /// Absent from TS 29.413 5.2; perform the prescribed ignore/report action.
    Unsupported(UnsupportedProcedure),
}

/// Classify exactly one complete N3IWF NGAP envelope without allocating or
/// materializing its body, including fragmented open types. Nonzero padding,
/// nonminimal determinants, truncation, trailing data and unsupported outer
/// CHOICE additions fail. All known Release 18 procedure codes enforce their
/// assigned criticality and valid outcome set before choosing a disposition.
///
/// Requires depth three and the complete input byte bound. `max_ies`, duplicate,
/// unknown-IE and validation policies belong to subsequent field admission and
/// are not weakened or consumed here. No successful classification establishes
/// well-formed fields, supported resource actions, or signalling ownership.
pub fn inspect(
    input: &[u8],
    receiver: Endpoint,
    ctx: DecodeContext,
) -> Result<ReceiveDisposition, DecodeError> {
    bound(input, ctx, 3)?;
    let prefix = input
        .get(..3)
        .ok_or_else(|| invalid("ngap routing envelope"))?;
    let outcome = match prefix[0] {
        0 => Outcome::Initiating,
        32 => Outcome::Successful,
        64 => Outcome::Unsuccessful,
        _ => return Err(invalid("ngap routing outcome or padding")),
    };
    let criticality = match prefix[2] {
        0 => Criticality::reject,
        64 => Criticality::ignore,
        128 => Criticality::notify,
        _ => return Err(invalid("ngap routing criticality or padding")),
    };
    let (rest, _) = aper::scan_open_type(&input[3..])?;
    if !rest.is_empty() {
        return Err(invalid("trailing ngap routing bytes"));
    }
    let code = prefix[1];
    let known = reference_procedure(code);
    if let Some((expected, outcomes)) = known {
        let mask = match outcome {
            Outcome::Initiating => 1,
            Outcome::Successful => 2,
            Outcome::Unsuccessful => 4,
        };
        if criticality != expected || outcomes & mask == 0 {
            return Err(invalid("ngap routing procedure metadata"));
        }
    }
    for &message in APPLICABLE_MESSAGES {
        let rule = message.rule();
        if rule.procedure_code == code && rule.outcome == outcome {
            if !rule.direction.permits_receiver(receiver) {
                return Err(invalid("ngap routing direction"));
            }
            return Ok(if rule.codec.is_some() {
                ReceiveDisposition::Qualified(message)
            } else {
                ReceiveDisposition::HandlerRequired(message)
            });
        }
    }
    Ok(ReceiveDisposition::Unsupported(UnsupportedProcedure {
        procedure_code: code,
        outcome,
        criticality,
        reference_known: known.is_some(),
    }))
}

// TS 38.413 V18.10.0 9.4 NGAP-ELEMENTARY-PROCEDURES. Every code in the
// release is checked, including those absent from the N3IWF applicability list.
// Masks encode Initiating=1, Successful=2, Unsuccessful=4. The independent
// reference corpus checks all 81 codes and 131 defined outcomes.
fn reference_procedure(code: u8) -> Option<(Criticality, u8)> {
    use Criticality::{ignore, reject};
    const PROCEDURES: &[(Criticality, u8)] = &[
        (reject, 7), // 0
        (ignore, 1), // 1
        (ignore, 1), // 2
        (ignore, 1), // 3
        (ignore, 1), // 4
        (ignore, 1), // 5
        (ignore, 1), // 6
        (ignore, 1), // 7
        (ignore, 1), // 8
        (ignore, 1), // 9
        (reject, 3), // 10
        (ignore, 1), // 11
        (reject, 7), // 12
        (reject, 7), // 13
        (reject, 7), // 14
        (ignore, 1), // 15
        (ignore, 1), // 16
        (ignore, 1), // 17
        (ignore, 1), // 18
        (ignore, 1), // 19
        (reject, 3), // 20
        (reject, 7), // 21
        (ignore, 1), // 22
        (reject, 1), // 23
        (ignore, 1), // 24
        (reject, 7), // 25
        (reject, 3), // 26
        (reject, 3), // 27
        (reject, 3), // 28
        (reject, 3), // 29
        (ignore, 1), // 30
        (ignore, 1), // 31
        (reject, 3), // 32
        (ignore, 1), // 33
        (ignore, 1), // 34
        (reject, 7), // 35
        (reject, 1), // 36
        (ignore, 1), // 37
        (ignore, 1), // 38
        (ignore, 1), // 39
        (reject, 7), // 40
        (reject, 3), // 41
        (ignore, 1), // 42
        (reject, 3), // 43
        (ignore, 1), // 44
        (ignore, 1), // 45
        (ignore, 1), // 46
        (ignore, 1), // 47
        (ignore, 1), // 48
        (ignore, 1), // 49
        (ignore, 1), // 50
        (reject, 3), // 51
        (ignore, 1), // 52
        (ignore, 1), // 53
        (ignore, 1), // 54
        (reject, 1), // 55
        (reject, 1), // 56
        (reject, 1), // 57
        (reject, 7), // 58
        (reject, 7), // 59
        (reject, 3), // 60
        (ignore, 1), // 61
        (reject, 1), // 62
        (ignore, 1), // 63
        (reject, 1), // 64
        (reject, 1), // 65
        (reject, 7), // 66
        (reject, 3), // 67
        (reject, 7), // 68
        (reject, 7), // 69
        (reject, 3), // 70
        (reject, 7), // 71
        (reject, 3), // 72
        (reject, 7), // 73
        (ignore, 1), // 74
        (reject, 1), // 75
        (reject, 7), // 76
        (ignore, 1), // 77
        (reject, 7), // 78
        (ignore, 1), // 79
        (reject, 7), // 80
    ];
    PROCEDURES.get(usize::from(code)).copied()
}
