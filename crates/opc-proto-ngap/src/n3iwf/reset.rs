//! NG Reset, Reset Acknowledge and Error Indication field admission.
//!
//! Signalling context is explicit and supplied by the caller; identifier
//! presence does not establish it. Admission neither authorizes resource
//! release nor proves completion or chooses a local procedure trigger.

use super::nas_fields::FiveGStmsi;
use super::release::Cause;
use super::reset_fields::{Connections, CriticalityDiagnostics, ResetType};
use super::*;
use crate::{policy, Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::Encode;

/// Caller-supplied signalling association for TS 38.413 8.7.4/8.7.5 rules.
/// This is not inferred from peer IDs and does not verify transport ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signalling {
    /// Non-UE-associated signalling; required for Reset and its acknowledgement.
    NonUe,
    /// UE-associated Error Indication; both UE identifiers are mandatory.
    UeAssociated,
}

/// Mandatory Reset fields. The caller decides what state the request names
/// and performs the procedure's correlation and resource actions.
#[derive(Clone, PartialEq, Eq)]
pub struct ResetRequest {
    /// Peer-reported Cause, without an authorization implication.
    pub cause: Cause,
    /// Explicit full or partial reset selection.
    pub reset: ResetType,
}
redacted!(ResetRequest);

/// Reset acknowledgement, which must be correlated with a local request before
/// use. For a partial reset the caller must preserve requested item order/IDs;
/// empty items may be echoed or omitted under TS 38.413 8.7.4.
#[derive(Clone, PartialEq, Eq)]
pub struct ResetAcknowledge {
    /// Optional ordered connection list. Absence and an empty item are distinct.
    pub connections: Option<Connections>,
    /// Optional response diagnostics; procedure code and triggering outcome
    /// must be absent because they apply only to Error Indication diagnostics.
    pub diagnostics: Option<CriticalityDiagnostics>,
}
redacted!(ResetAcknowledge);

/// Error report with at least one of Cause or Criticality Diagnostics.
/// The caller supplies signalling context and decides whether an Error
/// Indication is an appropriate response to the original incoming message.
#[derive(Clone, PartialEq, Eq)]
pub struct ErrorIndication {
    /// Required for UE-associated signalling; optional otherwise.
    pub amf: Option<AmfUeId>,
    /// Required for UE-associated signalling; optional otherwise.
    pub ran: Option<RanUeId>,
    /// Optional Cause; Cause or diagnostics must be present.
    pub cause: Option<Cause>,
    /// Optional root diagnostics; diagnostic item criticality cannot be ignore.
    pub diagnostics: Option<CriticalityDiagnostics>,
    /// Optional reported 5G-S-TMSI (IE 26/ignore), without identity authority.
    /// It does not replace the required AMF/RAN IDs for UE signalling.
    pub fiveg_s_tmsi: Option<FiveGStmsi>,
}
redacted!(ErrorIndication);

/// The three admitted outcomes. There is no Reset unsuccessful outcome.
#[derive(Clone, PartialEq, Eq)]
pub enum ResetMessage {
    /// NG Reset.
    Request(ResetRequest),
    /// NG Reset Acknowledge.
    Acknowledge(ResetAcknowledge),
    /// Error Indication.
    Error(ErrorIndication),
}
redacted!(ResetMessage);

/// Typed fields and value-free receiver diagnostics.
#[derive(Debug)]
pub struct AdmittedReset {
    /// Validated fields, without local procedure or resource effects.
    pub message: ResetMessage,
    /// Unknown-ignore IEs retained by the generic selected view.
    pub ignored_ie_count: usize,
    /// Unknown-notify IE identifiers, never their values.
    pub notify_ie_ids: Vec<u16>,
    /// Empty connection items that receivers must ignore. They remain in the
    /// explicit list for callers constructing a correlated acknowledgement.
    pub ignored_empty_connection_count: usize,
}

impl ResetMessage {
    /// Canonical construction with explicit signalling context. Validate
    /// presence, conditional applicability, depth and capacity before returning
    /// a PDU. This does not send an acknowledgement or release any state.
    pub fn construct(
        &self,
        signalling: Signalling,
        ctx: DecodeContext,
    ) -> Result<Pdu, DecodeError> {
        validate(self, signalling)?;
        crate::enforce_depth(depth(self), ctx)?;
        let output = output_context(ctx);
        let mut fields = Vec::new();
        let kind = match self {
            Self::Request(value) => {
                fields.push((15, Criticality::ignore, value.cause.encode(output)));
                fields.push((88, Criticality::reject, value.reset.encode(output)));
                MessageType::NgReset
            }
            Self::Acknowledge(value) => {
                if let Some(connections) = &value.connections {
                    fields.push((111, Criticality::ignore, connections.encode(output)));
                }
                if let Some(diagnostics) = &value.diagnostics {
                    fields.push((19, Criticality::ignore, diagnostics.encode(output)));
                }
                MessageType::NgResetAcknowledge
            }
            Self::Error(value) => {
                if let Some(amf) = value.amf {
                    fields.push((10, Criticality::ignore, amf.encode(output)));
                }
                if let Some(ran) = value.ran {
                    fields.push((85, Criticality::ignore, ran.encode(output)));
                }
                if let Some(cause) = value.cause {
                    fields.push((15, Criticality::ignore, cause.encode(output)));
                }
                if let Some(diagnostics) = &value.diagnostics {
                    fields.push((19, Criticality::ignore, diagnostics.encode(output)));
                }
                if let Some(identity) = value.fiveg_s_tmsi {
                    fields.push((26, Criticality::ignore, identity.encode(output)));
                }
                MessageType::ErrorIndication
            }
        };
        let values = fields
            .into_iter()
            .map(|(id, crit, value)| {
                value
                    .map(|value| (id, crit, value))
                    .map_err(|_| invalid("reset or error encoding or capacity"))
            })
            .collect::<Result<Vec<_>, DecodeError>>()?;
        let ies: Vec<_> = values
            .iter()
            .map(|(id, crit, value)| ProtocolIe::new(*id, *crit, value.as_bytes()))
            .collect();
        let pdu = Pdu::from_protocol_ies(kind, &ies, ctx)?;
        Self::from_pdu(&pdu, signalling, ctx)?;
        Ok(pdu)
    }

    /// Admit the generic decoder's selected view. Use the same DecodeContext
    /// at both boundaries; prior filtering cannot be undone. Signalling context
    /// must come from the caller's association, not from the incoming fields.
    pub fn from_pdu(
        pdu: &Pdu,
        signalling: Signalling,
        ctx: DecodeContext,
    ) -> Result<AdmittedReset, DecodeError> {
        crate::enforce_depth(5, ctx)?;
        pdu.wire_len(output_context(ctx))
            .map_err(|_| invalid("reset or error container policy"))?;
        macro_rules! fields {
            ($kind:expr, $value:expr) => {
                admit(
                    $kind,
                    $value
                        .protocol_ies
                        .0
                        .iter()
                        .map(|v| (v.id, v.criticality as u8, v.value.as_bytes())),
                    signalling,
                    ctx,
                )
            };
        }
        match &pdu.kind {
            PduKind::Initiating {
                message: Message::NgReset(value),
                ..
            } => fields!(MessageType::NgReset, value),
            PduKind::Successful {
                message: Message::NgResetAcknowledge(value),
                ..
            } => fields!(MessageType::NgResetAcknowledge, value),
            PduKind::Initiating {
                message: Message::ErrorIndication(value),
                ..
            } => fields!(MessageType::ErrorIndication, value),
            _ => Err(invalid("reset or error outcome")),
        }
    }
}

fn output_context(ctx: DecodeContext) -> EncodeContext {
    EncodeContext {
        max_message_len: ctx.max_message_len,
        ..EncodeContext::default()
    }
}
fn diagnostic_depth(value: &Option<CriticalityDiagnostics>) -> usize {
    value
        .as_ref()
        .map_or(5, |v| if v.ies.is_some() { 8 } else { 6 })
}
fn depth(message: &ResetMessage) -> usize {
    match message {
        ResetMessage::Request(v) => {
            if matches!(v.reset, ResetType::All) {
                6
            } else {
                8
            }
        }
        ResetMessage::Acknowledge(v) => {
            diagnostic_depth(&v.diagnostics).max(if v.connections.is_some() { 7 } else { 5 })
        }
        ResetMessage::Error(v) => {
            diagnostic_depth(&v.diagnostics).max(if v.cause.is_some() || v.fiveg_s_tmsi.is_some() {
                6
            } else {
                5
            })
        }
    }
}
fn validate(message: &ResetMessage, signalling: Signalling) -> Result<(), DecodeError> {
    match message {
        ResetMessage::Error(value) => {
            if value.cause.is_none() && value.diagnostics.is_none() {
                return Err(invalid("missing error indication basis"));
            }
            if signalling == Signalling::UeAssociated
                && (value.amf.is_none() || value.ran.is_none())
            {
                return Err(invalid("missing ue associated error identifiers"));
            }
        }
        _ if signalling != Signalling::NonUe => {
            return Err(invalid("reset requires non ue signalling"))
        }
        ResetMessage::Acknowledge(value)
            if value
                .diagnostics
                .as_ref()
                .is_some_and(|v| v.procedure_code.is_some() || v.triggering_outcome.is_some()) =>
        {
            return Err(invalid("response diagnostic header applicability"));
        }
        _ => {}
    }
    Ok(())
}

fn admit<'a>(
    kind: MessageType,
    fields: impl Iterator<Item = (u16, u8, &'a [u8])>,
    signalling: Signalling,
    ctx: DecodeContext,
) -> Result<AdmittedReset, DecodeError> {
    let (profile, supported): (_, &[u16]) = match kind {
        MessageType::NgReset => (policy::NG_RESET, &[15, 88]),
        MessageType::NgResetAcknowledge => (policy::NG_RESET_ACKNOWLEDGE, &[111, 19]),
        _ => (policy::ERROR_INDICATION, &[10, 85, 15, 19, 26]),
    };
    let leaf = DecodeContext {
        max_depth: ctx.max_depth.saturating_sub(4),
        ..ctx
    };
    let (mut amf, mut ran, mut cause, mut reset, mut connections, mut diagnostics) =
        (None, None, None, None, None, None);
    let mut fiveg_s_tmsi = None;
    let mut ignored_ie_count = 0;
    let mut notify_ie_ids = Vec::new();
    for (index, (id, criticality, value)) in fields.enumerate() {
        if index >= ctx.max_ies {
            return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, 0));
        }
        if !supported.contains(&id) {
            if profile.recognizes(id) {
                return Err(invalid("applicable reset or error ie not admitted"));
            }
            match criticality {
                1 => ignored_ie_count += 1,
                2 => notify_ie_ids.push(id),
                _ => return Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, 0)),
            }
            continue;
        }
        match id {
            10 => amf = Some(AmfUeId::decode(value, leaf)?),
            85 => ran = Some(RanUeId::decode(value, leaf)?),
            15 => cause = Some(Cause::decode(value, leaf)?),
            88 => reset = Some(ResetType::decode(value, leaf)?),
            111 => connections = Some(Connections::decode(value, leaf)?),
            19 => diagnostics = Some(CriticalityDiagnostics::decode(value, leaf)?),
            26 => fiveg_s_tmsi = Some(FiveGStmsi::decode(value, leaf)?),
            _ => return Err(invalid("reset or error field dispatch")),
        }
    }
    let message = match kind {
        MessageType::NgReset => ResetMessage::Request(ResetRequest {
            cause: cause.ok_or_else(|| invalid("missing reset cause"))?,
            reset: reset.ok_or_else(|| invalid("missing reset type"))?,
        }),
        MessageType::NgResetAcknowledge => ResetMessage::Acknowledge(ResetAcknowledge {
            connections,
            diagnostics,
        }),
        _ => ResetMessage::Error(ErrorIndication {
            amf,
            ran,
            cause,
            diagnostics,
            fiveg_s_tmsi,
        }),
    };
    validate(&message, signalling)?;
    let ignored_empty_connection_count = match &message {
        ResetMessage::Request(ResetRequest {
            reset: ResetType::Part(v),
            ..
        }) => v.ignored_empty_count(),
        ResetMessage::Acknowledge(v) => v
            .connections
            .as_ref()
            .map_or(0, Connections::ignored_empty_count),
        _ => 0,
    };
    Ok(AdmittedReset {
        message,
        ignored_ie_count,
        notify_ie_ids,
        ignored_empty_connection_count,
    })
}
