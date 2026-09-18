//! NAS Non-Delivery Indication and UE Context Release Request field admission.
//!
//! These are peer reports or requests. Correlating their identifiers, deciding
//! when to send them, and releasing resources remain the caller's responsibility.

use super::release::Cause;
use super::session_lists::{encode_list, unique_id, validate_ids, SessionId};
use super::setup_fields::Reader;
use super::*;
use crate::{policy, Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::Encode;

/// A context release request's optional list of 1–256 unique session IDs.
/// Absence of the list is distinct from an empty list, which is invalid.
#[derive(Clone, PartialEq, Eq)]
pub struct ContextReleaseSessions(Vec<SessionId>);
redacted!(ContextReleaseSessions);

impl ContextReleaseSessions {
    /// Enforce the root count and session uniqueness.
    pub fn new(values: Vec<SessionId>) -> Result<Self, DecodeError> {
        validate_ids(values.iter().copied(), values.len())?;
        Ok(Self(values))
    }
    /// Explicit peer session identifiers, in received order.
    pub fn values(&self) -> &[SessionId] {
        &self.0
    }
    /// Preflight the exact size before materializing qualified generated values.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let length = 1 + 2 * self.0.len();
        capacity(length, ctx)?;
        let values = self
            .0
            .iter()
            .map(|id| {
                asn::PDUSessionResourceItemCxtRelReq::new(asn::PDUSessionID(id.value()), None)
            })
            .collect();
        encode_list(&asn::PDUSessionResourceListCxtRelReq(values), length)
    }
    /// Require depth three and bound physical count, flags, padding and unique
    /// IDs before the independently qualified generated decoder allocates.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 3)?;
        let mut reader = Reader::new(input, ctx);
        let count = reader.count(8, 256, 16)?;
        let mut seen = [0; 4];
        for _ in 0..count {
            reader.flags(2)?;
            reader.align()?;
            unique_id(&mut seen, SessionId::new(reader.bits(8)? as u8))?;
        }
        reader.finish()?;
        let value: asn::PDUSessionResourceListCxtRelReq = decode_leaf(input)?;
        Ok(Self(
            value
                .0
                .iter()
                .map(|v| SessionId::new(v.p_dusession_id.0))
                .collect(),
        ))
    }
}

/// Peer NAS non-delivery report. NAS remains opaque and is borrowed where its
/// APER framing permits; the report is not proof of the UE's delivery state.
pub struct NasNonDelivery<'a> {
    /// Peer AMF UE identifier.
    pub amf: AmfUeId,
    /// Local RAN UE identifier.
    pub ran: RanUeId,
    /// Mandatory opaque NAS payload, including a valid zero-length payload.
    pub nas: NasPdu<'a>,
    /// Peer-reported reason for non-delivery.
    pub cause: Cause,
}
redacted!(NasNonDelivery<'_>);

/// Context release request fields, without authorization or resource effects.
#[derive(Clone, PartialEq, Eq)]
pub struct UeReleaseRequest {
    /// Peer AMF UE identifier.
    pub amf: AmfUeId,
    /// Local RAN UE identifier.
    pub ran: RanUeId,
    /// Optional nonempty list of unique session IDs.
    pub sessions: Option<ContextReleaseSessions>,
    /// Peer-reported reason for the request.
    pub cause: Cause,
}
redacted!(UeReleaseRequest);

/// The two initiating messages, with no response or local action implied.
pub enum UeRequestMessage<'a> {
    /// NAS Non-Delivery Indication.
    NasNonDelivery(NasNonDelivery<'a>),
    /// UE Context Release Request.
    ContextRelease(UeReleaseRequest),
}
redacted!(UeRequestMessage<'_>);

/// Admitted fields and identifier-only diagnostics.
#[derive(Debug)]
pub struct AdmittedUeRequest<'a> {
    /// Validated fields for the selected procedure.
    pub message: UeRequestMessage<'a>,
    /// Unknown-ignore IEs retained in the generic decoder's selected view.
    pub ignored_ie_count: usize,
    /// Unknown-notify IE identifiers, never their opaque values.
    pub notify_ie_ids: Vec<u16>,
}

impl UeRequestMessage<'_> {
    /// Construct canonical fields. Require depth six, or seven when a context
    /// release request includes a session list. No local trigger is inferred.
    pub fn construct(&self, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
        let output = output_context(ctx);
        let mut fields = Vec::new();
        let kind = match self {
            Self::NasNonDelivery(value) => {
                crate::enforce_depth(6, ctx)?;
                fields.push((10, Criticality::reject, value.amf.encode(output)));
                fields.push((85, Criticality::reject, value.ran.encode(output)));
                fields.push((38, Criticality::ignore, value.nas.encode(output)));
                fields.push((15, Criticality::ignore, value.cause.encode(output)));
                MessageType::NasNonDeliveryIndication
            }
            Self::ContextRelease(value) => {
                crate::enforce_depth(if value.sessions.is_some() { 7 } else { 6 }, ctx)?;
                fields.push((10, Criticality::reject, value.amf.encode(output)));
                fields.push((85, Criticality::reject, value.ran.encode(output)));
                if let Some(sessions) = &value.sessions {
                    fields.push((133, Criticality::reject, sessions.encode(output)));
                }
                fields.push((15, Criticality::ignore, value.cause.encode(output)));
                MessageType::UeContextReleaseRequest
            }
        };
        let values = fields
            .into_iter()
            .map(|(id, crit, value)| {
                value
                    .map(|value| (id, crit, value))
                    .map_err(|_| invalid("ue request encoding or capacity"))
            })
            .collect::<Result<Vec<_>, DecodeError>>()?;
        let ies: Vec<_> = values
            .iter()
            .map(|(id, crit, value)| ProtocolIe::new(*id, *crit, value.as_bytes()))
            .collect();
        let pdu = Pdu::from_protocol_ies(kind, &ies, ctx)?;
        Self::from_pdu(&pdu, ctx)?;
        Ok(pdu)
    }

    /// Admit the generic decoder's selected IE view. Use the same context for
    /// both boundaries; a prior duplicate or unknown filter cannot be undone.
    pub fn from_pdu(pdu: &Pdu, ctx: DecodeContext) -> Result<AdmittedUeRequest<'_>, DecodeError> {
        crate::enforce_depth(5, ctx)?;
        pdu.wire_len(output_context(ctx))
            .map_err(|_| invalid("ue request container policy"))?;
        match &pdu.kind {
            PduKind::Initiating {
                message: Message::NasNonDeliveryIndication(value),
                ..
            } => admit(
                true,
                value
                    .protocol_ies
                    .0
                    .iter()
                    .map(|v| (v.id, v.criticality as u8, v.value.as_bytes())),
                ctx,
            ),
            PduKind::Initiating {
                message: Message::UeContextReleaseRequest(value),
                ..
            } => admit(
                false,
                value
                    .protocol_ies
                    .0
                    .iter()
                    .map(|v| (v.id.0, v.criticality as u8, v.value.as_bytes())),
                ctx,
            ),
            _ => Err(invalid("ue request outcome")),
        }
    }
}

fn output_context(ctx: DecodeContext) -> EncodeContext {
    EncodeContext {
        max_message_len: ctx.max_message_len,
        ..EncodeContext::default()
    }
}

fn admit<'a>(
    nas_report: bool,
    fields: impl Iterator<Item = (u16, u8, &'a [u8])>,
    ctx: DecodeContext,
) -> Result<AdmittedUeRequest<'a>, DecodeError> {
    let (profile, supported): (_, &[u16]) = if nas_report {
        (policy::NAS_NON_DELIVERY_INDICATION, &[10, 85, 38, 15])
    } else {
        (policy::UE_CONTEXT_RELEASE_REQUEST, &[10, 85, 133, 15])
    };
    let leaf = DecodeContext {
        max_depth: ctx.max_depth.saturating_sub(4),
        ..ctx
    };
    let (mut amf, mut ran, mut nas, mut cause, mut sessions) = (None, None, None, None, None);
    let mut ignored_ie_count = 0;
    let mut notify_ie_ids = Vec::new();
    for (index, (id, criticality, value)) in fields.enumerate() {
        if index >= ctx.max_ies {
            return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, 0));
        }
        if !supported.contains(&id) {
            if profile.recognizes(id) {
                return Err(invalid("applicable ue request ie not admitted"));
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
            38 => nas = Some(NasPdu::decode(value, leaf)?),
            15 => cause = Some(Cause::decode(value, leaf)?),
            133 => sessions = Some(ContextReleaseSessions::decode(value, leaf)?),
            _ => return Err(invalid("ue request field dispatch")),
        }
    }
    let amf = amf.ok_or_else(|| invalid("missing amf ue id"))?;
    let ran = ran.ok_or_else(|| invalid("missing ran ue id"))?;
    let cause = cause.ok_or_else(|| invalid("missing cause"))?;
    let message = if nas_report {
        UeRequestMessage::NasNonDelivery(NasNonDelivery {
            amf,
            ran,
            cause,
            nas: nas.ok_or_else(|| invalid("missing nas pdu"))?,
        })
    } else {
        UeRequestMessage::ContextRelease(UeReleaseRequest {
            amf,
            ran,
            sessions,
            cause,
        })
    };
    Ok(AdmittedUeRequest {
        message,
        ignored_ie_count,
        notify_ie_ids,
    })
}
