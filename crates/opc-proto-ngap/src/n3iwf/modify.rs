//! Complete PDU Session Resource Modify Request/Response admission. TS 38.413
//! 8.2.3 abnormal-condition responses, request correspondence, session/QFI
//! ownership, NAS eligibility and actual modifications remain caller-owned.

use super::modify_lists::{FailedModifications, ModifiedSessions, SessionModifications};
use super::modify_results::response_diagnostics;
use super::reset_fields::CriticalityDiagnostics;
use super::session_lists::{unique_id, SessionTransferDiagnostics};
use super::*;
use crate::{Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::Encode;

/// Modification requests for one UE, with mandatory session entries.
pub struct ModifyRequest<'a> {
    /// Peer AMF UE identifier; no ownership inference.
    pub amf: AmfUeId,
    /// Local RAN UE identifier; the caller correlates the pair.
    pub ran: RanUeId,
    /// Nonempty session requests. NAS is opaque and forwarded conditionally.
    pub sessions: SessionModifications<'a>,
}
redacted!(ModifyRequest<'_>);
/// Session results within the successful NGAP procedure outcome, including
/// all-failed or mixed session results. At least one list must be present.
#[derive(Clone, PartialEq, Eq)]
pub struct ModifyResponse {
    /// Peer AMF UE identifier.
    pub amf: AmfUeId,
    /// Local RAN UE identifier.
    pub ran: RanUeId,
    /// Optional successful sessions, disjoint from failed sessions.
    pub modified: Option<ModifiedSessions>,
    /// Optional failed session modifications.
    pub failed: Option<FailedModifications>,
    /// Optional qualified N3IWF location.
    pub location: Option<N3iwfLocation>,
    /// Optional diagnostics with same-procedure response applicability.
    pub diagnostics: Option<CriticalityDiagnostics>,
}
redacted!(ModifyResponse);
/// Both procedure-26 outcomes; no unsuccessful procedure outcome is defined.
pub enum ModifyMessage<'a> {
    /// AMF-originated request.
    Request(ModifyRequest<'a>),
    /// N3IWF session results.
    Response(ModifyResponse),
}
redacted!(ModifyMessage<'_>);
/// Fully admitted fields and value-free caller-owned diagnostics.
#[derive(Debug)]
pub struct AdmittedModify<'a> {
    /// Typed fields without resource or procedure side effects.
    pub message: ModifyMessage<'a>,
    /// Retained unknown-ignore or receiver-ignored RAN Paging Priority IEs.
    pub ignored_ie_count: usize,
    /// Retained unknown-notify identifiers, never their values.
    pub notify_ie_ids: Vec<u16>,
    /// Nonempty contained request diagnostics in session order.
    pub transfer_diagnostics: Vec<SessionTransferDiagnostics>,
}
impl ModifyRequest<'_> {
    /// Construct in schema order, then apply complete admission with the same
    /// byte/count/depth limits. RAN Paging Priority is receiver-ignored by N3IWF.
    pub fn construct(&self, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
        let out = output_context(ctx);
        construct(
            MessageType::PduSessionResourceModifyRequest,
            vec![
                (10, Criticality::reject, self.amf.encode(out)),
                (85, Criticality::reject, self.ran.encode(out)),
                (64, Criticality::reject, self.sessions.encode(out)),
            ],
            ctx,
        )
    }
}
impl ModifyResponse {
    fn validate(&self) -> Result<(), DecodeError> {
        if self.modified.is_none() && self.failed.is_none() {
            return Err(invalid("missing modification results"));
        }
        let mut seen = [0; 4];
        if let Some(list) = &self.modified {
            for v in list.values() {
                unique_id(&mut seen, v.id)?;
            }
        }
        if let Some(list) = &self.failed {
            for v in list.values() {
                unique_id(&mut seen, v.id)?;
            }
        }
        if let Some(d) = &self.diagnostics {
            response_diagnostics(d)?;
        }
        Ok(())
    }
    /// Require at least one disjoint result list and applicable diagnostics,
    /// then construct and admit with the caller's complete resource limits.
    pub fn construct(&self, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
        self.validate()?;
        let out = output_context(ctx);
        let mut fields = vec![
            (10, Criticality::ignore, self.amf.encode(out)),
            (85, Criticality::ignore, self.ran.encode(out)),
        ];
        if let Some(v) = &self.modified {
            fields.push((65, Criticality::ignore, v.encode(out)));
        }
        if let Some(v) = &self.failed {
            fields.push((54, Criticality::ignore, v.encode(out)));
        }
        if let Some(v) = &self.location {
            fields.push((121, Criticality::ignore, v.encode(out)));
        }
        if let Some(v) = &self.diagnostics {
            fields.push((19, Criticality::ignore, v.encode(out)));
        }
        construct(MessageType::PduSessionResourceModifyResponse, fields, ctx)
    }
}
impl<'a> ModifyMessage<'a> {
    /// Admit the generic decoder's policy-selected IE view. Use the same
    /// context for both boundaries: discarded fields cannot be recovered.
    /// A typed rejection alone does not send a prescribed failure response.
    pub fn from_pdu(pdu: &'a Pdu, ctx: DecodeContext) -> Result<AdmittedModify<'a>, DecodeError> {
        crate::enforce_depth(5, ctx)?;
        pdu.wire_len(output_context(ctx))
            .map_err(|_| invalid("modify container policy"))?;
        macro_rules! fields {
            ($value:ident,$request:literal) => {
                admit(
                    $request,
                    $value
                        .protocol_ies
                        .0
                        .iter()
                        .map(|ie| (ie.id, ie.criticality as u8, ie.value.as_bytes())),
                    ctx,
                )
            };
        }
        match &pdu.kind {
            PduKind::Initiating {
                message: Message::PduSessionResourceModifyRequest(v),
                ..
            } => fields!(v, true),
            PduKind::Successful {
                message: Message::PduSessionResourceModifyResponse(v),
                ..
            } => fields!(v, false),
            _ => Err(invalid("modify procedure outcome")),
        }
    }
}
fn admit<'a>(
    request: bool,
    fields: impl Iterator<Item = (u16, u8, &'a [u8])>,
    ctx: DecodeContext,
) -> Result<AdmittedModify<'a>, DecodeError> {
    let leaf = DecodeContext {
        max_depth: ctx.max_depth.saturating_sub(4),
        ..ctx
    };
    let (mut amf, mut ran, mut requests, mut modified, mut failed, mut location, mut diagnostics) =
        (None, None, None, None, None, None, None);
    let mut ignored_ie_count = 0;
    let mut notify_ie_ids = Vec::new();
    let mut transfer_diagnostics = Vec::new();
    for (index, (id, criticality, value)) in fields.enumerate() {
        if index >= ctx.max_ies {
            return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, 0));
        }
        match id {
            10 => amf = Some(AmfUeId::decode(value, leaf)?),
            85 => ran = Some(RanUeId::decode(value, leaf)?),
            83 if request => ignored_ie_count += 1,
            64 if request => {
                let admitted = SessionModifications::decode(value, leaf)?;
                requests = Some(admitted.requests);
                transfer_diagnostics = admitted.diagnostics;
            }
            65 if !request => modified = Some(ModifiedSessions::decode(value, leaf)?),
            54 if !request => failed = Some(FailedModifications::decode(value, leaf)?),
            121 if !request => location = Some(N3iwfLocation::decode(value, leaf)?),
            19 if !request => diagnostics = Some(CriticalityDiagnostics::decode(value, leaf)?),
            _ => match criticality {
                1 => ignored_ie_count += 1,
                2 => notify_ie_ids.push(id),
                _ => return Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, 0)),
            },
        }
    }
    let amf = amf.ok_or_else(|| invalid("missing modify amf ue id"))?;
    let ran = ran.ok_or_else(|| invalid("missing modify ran ue id"))?;
    let message = if request {
        ModifyMessage::Request(ModifyRequest {
            amf,
            ran,
            sessions: requests.ok_or_else(|| invalid("missing modification requests"))?,
        })
    } else {
        let response = ModifyResponse {
            amf,
            ran,
            modified,
            failed,
            location,
            diagnostics,
        };
        response.validate()?;
        ModifyMessage::Response(response)
    };
    Ok(AdmittedModify {
        message,
        ignored_ie_count,
        notify_ie_ids,
        transfer_diagnostics,
    })
}
fn construct(
    kind: MessageType,
    fields: Vec<(u16, Criticality, Result<EncodedValue, EncodeError>)>,
    ctx: DecodeContext,
) -> Result<Pdu, DecodeError> {
    let fields = fields
        .into_iter()
        .map(|(id, c, v)| {
            v.map(|v| (id, c, v))
                .map_err(|_| invalid("modify encoding or capacity"))
        })
        .collect::<Result<Vec<_>, DecodeError>>()?;
    let ies: Vec<_> = fields
        .iter()
        .map(|(id, c, v)| ProtocolIe::new(*id, *c, v.as_bytes()))
        .collect();
    let pdu = Pdu::from_protocol_ies(kind, &ies, ctx)?;
    ModifyMessage::from_pdu(&pdu, ctx)?;
    Ok(pdu)
}
fn output_context(ctx: DecodeContext) -> EncodeContext {
    EncodeContext {
        max_message_len: ctx.max_message_len,
        ..EncodeContext::default()
    }
}
