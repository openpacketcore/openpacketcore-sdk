//! PDU Session Resource Release Command/Response field admission.
//!
//! Peer release requests and reports do not prove session ownership or trigger
//! resource cleanup. The caller correlates identifiers with its own state.

use super::release::Cause;
use super::resource_results::{cause_width, read_cause};
use super::session_lists::{encode_list, preflight_results, validate_ids, SessionId};
use super::setup_fields::Reader;
use super::*;
use crate::{policy, Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::Encode;

/// Root release command transfer containing one explicit peer-reported Cause.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReleaseCommandTransfer {
    /// Cause without any authorization or local cleanup implication.
    pub cause: Cause,
}
redacted!(ReleaseCommandTransfer);

impl ReleaseCommandTransfer {
    fn wire_len(self) -> usize {
        (6 + cause_width(self.cause.class())).div_ceil(8)
    }
    /// Encode the independently qualified generated root with exact sizing.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity(self.wire_len(), ctx)?;
        encode_leaf(
            &asn::PDUSessionResourceReleaseCommandTransfer::new(self.cause.generated()?, None),
            ctx,
        )
    }
    /// Require depth three and an exact root Cause, with no extensions or
    /// nonzero final padding, before invoking the qualified generated decoder.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 3)?;
        let mut reader = Reader::new(input, ctx);
        reader.flags(2)?;
        read_cause(&mut reader)?;
        reader.finish()?;
        let value: asn::PDUSessionResourceReleaseCommandTransfer = decode_leaf(input)?;
        Ok(Self {
            cause: Cause::from_generated(value.cause)?,
        })
    }
}

/// Empty root release response transfer. Usage reports and other extensions
/// are unsupported; absence is not evidence that resources have been removed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReleaseResponseTransfer;
redacted!(ReleaseResponseTransfer);

impl ReleaseResponseTransfer {
    /// Encode the independently qualified single-octet empty root.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity(1, ctx)?;
        encode_leaf(
            &asn::PDUSessionResourceReleaseResponseTransfer::new(None),
            ctx,
        )
    }
    /// Require depth one and exactly the empty root including zero padding.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 1)?;
        if input != [0] {
            return Err(invalid("release response transfer framing"));
        }
        let _: asn::PDUSessionResourceReleaseResponseTransfer = decode_leaf(input)?;
        Ok(Self)
    }
}

/// A session named by a release command, with its root Cause.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RequestedSessionRelease {
    /// Session identifier, without an ownership claim.
    pub id: SessionId,
    /// Peer request's per-session Cause.
    pub transfer: ReleaseCommandTransfer,
}
redacted!(RequestedSessionRelease);

/// Nonempty release requests with 1–256 unique session IDs; depth six.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionReleaseRequests(Vec<RequestedSessionRelease>);
redacted!(SessionReleaseRequests);

impl SessionReleaseRequests {
    /// Enforce the root count and session uniqueness.
    pub fn new(values: Vec<RequestedSessionRelease>) -> Result<Self, DecodeError> {
        validate_ids(values.iter().map(|v| v.id), values.len())?;
        Ok(Self(values))
    }
    /// Explicit peer requests in received order.
    pub fn values(&self) -> &[RequestedSessionRelease] {
        &self.0
    }
    /// Preflight exact complete size before materializing generated values.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let length = 1 + self
            .0
            .iter()
            .map(|v| 3 + v.transfer.wire_len())
            .sum::<usize>();
        capacity(length, ctx)?;
        let values = self
            .0
            .iter()
            .map(|v| {
                Ok(asn::PDUSessionResourceToReleaseItemRelCmd::new(
                    asn::PDUSessionID(v.id.value()),
                    v.transfer.encode(ctx)?.as_bytes().to_vec().into(),
                    None,
                ))
            })
            .collect::<Result<Vec<_>, EncodeError>>()?;
        encode_list(&asn::PDUSessionResourceToReleaseListRelCmd(values), length)
    }
    /// Bound physical counts, duplicates, flags, lengths and padding before
    /// generated materialization. Admit every contained root before returning.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        preflight_results(input, ctx, 6, 2)?;
        let value: asn::PDUSessionResourceToReleaseListRelCmd = decode_leaf(input)?;
        let nested = DecodeContext {
            max_depth: ctx.max_depth.saturating_sub(3),
            ..ctx
        };
        let values = value
            .0
            .iter()
            .map(|v| {
                Ok(RequestedSessionRelease {
                    id: SessionId::new(v.p_dusession_id.0),
                    transfer: ReleaseCommandTransfer::decode(
                        v.p_dusession_resource_release_command_transfer.as_ref(),
                        nested,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, DecodeError>>()?;
        Ok(Self(values))
    }
}

/// Nonempty peer release report with 1–256 unique session IDs and empty root
/// response transfers. Depth four; correlation and cleanup are caller-owned.
#[derive(Clone, PartialEq, Eq)]
pub struct ReleasedSessions(Vec<SessionId>);
redacted!(ReleasedSessions);

impl ReleasedSessions {
    /// Enforce the root count and session uniqueness.
    pub fn new(values: Vec<SessionId>) -> Result<Self, DecodeError> {
        validate_ids(values.iter().copied(), values.len())?;
        Ok(Self(values))
    }
    /// Explicit reported session IDs in received order.
    pub fn values(&self) -> &[SessionId] {
        &self.0
    }
    /// Preflight exact complete size before materializing generated values.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let length = 1 + 4 * self.0.len();
        capacity(length, ctx)?;
        let transfer = ReleaseResponseTransfer.encode(ctx)?;
        let values = self
            .0
            .iter()
            .map(|id| {
                asn::PDUSessionResourceReleasedItemRelRes::new(
                    asn::PDUSessionID(id.value()),
                    transfer.as_bytes().to_vec().into(),
                    None,
                )
            })
            .collect();
        encode_list(&asn::PDUSessionResourceReleasedListRelRes(values), length)
    }
    /// Preflight counts, duplicates and framing, then require each contained
    /// response to be exactly the admitted empty root.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        preflight_results(input, ctx, 4, 1)?;
        let value: asn::PDUSessionResourceReleasedListRelRes = decode_leaf(input)?;
        let nested = DecodeContext {
            max_depth: ctx.max_depth.saturating_sub(3),
            ..ctx
        };
        let values = value
            .0
            .iter()
            .map(|v| {
                ReleaseResponseTransfer::decode(
                    v.p_dusession_resource_release_response_transfer.as_ref(),
                    nested,
                )?;
                Ok(SessionId::new(v.p_dusession_id.0))
            })
            .collect::<Result<Vec<_>, DecodeError>>()?;
        Ok(Self(values))
    }
}

/// Release command fields, without any authorization or resource effect.
pub struct SessionReleaseCommand<'a> {
    /// Peer AMF UE identifier.
    pub amf: AmfUeId,
    /// Local RAN UE identifier.
    pub ran: RanUeId,
    /// Nonempty requested sessions with per-session Causes.
    pub sessions: SessionReleaseRequests,
    /// Optional opaque NAS, never interpreted as an authorization decision.
    pub nas: Option<NasPdu<'a>>,
}
redacted!(SessionReleaseCommand<'_>);

/// Peer release response fields, without proof of cleanup or correlation.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionReleaseResponse {
    /// Peer AMF UE identifier.
    pub amf: AmfUeId,
    /// Local RAN UE identifier.
    pub ran: RanUeId,
    /// Nonempty reported sessions, each carrying an empty response transfer.
    pub sessions: ReleasedSessions,
    /// Optional N3IWF location; other access choices are unsupported.
    pub location: Option<N3iwfLocation>,
    /// Optional same-procedure diagnostics, without triggering procedure fields.
    pub diagnostics: Option<super::reset_fields::CriticalityDiagnostics>,
}
redacted!(SessionReleaseResponse);

/// The command and successful response; there is no unsuccessful outcome.
pub enum ResourceReleaseMessage<'a> {
    /// PDU Session Resource Release Command.
    Command(SessionReleaseCommand<'a>),
    /// PDU Session Resource Release Response.
    Response(SessionReleaseResponse),
}
redacted!(ResourceReleaseMessage<'_>);

/// Admitted fields and identifier-only diagnostics, without resource effects.
#[derive(Debug)]
pub struct AdmittedResourceRelease<'a> {
    /// Validated fields for the selected message outcome.
    pub message: ResourceReleaseMessage<'a>,
    /// Receiver-ignored or unknown-ignore IEs in the selected policy view.
    pub ignored_ie_count: usize,
    /// Unknown-notify IE identifiers, never their opaque values.
    pub notify_ie_ids: Vec<u16>,
}

impl ResourceReleaseMessage<'_> {
    /// Construct the admitted canonical subset, requiring depth ten for a
    /// command or eight for a response. No cleanup or response is triggered.
    pub fn construct(&self, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
        let output = output_context(ctx);
        let mut fields = Vec::new();
        let kind = match self {
            Self::Command(value) => {
                crate::enforce_depth(10, ctx)?;
                fields.push((10, Criticality::reject, value.amf.encode(output)));
                fields.push((85, Criticality::reject, value.ran.encode(output)));
                if let Some(nas) = &value.nas {
                    fields.push((38, Criticality::ignore, nas.encode(output)));
                }
                fields.push((79, Criticality::reject, value.sessions.encode(output)));
                MessageType::PduSessionResourceReleaseCommand
            }
            Self::Response(value) => {
                crate::enforce_depth(8, ctx)?;
                let diagnostics =
                    super::reset_fields::encode_response_diagnostics(&value.diagnostics, ctx)?;
                fields.push((10, Criticality::ignore, value.amf.encode(output)));
                fields.push((85, Criticality::ignore, value.ran.encode(output)));
                fields.push((70, Criticality::ignore, value.sessions.encode(output)));
                if let Some(location) = &value.location {
                    fields.push((121, Criticality::ignore, location.encode(output)));
                }
                if let Some(value) = diagnostics {
                    fields.push((19, Criticality::ignore, Ok(value)));
                }
                MessageType::PduSessionResourceReleaseResponse
            }
        };
        let values = fields
            .into_iter()
            .map(|(id, crit, value)| {
                value
                    .map(|value| (id, crit, value))
                    .map_err(|_| invalid("resource release encoding or capacity"))
            })
            .collect::<Result<Vec<_>, DecodeError>>()?;
        let ies: Vec<_> = values
            .iter()
            .map(|(id, crit, value)| ProtocolIe::new(*id, *crit, value.as_bytes()))
            .collect();
        let pdu = Pdu::from_protocol_ies(kind, &ies, ctx)?;
        ResourceReleaseMessage::from_pdu(&pdu, ctx)?;
        Ok(pdu)
    }

    /// Admit the generic decoder's selected IE view. Use the same context for
    /// generic decoding and this boundary; prior filtering cannot be undone.
    pub fn from_pdu(
        pdu: &Pdu,
        ctx: DecodeContext,
    ) -> Result<AdmittedResourceRelease<'_>, DecodeError> {
        crate::enforce_depth(5, ctx)?;
        pdu.wire_len(output_context(ctx))
            .map_err(|_| invalid("resource release container policy"))?;
        match &pdu.kind {
            PduKind::Initiating {
                message: Message::PduSessionResourceReleaseCommand(value),
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
            PduKind::Successful {
                message: Message::PduSessionResourceReleaseResponse(value),
                ..
            } => admit(
                false,
                value
                    .protocol_ies
                    .0
                    .iter()
                    .map(|v| (v.id, v.criticality as u8, v.value.as_bytes())),
                ctx,
            ),
            _ => Err(invalid("resource release outcome")),
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
    command: bool,
    fields: impl Iterator<Item = (u16, u8, &'a [u8])>,
    ctx: DecodeContext,
) -> Result<AdmittedResourceRelease<'a>, DecodeError> {
    let (profile, supported): (_, &[u16]) = if command {
        (
            policy::PDU_SESSION_RESOURCE_RELEASE_COMMAND,
            &[10, 85, 38, 79],
        )
    } else {
        (
            policy::PDU_SESSION_RESOURCE_RELEASE_RESPONSE,
            &[10, 85, 70, 121, 19],
        )
    };
    let leaf = DecodeContext {
        max_depth: ctx.max_depth.saturating_sub(4),
        ..ctx
    };
    let (mut amf, mut ran, mut nas, mut location) = (None, None, None, None);
    let (mut requested, mut released) = (None, None);
    let mut diagnostics = None;
    let mut ignored_ie_count = 0;
    let mut notify_ie_ids = Vec::new();
    for (index, (id, criticality, value)) in fields.enumerate() {
        if index >= ctx.max_ies {
            return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, 0));
        }
        if command && id == 83 {
            // TS 29.413 5.3: do not decode RAN Paging Priority contents.
            ignored_ie_count += 1;
            continue;
        }
        if !supported.contains(&id) {
            if profile.recognizes(id) {
                return Err(invalid("applicable resource release ie not admitted"));
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
            79 => requested = Some(SessionReleaseRequests::decode(value, leaf)?),
            70 => released = Some(ReleasedSessions::decode(value, leaf)?),
            121 => location = Some(N3iwfLocation::decode(value, leaf)?),
            19 => {
                diagnostics = Some(super::reset_fields::decode_response_diagnostics(
                    value, leaf,
                )?)
            }
            _ => return Err(invalid("resource release field dispatch")),
        }
    }
    let amf = amf.ok_or_else(|| invalid("missing amf ue id"))?;
    let ran = ran.ok_or_else(|| invalid("missing ran ue id"))?;
    let message = if command {
        ResourceReleaseMessage::Command(SessionReleaseCommand {
            amf,
            ran,
            sessions: requested.ok_or_else(|| invalid("missing resource release list"))?,
            nas,
        })
    } else {
        ResourceReleaseMessage::Response(SessionReleaseResponse {
            amf,
            ran,
            sessions: released.ok_or_else(|| invalid("missing resource release result"))?,
            location,
            diagnostics,
        })
    };
    Ok(AdmittedResourceRelease {
        message,
        ignored_ie_count,
        notify_ie_ids,
    })
}
