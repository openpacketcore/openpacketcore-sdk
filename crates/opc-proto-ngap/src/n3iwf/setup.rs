//! Typed N3IWF NG Setup Request, Response and Failure admission.
//!
//! TS 29.413 requires receiver-ignore behavior for paging DRX and IAB fields.
//! Request construction therefore takes an explicit paging value separately;
//! receive checks its mandatory presence without interpreting its payload.
//! No association activation, AMF selection, slice authorization, timer or
//! retry is performed here. Other applicable optional IEs fail explicitly.
use super::release::Cause;
pub use super::setup_fields::{
    AmfName, GlobalN3iwfId, Guami, PlmnSlices, PlmnSupportList, ServedGuamiList, SupportedTa,
    SupportedTaList,
};
use super::*;
use crate::{policy, Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::Encode;

/// Caller-selected paging value required for construction, ignored on receive.
pub use asn::PagingDRX as PagingDrx;
/// Advertised retry delay; the caller owns timer and retry behavior.
pub use asn::TimeToWait;

/// Admitted request fields, excluding receiver-ignored DRX.
#[derive(Clone, PartialEq, Eq)]
pub struct NgSetupRequest {
    /// N3IWF identity advertised by the sender.
    pub global: GlobalN3iwfId,
    /// Supported tracking areas, PLMNs and slices.
    pub tracking_areas: SupportedTaList,
}
redacted!(NgSetupRequest);
/// Admitted response root fields.
#[derive(Clone, PartialEq, Eq)]
pub struct NgSetupResponse {
    /// Advertised AMF name.
    pub name: AmfName,
    /// Served AMF identities, without backup names/extensions.
    pub served: ServedGuamiList,
    /// Relative capacity in the ASN.1 range 0..=255; no selection is inferred.
    pub relative_capacity: u8,
    /// Advertised PLMNs and slices.
    pub plmns: PlmnSupportList,
    /// Optional same-procedure diagnostics; absence and an empty root differ.
    pub diagnostics: Option<super::reset_fields::CriticalityDiagnostics>,
}
redacted!(NgSetupResponse);
/// Admitted failure fields, with optional root retry delay.
#[derive(Clone, PartialEq, Eq)]
pub struct NgSetupFailure {
    /// Cause selected by the sender.
    pub cause: Cause,
    /// Optional delay; no timer is created by the codec.
    pub time_to_wait: Option<TimeToWait>,
    /// Optional same-procedure diagnostics with no triggering procedure header.
    pub diagnostics: Option<super::reset_fields::CriticalityDiagnostics>,
}
redacted!(NgSetupFailure);

/// Validated fields for the three outcomes of procedure 21.
#[derive(Clone, PartialEq, Eq)]
pub enum SetupMessage {
    /// Initiating NG Setup Request.
    Request(NgSetupRequest),
    /// Successful NG Setup Response.
    Response(NgSetupResponse),
    /// Unsuccessful NG Setup Failure.
    Failure(NgSetupFailure),
}
redacted!(SetupMessage);
/// Field admission and value-free caller diagnostics.
#[derive(Debug)]
pub struct AdmittedSetup {
    /// Validated fields; no procedure state change has occurred.
    pub message: SetupMessage,
    /// Receiver-ignored or unknown-ignore IEs retained in the filtered view.
    pub ignored_ie_count: usize,
    /// Unknown-notify identifiers for the caller's diagnostics handling.
    pub notify_ie_ids: Vec<u16>,
}

impl NgSetupRequest {
    /// Construct the canonical request with an explicit mandatory DRX value.
    /// Requires message depth twelve and the field-local cumulative item bound.
    pub fn construct(&self, paging: PagingDrx, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
        crate::enforce_depth(12, ctx)?;
        let count = self.tracking_areas.values().len()
            + self
                .tracking_areas
                .values()
                .iter()
                .map(|ta| plmn_items(ta.plmns()))
                .sum::<usize>();
        check_items(count.max(3), ctx)?;
        let output = output_context(ctx);
        construct(
            MessageType::NgSetupRequest,
            vec![
                (
                    27,
                    Criticality::reject,
                    self.global.encode(output).map_err(encode_error)?,
                ),
                (
                    102,
                    Criticality::reject,
                    self.tracking_areas.encode(output).map_err(encode_error)?,
                ),
                (
                    21,
                    Criticality::ignore,
                    encode_leaf(&paging, output).map_err(encode_error)?,
                ),
            ],
            ctx,
        )
    }
}
impl NgSetupResponse {
    /// Construct the canonical response; requires message depth ten.
    pub fn construct(&self, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
        crate::enforce_depth(10, ctx)?;
        let diagnostics = super::reset_fields::encode_response_diagnostics(&self.diagnostics, ctx)?;
        check_items(
            self.served
                .values()
                .len()
                .max(plmn_items(self.plmns.values()))
                .max(4 + usize::from(diagnostics.is_some())),
            ctx,
        )?;
        let output = output_context(ctx);
        let mut fields = vec![
            (
                1,
                Criticality::reject,
                self.name.encode(output).map_err(encode_error)?,
            ),
            (
                96,
                Criticality::reject,
                self.served.encode(output).map_err(encode_error)?,
            ),
            (
                86,
                Criticality::ignore,
                encode_leaf(&asn::RelativeAMFCapacity(self.relative_capacity), output)
                    .map_err(encode_error)?,
            ),
            (
                80,
                Criticality::reject,
                self.plmns.encode(output).map_err(encode_error)?,
            ),
        ];
        if let Some(value) = diagnostics {
            fields.push((19, Criticality::ignore, value));
        }
        construct(MessageType::NgSetupResponse, fields, ctx)
    }
}
impl NgSetupFailure {
    /// Construct the canonical failure; requires message depth six.
    pub fn construct(&self, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
        crate::enforce_depth(6, ctx)?;
        let diagnostics = super::reset_fields::encode_response_diagnostics(&self.diagnostics, ctx)?;
        check_items(
            1 + usize::from(self.time_to_wait.is_some()) + usize::from(diagnostics.is_some()),
            ctx,
        )?;
        let output = output_context(ctx);
        let mut fields = vec![(
            15,
            Criticality::ignore,
            self.cause.encode(output).map_err(encode_error)?,
        )];
        if let Some(wait) = self.time_to_wait {
            fields.push((
                107,
                Criticality::ignore,
                encode_leaf(&wait, output).map_err(encode_error)?,
            ));
        }
        if let Some(value) = diagnostics {
            fields.push((19, Criticality::ignore, value));
        }
        construct(MessageType::NgSetupFailure, fields, ctx)
    }
}
fn plmn_items(values: &[PlmnSlices]) -> usize {
    values.len() + values.iter().map(|p| p.slices().len()).sum::<usize>()
}
fn check_items(count: usize, ctx: DecodeContext) -> Result<(), DecodeError> {
    if count > ctx.max_ies {
        return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, 0));
    }
    Ok(())
}
fn output_context(ctx: DecodeContext) -> EncodeContext {
    EncodeContext {
        max_message_len: ctx.max_message_len,
        ..EncodeContext::default()
    }
}
fn encode_error(_: EncodeError) -> DecodeError {
    invalid("setup field encoding or capacity")
}
fn construct(
    kind: MessageType,
    fields: Vec<(u16, Criticality, EncodedValue)>,
    ctx: DecodeContext,
) -> Result<Pdu, DecodeError> {
    let ies: Vec<_> = fields
        .iter()
        .map(|(id, crit, value)| ProtocolIe::new(*id, *crit, value.as_bytes()))
        .collect();
    let pdu = Pdu::from_protocol_ies(kind, &ies, ctx)?;
    SetupMessage::from_pdu(&pdu, ctx)?;
    Ok(pdu)
}

impl SetupMessage {
    /// Validate the generic decoder's filtered IE view and mutable wrapper.
    /// Generic unknown/duplicate policy has already run; raw bytes stay intact.
    pub fn from_pdu(pdu: &Pdu, ctx: DecodeContext) -> Result<AdmittedSetup, DecodeError> {
        crate::enforce_depth(5, ctx)?;
        pdu.wire_len(output_context(ctx))
            .map_err(|_| invalid("setup message container policy"))?;
        match &pdu.kind {
            PduKind::Initiating {
                message: Message::NgSetupRequest(v),
                ..
            } => admit(
                MessageType::NgSetupRequest,
                v.protocol_ies
                    .0
                    .iter()
                    .map(|ie| (ie.id, ie.criticality as u8, ie.value.as_bytes())),
                ctx,
            ),
            PduKind::Successful {
                message: Message::NgSetupResponse(v),
                ..
            } => admit(
                MessageType::NgSetupResponse,
                v.protocol_ies
                    .0
                    .iter()
                    .map(|ie| (ie.id, ie.criticality as u8, ie.value.as_bytes())),
                ctx,
            ),
            PduKind::Unsuccessful {
                message: Message::NgSetupFailure(v),
                ..
            } => admit(
                MessageType::NgSetupFailure,
                v.protocol_ies
                    .0
                    .iter()
                    .map(|ie| (ie.id, ie.criticality as u8, ie.value.as_bytes())),
                ctx,
            ),
            _ => Err(invalid("setup message outcome")),
        }
    }
}
fn admit<'a>(
    kind: MessageType,
    fields: impl Iterator<Item = (u16, u8, &'a [u8])>,
    ctx: DecodeContext,
) -> Result<AdmittedSetup, DecodeError> {
    let (profile, supported, ignored): (policy::IeProfile, &[u16], &[u16]) = match kind {
        MessageType::NgSetupRequest => (policy::NG_SETUP_REQUEST, &[27, 102], &[21, 204]),
        MessageType::NgSetupResponse => {
            (policy::NG_SETUP_RESPONSE, &[1, 96, 86, 80, 19], &[200, 404])
        }
        MessageType::NgSetupFailure => (policy::NG_SETUP_FAILURE, &[15, 107, 19], &[]),
        _ => return Err(invalid("setup message outcome")),
    };
    let leaf = DecodeContext {
        max_depth: ctx.max_depth.saturating_sub(4),
        ..ctx
    };
    let (mut global, mut tracking_areas, mut paging_present) = (None, None, false);
    let (mut name, mut served, mut relative_capacity, mut plmns) = (None, None, None, None);
    let (mut cause, mut time_to_wait) = (None, None);
    let mut diagnostics = None;
    let mut ignored_ie_count = 0;
    let mut notify_ie_ids = Vec::new();
    for (index, (id, crit, value)) in fields.enumerate() {
        check_items(index + 1, ctx)?;
        if ignored.contains(&id) {
            paging_present |= id == 21;
            ignored_ie_count += 1;
            continue;
        }
        if !supported.contains(&id) {
            if profile.recognizes(id) {
                return Err(invalid("applicable setup ie not admitted"));
            }
            match crit {
                1 => ignored_ie_count += 1,
                2 => notify_ie_ids.push(id),
                _ => return Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, 0)),
            }
            continue;
        }
        match id {
            27 => global = Some(GlobalN3iwfId::decode(value, leaf)?),
            102 => tracking_areas = Some(SupportedTaList::decode(value, leaf)?),
            1 => name = Some(AmfName::decode(value, leaf)?),
            96 => served = Some(ServedGuamiList::decode(value, leaf)?),
            86 => {
                bound(value, leaf, 1)?;
                relative_capacity = Some(decode_leaf::<asn::RelativeAMFCapacity>(value)?.0);
            }
            80 => plmns = Some(PlmnSupportList::decode(value, leaf)?),
            15 => cause = Some(Cause::decode(value, leaf)?),
            107 => {
                bound(value, leaf, 1)?;
                if value.first().is_some_and(|v| v & 0x80 != 0) {
                    return Err(unsupported());
                }
                time_to_wait = Some(decode_leaf::<TimeToWait>(value)?);
            }
            19 => {
                diagnostics = Some(super::reset_fields::decode_response_diagnostics(
                    value, leaf,
                )?)
            }
            _ => return Err(invalid("setup field dispatch")),
        }
    }
    let message = match kind {
        MessageType::NgSetupRequest => {
            if !paging_present {
                return Err(invalid("missing default paging drx"));
            }
            SetupMessage::Request(NgSetupRequest {
                global: global.ok_or_else(|| invalid("missing global n3iwf id"))?,
                tracking_areas: tracking_areas
                    .ok_or_else(|| invalid("missing supported tracking areas"))?,
            })
        }
        MessageType::NgSetupResponse => SetupMessage::Response(NgSetupResponse {
            name: name.ok_or_else(|| invalid("missing amf name"))?,
            served: served.ok_or_else(|| invalid("missing served guamis"))?,
            relative_capacity: relative_capacity
                .ok_or_else(|| invalid("missing relative amf capacity"))?,
            plmns: plmns.ok_or_else(|| invalid("missing plmn support"))?,
            diagnostics,
        }),
        MessageType::NgSetupFailure => SetupMessage::Failure(NgSetupFailure {
            cause: cause.ok_or_else(|| invalid("missing setup failure cause"))?,
            time_to_wait,
            diagnostics,
        }),
        _ => return Err(invalid("setup message outcome")),
    };
    Ok(AdmittedSetup {
        message,
        ignored_ie_count,
        notify_ie_ids,
    })
}
