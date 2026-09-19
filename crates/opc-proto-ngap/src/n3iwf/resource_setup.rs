//! Initial Context Setup and PDU Session Resource Setup field admission.
//!
//! These codecs validate the documented N3IWF subset without establishing UE
//! ownership, authorizing a slice, using a key or changing session resources.
//! TS 29.413 ignores security-capability contents on receive; construction
//! still requires an explicit mandatory capability value from the caller.

use super::context_fields::{
    validate_slice_lists, AllowedNssai, Guami, PartiallyAllowedNssai, SecurityAlgorithmMasks,
};
use super::nas::UeAggregateBitRate;
use super::nas_fields::{ExtendedAmfName, MaskedImeisv};
use super::release::Cause;
use super::session_lists::{
    FailedSessions, SessionResourceTypes, SessionResults, SessionSetupRequests,
    SessionTransferDiagnostics, SuccessfulSessions,
};
use super::setup_fields::AmfName;
pub use super::trace_fields::{TraceActivation, TraceDepth};
use super::*;
use crate::{policy, Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::Encode;

/// Context request fields, excluding receiver-ignored security capabilities.
pub struct InitialContextRequest<'a> {
    /// AMF-assigned UE identifier, without an ownership claim.
    pub amf: AmfUeId,
    /// RAN-assigned UE identifier, without an ownership claim.
    pub ran: RanUeId,
    /// AMF identity advertised by the peer.
    pub guami: Guami,
    /// Advertised allowed slices; the caller owns authorization decisions.
    pub allowed: AllowedNssai,
    /// Borrowed security key; no key use or installation occurs.
    pub key: SecurityKey<'a>,
    /// Required whenever a session request list is present.
    pub aggregate_bit_rate: Option<UeAggregateBitRate>,
    /// Optional session requests with the admitted root transfer profile.
    pub sessions: Option<SessionSetupRequests<'a>>,
    /// Optional opaque NAS, separate from per-session NAS.
    pub nas: Option<NasPdu<'a>>,
    /// Optional root name of the old AMF; no AMF is selected.
    pub old_amf: Option<AmfName>,
    /// Optional trace parameters; no trace session is started or authorized.
    pub trace: Option<TraceActivation>,
    /// Optional fixed masked identity, without subscriber interpretation.
    pub masked_imeisv: Option<MaskedImeisv>,
    /// Optional partial slices, disjoint from Allowed NSSAI with combined count <= 8.
    pub partially_allowed_nssai: Option<PartiallyAllowedNssai>,
    /// Independent optional VisibleString and UTF8String old-AMF names.
    pub extended_old_amf: Option<ExtendedAmfName>,
}
redacted!(InitialContextRequest<'_>);

/// Context setup result, including a possible partial resource result.
pub struct InitialContextResponse {
    /// Peer AMF UE identifier.
    pub amf: AmfUeId,
    /// Local RAN UE identifier.
    pub ran: RanUeId,
    /// Disjoint optional results. Empty is valid when no sessions were requested.
    pub sessions: SessionResults,
    /// Optional same-procedure diagnostics; absence and an empty root differ.
    pub diagnostics: Option<super::reset_fields::CriticalityDiagnostics>,
}
redacted!(InitialContextResponse);

/// Context failure; it cannot contain a successful-session list.
pub struct InitialContextFailure {
    /// Peer AMF UE identifier.
    pub amf: AmfUeId,
    /// Local RAN UE identifier.
    pub ran: RanUeId,
    /// Peer-reported root Cause.
    pub cause: Cause,
    /// Optional failed sessions with individual root Causes.
    pub failed: Option<FailedSessions>,
    /// Optional same-procedure diagnostics with no triggering procedure header.
    pub diagnostics: Option<super::reset_fields::CriticalityDiagnostics>,
}
redacted!(InitialContextFailure);

/// PDU Session Resource Setup request for an existing UE context.
pub struct SessionResourceRequest<'a> {
    /// Peer AMF UE identifier.
    pub amf: AmfUeId,
    /// Local RAN UE identifier.
    pub ran: RanUeId,
    /// Mandatory nonempty session request list.
    pub sessions: SessionSetupRequests<'a>,
    /// Optional UE bitrate update, applicable to N3IWF.
    pub aggregate_bit_rate: Option<UeAggregateBitRate>,
    /// Optional opaque NAS, separate from per-session NAS.
    pub nas: Option<NasPdu<'a>>,
}
redacted!(SessionResourceRequest<'_>);

/// Session setup response. At least one result list must be present.
pub struct SessionResourceResponse {
    /// Peer AMF UE identifier.
    pub amf: AmfUeId,
    /// Local RAN UE identifier.
    pub ran: RanUeId,
    /// Disjoint nonempty overall result; failures use this successful outcome too.
    pub sessions: SessionResults,
    /// Optional N3IWF location; other access choices are unsupported.
    pub location: Option<N3iwfLocation>,
    /// Optional same-procedure diagnostics with ordered, repeatable IE reports.
    pub diagnostics: Option<super::reset_fields::CriticalityDiagnostics>,
}
redacted!(SessionResourceResponse);

/// Five admitted context/session setup outcomes.
pub enum ResourceSetupMessage<'a> {
    /// Initial Context Setup Request.
    InitialRequest(InitialContextRequest<'a>),
    /// Initial Context Setup Response.
    InitialResponse(InitialContextResponse),
    /// Initial Context Setup Failure.
    InitialFailure(InitialContextFailure),
    /// PDU Session Resource Setup Request.
    SessionRequest(SessionResourceRequest<'a>),
    /// PDU Session Resource Setup Response.
    SessionResponse(SessionResourceResponse),
}
redacted!(ResourceSetupMessage<'_>);

/// Fully admitted message and caller-owned diagnostics, without resource effects.
#[derive(Debug)]
pub struct AdmittedResourceSetup<'a> {
    /// Fields validated for this message outcome.
    pub message: ResourceSetupMessage<'a>,
    /// Receiver-ignored or unknown-ignore top-level IEs in the filtered view.
    pub ignored_ie_count: usize,
    /// Unknown-notify top-level identifiers; never their opaque values.
    pub notify_ie_ids: Vec<u16>,
    /// Nonempty diagnostics from contained request transfers, in input order.
    pub transfer_diagnostics: Vec<SessionTransferDiagnostics>,
}

impl InitialContextRequest<'_> {
    /// Construct with explicit mandatory security capabilities. A resource
    /// list requires UE aggregate bitrate and message depth seventeen; a
    /// context-only request needs depth eight. Receive ignores capability bits.
    pub fn construct(
        &self,
        capabilities: SecurityAlgorithmMasks,
        ctx: DecodeContext,
    ) -> Result<Pdu, DecodeError> {
        self.construct_with_resource_types(capabilities, None, ctx)
    }

    /// Construct with exact caller-established resource types for the requested
    /// sessions. This permits Session AMBR absence for all-GBR sessions; the
    /// enclosing UE-AMBR and mandatory security rules are unchanged.
    pub fn construct_classified(
        &self,
        capabilities: SecurityAlgorithmMasks,
        resource_types: &SessionResourceTypes,
        ctx: DecodeContext,
    ) -> Result<Pdu, DecodeError> {
        self.construct_with_resource_types(capabilities, Some(resource_types), ctx)
    }

    fn construct_with_resource_types(
        &self,
        capabilities: SecurityAlgorithmMasks,
        resource_types: Option<&SessionResourceTypes>,
        ctx: DecodeContext,
    ) -> Result<Pdu, DecodeError> {
        if resource_types.is_some() && self.sessions.is_none() {
            return Err(invalid("resource classification without sessions"));
        }
        validate_slice_lists(Some(&self.allowed), self.partially_allowed_nssai.as_ref())?;
        if self.sessions.is_some() && self.aggregate_bit_rate.is_none() {
            return Err(invalid("missing conditional ue aggregate bitrate"));
        }
        crate::enforce_depth(if self.sessions.is_some() { 17 } else { 8 }, ctx)?;
        let output = output_context(ctx);
        let mut fields = id_fields(self.amf, self.ran, Criticality::reject, output)?;
        if let Some(name) = &self.old_amf {
            fields.push((
                48,
                Criticality::reject,
                name.encode(output).map_err(encode_error)?,
            ));
        }
        if let Some(rate) = &self.aggregate_bit_rate {
            fields.push((
                110,
                Criticality::reject,
                rate.encode(output).map_err(encode_error)?,
            ));
        }
        fields.push((
            28,
            Criticality::reject,
            self.guami.encode(output).map_err(encode_error)?,
        ));
        if let Some(sessions) = &self.sessions {
            fields.push((
                71,
                Criticality::reject,
                encode_requests(sessions, resource_types, output)?,
            ));
        }
        fields.extend([
            (
                0,
                Criticality::reject,
                self.allowed.encode(output).map_err(encode_error)?,
            ),
            (
                119,
                Criticality::reject,
                capabilities.encode(output).map_err(encode_error)?,
            ),
            (
                94,
                Criticality::reject,
                self.key.encode(output).map_err(encode_error)?,
            ),
        ]);
        if let Some(trace) = self.trace {
            fields.push((
                108,
                Criticality::ignore,
                trace.encode(output).map_err(encode_error)?,
            ));
        }
        if let Some(identity) = self.masked_imeisv {
            fields.push((
                34,
                Criticality::ignore,
                identity.encode(output).map_err(encode_error)?,
            ));
        }
        if let Some(nas) = &self.nas {
            fields.push((
                38,
                Criticality::ignore,
                nas.encode(output).map_err(encode_error)?,
            ));
        }
        if let Some(partial) = &self.partially_allowed_nssai {
            fields.push((
                414,
                Criticality::ignore,
                partial.encode(output).map_err(encode_error)?,
            ));
        }
        if let Some(name) = &self.extended_old_amf {
            fields.push((
                443,
                Criticality::ignore,
                name.encode(output).map_err(encode_error)?,
            ));
        }
        construct_with_resource_types(
            MessageType::InitialContextSetupRequest,
            fields,
            resource_types,
            ctx,
        )
    }
}

impl InitialContextResponse {
    /// Construct a context response, including empty or partial session results.
    pub fn construct(&self, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
        result_depth(&self.sessions, ctx)?;
        let diagnostics = super::reset_fields::encode_response_diagnostics(&self.diagnostics, ctx)?;
        let output = output_context(ctx);
        let mut fields = id_fields(self.amf, self.ran, Criticality::ignore, output)?;
        result_fields(&mut fields, &self.sessions, 72, 55, output)?;
        if let Some(value) = diagnostics {
            fields.push((19, Criticality::ignore, value));
        }
        construct(MessageType::InitialContextSetupResponse, fields, ctx)
    }
}

impl InitialContextFailure {
    /// Construct failure, with optional individual failed-session results.
    pub fn construct(&self, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
        crate::enforce_depth(if self.failed.is_some() { 10 } else { 6 }, ctx)?;
        let diagnostics = super::reset_fields::encode_response_diagnostics(&self.diagnostics, ctx)?;
        let output = output_context(ctx);
        let mut fields = id_fields(self.amf, self.ran, Criticality::ignore, output)?;
        if let Some(failed) = &self.failed {
            fields.push((
                132,
                Criticality::ignore,
                failed.encode(output).map_err(encode_error)?,
            ));
        }
        fields.push((
            15,
            Criticality::ignore,
            self.cause.encode(output).map_err(encode_error)?,
        ));
        if let Some(value) = diagnostics {
            fields.push((19, Criticality::ignore, value));
        }
        construct(MessageType::InitialContextSetupFailure, fields, ctx)
    }
}

impl SessionResourceRequest<'_> {
    /// Construct the mandatory session list; requires message depth seventeen.
    /// UE aggregate bitrate is optional here, unlike a context request with resources.
    pub fn construct(&self, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
        self.construct_with_resource_types(None, ctx)
    }

    /// Construct with exact local session/QFI classification, permitting absent
    /// Session AMBR only for all-GBR sessions. No resource effects occur.
    pub fn construct_classified(
        &self,
        resource_types: &SessionResourceTypes,
        ctx: DecodeContext,
    ) -> Result<Pdu, DecodeError> {
        self.construct_with_resource_types(Some(resource_types), ctx)
    }

    fn construct_with_resource_types(
        &self,
        resource_types: Option<&SessionResourceTypes>,
        ctx: DecodeContext,
    ) -> Result<Pdu, DecodeError> {
        crate::enforce_depth(17, ctx)?;
        let output = output_context(ctx);
        let mut fields = id_fields(self.amf, self.ran, Criticality::reject, output)?;
        if let Some(nas) = &self.nas {
            fields.push((
                38,
                Criticality::reject,
                nas.encode(output).map_err(encode_error)?,
            ));
        }
        fields.push((
            74,
            Criticality::reject,
            encode_requests(&self.sessions, resource_types, output)?,
        ));
        if let Some(rate) = &self.aggregate_bit_rate {
            fields.push((
                110,
                Criticality::ignore,
                rate.encode(output).map_err(encode_error)?,
            ));
        }
        construct_with_resource_types(
            MessageType::PduSessionResourceSetupRequest,
            fields,
            resource_types,
            ctx,
        )
    }
}

impl SessionResourceResponse {
    /// Construct a nonempty overall result. A failed-only list is valid; no
    /// separate unsuccessful PDU Session Resource Setup outcome is defined.
    pub fn construct(&self, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
        if self.sessions.is_empty() {
            return Err(invalid("missing session setup result"));
        }
        result_depth(&self.sessions, ctx)?;
        let diagnostics = super::reset_fields::encode_response_diagnostics(&self.diagnostics, ctx)?;
        let output = output_context(ctx);
        let mut fields = id_fields(self.amf, self.ran, Criticality::ignore, output)?;
        result_fields(&mut fields, &self.sessions, 75, 58, output)?;
        if let Some(value) = diagnostics {
            fields.push((19, Criticality::ignore, value));
        }
        if let Some(location) = &self.location {
            fields.push((
                121,
                Criticality::ignore,
                location.encode(output).map_err(encode_error)?,
            ));
        }
        construct(MessageType::PduSessionResourceSetupResponse, fields, ctx)
    }
}

type Fields = Vec<(u16, Criticality, EncodedValue)>;
fn id_fields(
    amf: AmfUeId,
    ran: RanUeId,
    criticality: Criticality,
    ctx: EncodeContext,
) -> Result<Fields, DecodeError> {
    Ok(vec![
        (10, criticality, amf.encode(ctx).map_err(encode_error)?),
        (85, criticality, ran.encode(ctx).map_err(encode_error)?),
    ])
}
fn result_fields(
    fields: &mut Fields,
    results: &SessionResults,
    yes: u16,
    no: u16,
    ctx: EncodeContext,
) -> Result<(), DecodeError> {
    if let Some(successful) = results.successful() {
        fields.push((
            yes,
            Criticality::ignore,
            successful.encode(ctx).map_err(encode_error)?,
        ));
    }
    if let Some(failed) = results.failed() {
        fields.push((
            no,
            Criticality::ignore,
            failed.encode(ctx).map_err(encode_error)?,
        ));
    }
    Ok(())
}
fn result_depth(results: &SessionResults, ctx: DecodeContext) -> Result<(), DecodeError> {
    crate::enforce_depth(
        if results.successful().is_some() {
            13
        } else if results.failed().is_some() {
            10
        } else {
            5
        },
        ctx,
    )
}
fn output_context(ctx: DecodeContext) -> EncodeContext {
    EncodeContext {
        max_message_len: ctx.max_message_len,
        ..EncodeContext::default()
    }
}
fn encode_error(_: EncodeError) -> DecodeError {
    invalid("resource setup encoding or capacity")
}
fn construct(kind: MessageType, fields: Fields, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
    construct_with_resource_types(kind, fields, None, ctx)
}
fn encode_requests(
    sessions: &SessionSetupRequests<'_>,
    resource_types: Option<&SessionResourceTypes>,
    ctx: EncodeContext,
) -> Result<EncodedValue, DecodeError> {
    match resource_types {
        Some(types) => sessions.encode_classified(types, ctx),
        None => sessions.encode(ctx),
    }
    .map_err(encode_error)
}
fn construct_with_resource_types(
    kind: MessageType,
    fields: Fields,
    resource_types: Option<&SessionResourceTypes>,
    ctx: DecodeContext,
) -> Result<Pdu, DecodeError> {
    let ies: Vec<_> = fields
        .iter()
        .map(|(id, crit, value)| ProtocolIe::new(*id, *crit, value.as_bytes()))
        .collect();
    let pdu = Pdu::from_protocol_ies(kind, &ies, ctx)?;
    ResourceSetupMessage::from_pdu_with_resource_types(&pdu, resource_types, ctx)?;
    Ok(pdu)
}

impl<'a> ResourceSetupMessage<'a> {
    /// Admit the generic decoder's selected IE view, revalidating mutable
    /// wrapper metadata and field criticality. Use the same context for generic
    /// decoding and admission; already filtered unknowns/duplicates stay filtered.
    pub fn from_pdu(
        pdu: &'a Pdu,
        ctx: DecodeContext,
    ) -> Result<AdmittedResourceSetup<'a>, DecodeError> {
        Self::from_pdu_with_resource_types(pdu, None, ctx)
    }

    /// Admit a Setup request with exact caller-established session/QFI resource
    /// types. Missing Session AMBR requires an all-GBR classification. Other
    /// presence, key custody, ignored fields and DecodeContext policies apply
    /// unchanged. A classification supplied for a non-request is rejected.
    pub fn from_pdu_classified(
        pdu: &'a Pdu,
        resource_types: &SessionResourceTypes,
        ctx: DecodeContext,
    ) -> Result<AdmittedResourceSetup<'a>, DecodeError> {
        Self::from_pdu_with_resource_types(pdu, Some(resource_types), ctx)
    }

    fn from_pdu_with_resource_types(
        pdu: &'a Pdu,
        resource_types: Option<&SessionResourceTypes>,
        ctx: DecodeContext,
    ) -> Result<AdmittedResourceSetup<'a>, DecodeError> {
        crate::enforce_depth(5, ctx)?;
        pdu.wire_len(output_context(ctx))
            .map_err(|_| invalid("resource setup container policy"))?;
        macro_rules! fields {
            ($kind:ident, $value:ident) => {
                admit(
                    MessageType::$kind,
                    $value
                        .protocol_ies
                        .0
                        .iter()
                        .map(|ie| (ie.id, ie.criticality as u8, ie.value.as_bytes())),
                    resource_types,
                    ctx,
                )
            };
        }
        match &pdu.kind {
            PduKind::Initiating {
                message: Message::InitialContextSetupRequest(value),
                ..
            } => fields!(InitialContextSetupRequest, value),
            PduKind::Successful {
                message: Message::InitialContextSetupResponse(value),
                ..
            } => fields!(InitialContextSetupResponse, value),
            PduKind::Unsuccessful {
                message: Message::InitialContextSetupFailure(value),
                ..
            } => fields!(InitialContextSetupFailure, value),
            PduKind::Initiating {
                message: Message::PduSessionResourceSetupRequest(value),
                ..
            } => fields!(PduSessionResourceSetupRequest, value),
            PduKind::Successful {
                message: Message::PduSessionResourceSetupResponse(value),
                ..
            } => fields!(PduSessionResourceSetupResponse, value),
            _ => Err(invalid("resource setup message outcome")),
        }
    }
}

// TS 29.413 5.3. Trace Activation (108) and UE AMBR (110) apply to N3IWF
// through the non-trusted-access exceptions; neither is receiver-ignored.
const CONTEXT_IGNORED: &[u16] = &[
    18, 36, 117, 31, 24, 91, 118, 146, 33, 165, 177, 199, 205, 206, 209, 216, 215, 218, 217, 219,
    222, 234, 254, 264, 119, 326, 328, 334, 335, 345, 346, 367, 373, 374, 375, 376, 377, 378, 400,
    347,
];

fn admit<'a>(
    kind: MessageType,
    fields: impl Iterator<Item = (u16, u8, &'a [u8])>,
    resource_types: Option<&SessionResourceTypes>,
    ctx: DecodeContext,
) -> Result<AdmittedResourceSetup<'a>, DecodeError> {
    if resource_types.is_some()
        && !matches!(
            kind,
            MessageType::InitialContextSetupRequest | MessageType::PduSessionResourceSetupRequest
        )
    {
        return Err(invalid("resource classification for non-request"));
    }
    let (profile, supported, ignored): (policy::IeProfile, &[u16], &[u16]) = match kind {
        MessageType::InitialContextSetupRequest => (
            policy::INITIAL_CONTEXT_SETUP_REQUEST,
            &[10, 85, 48, 110, 28, 71, 0, 94, 108, 34, 38, 414, 443],
            CONTEXT_IGNORED,
        ),
        MessageType::InitialContextSetupResponse => (
            policy::INITIAL_CONTEXT_SETUP_RESPONSE,
            &[10, 85, 72, 55, 19],
            &[],
        ),
        MessageType::InitialContextSetupFailure => (
            policy::INITIAL_CONTEXT_SETUP_FAILURE,
            &[10, 85, 132, 15, 19],
            &[],
        ),
        MessageType::PduSessionResourceSetupRequest => (
            policy::PDU_SESSION_RESOURCE_SETUP_REQUEST,
            &[10, 85, 38, 74, 110],
            &[83, 335],
        ),
        MessageType::PduSessionResourceSetupResponse => (
            policy::PDU_SESSION_RESOURCE_SETUP_RESPONSE,
            &[10, 85, 75, 58, 121, 19],
            &[],
        ),
        _ => return Err(invalid("resource setup message outcome")),
    };
    let leaf = DecodeContext {
        max_depth: ctx.max_depth.saturating_sub(4),
        ..ctx
    };
    let (mut amf, mut ran) = (None, None);
    let (mut guami, mut allowed, mut key, mut capabilities_present) = (None, None, None, false);
    let (mut aggregate_bit_rate, mut requests, mut nas) = (None, None, None);
    let (mut successful, mut failed, mut cause, mut location) = (None, None, None, None);
    let mut diagnostics = None;
    let (
        mut old_amf,
        mut trace,
        mut masked_imeisv,
        mut partially_allowed_nssai,
        mut extended_old_amf,
    ) = (None, None, None, None, None);
    let mut ignored_ie_count = 0;
    let mut notify_ie_ids = Vec::new();
    let mut transfer_diagnostics = Vec::new();
    for (index, (id, criticality, value)) in fields.enumerate() {
        if index >= ctx.max_ies {
            return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, 0));
        }
        if ignored.contains(&id) {
            capabilities_present |= id == 119;
            ignored_ie_count += 1;
            continue;
        }
        if !supported.contains(&id) {
            if profile.recognizes(id) {
                return Err(invalid("applicable resource setup ie not admitted"));
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
            48 => old_amf = Some(AmfName::decode(value, leaf)?),
            108 => trace = Some(TraceActivation::decode(value, leaf)?),
            34 => masked_imeisv = Some(MaskedImeisv::decode(value, leaf)?),
            414 => partially_allowed_nssai = Some(PartiallyAllowedNssai::decode(value, leaf)?),
            443 => extended_old_amf = Some(ExtendedAmfName::decode(value, leaf)?),
            110 => aggregate_bit_rate = Some(UeAggregateBitRate::decode(value, leaf)?),
            28 => guami = Some(Guami::decode(value, leaf)?),
            0 => allowed = Some(AllowedNssai::decode(value, leaf)?),
            94 => key = Some(SecurityKey::decode(value, leaf)?),
            38 => nas = Some(NasPdu::decode(value, leaf)?),
            71 | 74 => {
                let admitted = match resource_types {
                    Some(types) => SessionSetupRequests::decode_classified(value, types, leaf)?,
                    None => SessionSetupRequests::decode(value, leaf)?,
                };
                requests = Some(admitted.requests);
                transfer_diagnostics = admitted.diagnostics;
            }
            72 | 75 => successful = Some(SuccessfulSessions::decode(value, leaf)?),
            55 | 58 | 132 => failed = Some(FailedSessions::decode(value, leaf)?),
            15 => cause = Some(Cause::decode(value, leaf)?),
            121 => location = Some(N3iwfLocation::decode(value, leaf)?),
            19 => {
                diagnostics = Some(super::reset_fields::decode_response_diagnostics(
                    value, leaf,
                )?)
            }
            _ => return Err(invalid("resource setup field dispatch")),
        }
    }
    if resource_types.is_some() && requests.is_none() {
        return Err(invalid("resource classification without sessions"));
    }
    let amf = amf.ok_or_else(|| invalid("missing amf ue id"))?;
    let ran = ran.ok_or_else(|| invalid("missing ran ue id"))?;
    let message = match kind {
        MessageType::InitialContextSetupRequest => {
            if !capabilities_present {
                return Err(invalid("missing ue security capabilities"));
            }
            if requests.is_some() && aggregate_bit_rate.is_none() {
                return Err(invalid("missing conditional ue aggregate bitrate"));
            }
            let allowed = allowed.ok_or_else(|| invalid("missing allowed nssai"))?;
            validate_slice_lists(Some(&allowed), partially_allowed_nssai.as_ref())?;
            ResourceSetupMessage::InitialRequest(InitialContextRequest {
                amf,
                ran,
                guami: guami.ok_or_else(|| invalid("missing guami"))?,
                allowed,
                key: key.ok_or_else(|| invalid("missing security key"))?,
                aggregate_bit_rate,
                sessions: requests,
                nas,
                old_amf,
                trace,
                masked_imeisv,
                partially_allowed_nssai,
                extended_old_amf,
            })
        }
        MessageType::InitialContextSetupResponse => {
            ResourceSetupMessage::InitialResponse(InitialContextResponse {
                amf,
                ran,
                sessions: SessionResults::new(successful, failed)?,
                diagnostics,
            })
        }
        MessageType::InitialContextSetupFailure => {
            ResourceSetupMessage::InitialFailure(InitialContextFailure {
                amf,
                ran,
                cause: cause.ok_or_else(|| invalid("missing context failure cause"))?,
                failed,
                diagnostics,
            })
        }
        MessageType::PduSessionResourceSetupRequest => {
            ResourceSetupMessage::SessionRequest(SessionResourceRequest {
                amf,
                ran,
                sessions: requests.ok_or_else(|| invalid("missing session setup list"))?,
                aggregate_bit_rate,
                nas,
            })
        }
        MessageType::PduSessionResourceSetupResponse => {
            let sessions = SessionResults::new(successful, failed)?;
            if sessions.is_empty() {
                return Err(invalid("missing session setup result"));
            }
            ResourceSetupMessage::SessionResponse(SessionResourceResponse {
                amf,
                ran,
                sessions,
                location,
                diagnostics,
            })
        }
        _ => return Err(invalid("resource setup message outcome")),
    };
    Ok(AdmittedResourceSetup {
        message,
        ignored_ie_count,
        notify_ie_ids,
        transfer_diagnostics,
    })
}
