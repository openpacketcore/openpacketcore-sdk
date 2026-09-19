//! Session-list admission for the qualified setup-transfer subsets.
//! Context/session procedures select the enclosing IE and correlate these
//! identifiers with the original request. No session or resource is created.

use super::qos_fields::QosResourceTypes;
use super::resource_request::SetupRequestTransfer;
use super::resource_results::{SetupFailureTransfer, SetupResponseTransfer};
use super::setup_fields::{Reader, Writer};
use super::*;
use opc_types::Snssai;

/// NGAP's eight-bit PDU session identifier. Reserved-value and ownership
/// policy belong to the caller; this is distinct from a QFI or UE identifier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionId(u8);
redacted!(SessionId);
impl SessionId {
    /// Retain any ASN.1 root identifier (0..=255).
    pub const fn new(value: u8) -> Self {
        Self(value)
    }
    /// Explicit wire identifier for request correlation.
    pub const fn value(self) -> u8 {
        self.0
    }
}

/// Caller-established resource types for each session's exact requested QFI set.
/// This local input grants no resource, subscriber or procedure authority.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionResourceTypes(Vec<(SessionId, QosResourceTypes)>);
redacted!(SessionResourceTypes);
impl SessionResourceTypes {
    /// Require 1–256 distinct session identifiers. The classified boundary
    /// checks that this roster exactly matches the admitted request list.
    pub fn new(values: Vec<(SessionId, QosResourceTypes)>) -> Result<Self, DecodeError> {
        validate_ids(values.iter().map(|(id, _)| *id), values.len())?;
        Ok(Self(values))
    }
    /// Explicit local classification for a session, if supplied.
    pub fn get(&self, session: SessionId) -> Option<&QosResourceTypes> {
        self.0
            .iter()
            .find(|(id, _)| *id == session)
            .map(|(_, types)| types)
    }
    fn validate(&self, sessions: &SessionSetupRequests<'_>) -> Result<(), DecodeError> {
        if self.0.len() != sessions.0.len() {
            return Err(invalid("session resource classification coverage"));
        }
        for session in &sessions.0 {
            self.get(session.id)
                .ok_or_else(|| invalid("missing session resource classification"))?
                .requires_session_ambr(session.transfer.flows.values())?;
        }
        Ok(())
    }
}

/// One setup request, retaining optional opaque NAS and its requested slice.
pub struct SessionSetupRequest<'a> {
    /// Session being requested, without a local ownership claim.
    pub id: SessionId,
    /// Requested slice, without admission/authorization.
    pub slice: Snssai,
    /// Optional opaque per-session NAS. Empty and absent remain distinct.
    pub nas: Option<NasPdu<'a>>,
    /// Qualified root request transfer; missing Session AMBR requires the
    /// classified list API and an all-GBR flow list.
    pub transfer: SetupRequestTransfer,
}
redacted!(SessionSetupRequest<'_>);

/// Nonempty 1–256 session requests with unique session identifiers. The root
/// layouts of SetupListCxtReq and SetupListSUReq are independently identical.
pub struct SessionSetupRequests<'a>(Vec<SessionSetupRequest<'a>>);
redacted!(SessionSetupRequests<'_>);

/// Value-free IE-policy evidence tied to an explicitly accessed session ID.
#[derive(Debug)]
pub struct SessionTransferDiagnostics {
    /// Session whose contained transfer produced the evidence.
    pub session: SessionId,
    /// Receiver-ignored and unknown-ignore entries retained by shared selection.
    pub ignored_ie_count: usize,
    /// Unknown-notify IE identifiers, never their values.
    pub notify_ie_ids: Vec<u16>,
}
/// Fully admitted requests and contained-transfer diagnostics. Malformed
/// entries reject the entire list before a caller can act on its results.
#[derive(Debug)]
pub struct AdmittedSessionRequests<'a> {
    /// Admitted session requests; no resource allocation or authorization occurred.
    pub requests: SessionSetupRequests<'a>,
    /// Sessions with nonempty diagnostics, in input order.
    pub diagnostics: Vec<SessionTransferDiagnostics>,
}

impl<'a> SessionSetupRequests<'a> {
    /// Require the root count and unique session IDs.
    pub fn new(values: Vec<SessionSetupRequest<'a>>) -> Result<Self, DecodeError> {
        validate_ids(values.iter().map(|v| v.id), values.len())?;
        Ok(Self(values))
    }
    /// Explicit access to the requested sessions in input order.
    pub fn values(&self) -> &[SessionSetupRequest<'a>] {
        &self.0
    }
    /// Construct canonical bytes using qualified root and fragment helpers.
    /// Preflight total NAS/field size before allocating the complete list.
    /// Unknown transfer fields are omitted; preserve the original input
    /// separately when lossless retransmission is required.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        self.encode_with_resource_types(None, ctx)
    }

    /// Encode using exact caller-established session/QFI classification.
    pub fn encode_classified(
        &self,
        resource_types: &SessionResourceTypes,
        ctx: EncodeContext,
    ) -> Result<EncodedValue, EncodeError> {
        self.encode_with_resource_types(Some(resource_types), ctx)
    }

    fn encode_with_resource_types(
        &self,
        resource_types: Option<&SessionResourceTypes>,
        ctx: EncodeContext,
    ) -> Result<EncodedValue, EncodeError> {
        if let Some(types) = resource_types {
            types.validate(self).map_err(|_| {
                EncodeError::new(EncodeErrorCode::Structural {
                    reason: "session resource classification coverage",
                })
            })?;
        }
        let mut length = 1;
        capacity(length, ctx)?;
        let mut transfers = Vec::with_capacity(self.0.len());
        for value in &self.0 {
            let transfer = match resource_types.and_then(|types| types.get(value.id)) {
                Some(types) => value.transfer.encode_classified(types, ctx)?,
                None => value.transfer.encode(ctx)?,
            };
            add_size(
                &mut length,
                2 + if value.slice.sd().is_some() { 5 } else { 2 },
                ctx,
            )?;
            if let Some(nas) = &value.nas {
                add_size(
                    &mut length,
                    constructed::open_type_len(nas.as_bytes().len())?,
                    ctx,
                )?;
            }
            add_size(
                &mut length,
                constructed::open_type_len(transfer.as_bytes().len())?,
                ctx,
            )?;
            transfers.push(transfer);
        }
        // Generated encoding repeats the wrong NAS prefix in a fragmented
        // remainder. Use the already qualified fragment writer and S-NSSAI
        // root helper; list/item extensions remain unsupported.
        let mut wire = Zeroizing::new(Vec::with_capacity(length));
        wire.push((self.0.len() - 1) as u8);
        for (value, transfer) in self.0.iter().zip(&transfers) {
            wire.push(if value.nas.is_some() { 0x40 } else { 0 });
            wire.push(value.id.value());
            if let Some(nas) = &value.nas {
                constructed::write_open_type(&mut wire, nas.as_bytes());
            }
            let mut slice = Writer::new(if value.slice.sd().is_some() { 5 } else { 2 });
            slice.snssai(&value.slice)?;
            wire.extend_from_slice(slice.finish()?.as_bytes());
            constructed::write_open_type(&mut wire, transfer.as_bytes());
        }
        if wire.len() != length {
            return Err(EncodeError::new(EncodeErrorCode::Structural {
                reason: "session request framing",
            }));
        }
        Ok(EncodedValue(wire))
    }
    /// Decode with depth thirteen. Outer session count and each contained
    /// transfer use field-local `max_ies` limits; physical bytes bound both.
    /// Ordinary NAS borrows input; fragmented NAS is coalesced only after
    /// physical preflight. All list/item/slice extensions are unsupported.
    pub fn decode(
        input: &'a [u8],
        ctx: DecodeContext,
    ) -> Result<AdmittedSessionRequests<'a>, DecodeError> {
        Self::decode_with_resource_types(input, None, ctx)
    }

    /// Admit requests with exact caller-established resource classifications.
    /// Session AMBR can be absent only in an all-GBR session. Shared policies,
    /// physical bounds, session uniqueness and NAS custody remain unchanged.
    pub fn decode_classified(
        input: &'a [u8],
        resource_types: &SessionResourceTypes,
        ctx: DecodeContext,
    ) -> Result<AdmittedSessionRequests<'a>, DecodeError> {
        Self::decode_with_resource_types(input, Some(resource_types), ctx)
    }

    fn decode_with_resource_types(
        input: &'a [u8],
        resource_types: Option<&SessionResourceTypes>,
        ctx: DecodeContext,
    ) -> Result<AdmittedSessionRequests<'a>, DecodeError> {
        bound(input, ctx, 13)?;
        let mut reader = Reader::new(input, ctx);
        let count = reader.count(8, 256, 40)?;
        let mut values = Vec::with_capacity(count);
        let mut seen = [0; 4];
        let mut diagnostics = Vec::new();
        let nested = DecodeContext {
            max_depth: ctx.max_depth.saturating_sub(3),
            ..ctx
        };
        for _ in 0..count {
            let flags = reader.bits(3)?;
            if flags & 5 != 0 {
                return Err(unsupported());
            }
            reader.align()?;
            let id = SessionId::new(reader.bits(8)? as u8);
            unique_id(&mut seen, id)?;
            let nas = if flags & 2 != 0 {
                Some(NasPdu(reader.open_octets(ctx.max_message_len)?))
            } else {
                None
            };
            let slice = reader.snssai()?;
            let wire = reader.open_octets(ctx.max_message_len)?;
            let admitted = match resource_types {
                Some(types) => SetupRequestTransfer::decode_classified(
                    &wire,
                    types
                        .get(id)
                        .ok_or_else(|| invalid("missing session resource classification"))?,
                    nested,
                )?,
                None => SetupRequestTransfer::decode(&wire, nested)?,
            };
            if admitted.ignored_ie_count != 0 || !admitted.notify_ie_ids.is_empty() {
                diagnostics.push(SessionTransferDiagnostics {
                    session: id,
                    ignored_ie_count: admitted.ignored_ie_count,
                    notify_ie_ids: admitted.notify_ie_ids,
                });
            }
            values.push(SessionSetupRequest {
                id,
                slice,
                nas,
                transfer: admitted.transfer,
            });
        }
        reader.finish()?;
        let requests = Self(values);
        if let Some(types) = resource_types {
            types.validate(&requests)?;
        }
        Ok(AdmittedSessionRequests {
            requests,
            diagnostics,
        })
    }
}

/// One session's successful setup, which may still contain failed QoS flows.
#[derive(Clone, PartialEq, Eq)]
pub struct SuccessfulSession {
    /// Session whose resources the peer reports.
    pub id: SessionId,
    /// Downlink endpoint and partial QoS result.
    pub transfer: SetupResponseTransfer,
}
redacted!(SuccessfulSession);
/// One entirely failed session's setup result.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FailedSession {
    /// Session whose setup failed.
    pub id: SessionId,
    /// Peer-reported root Cause.
    pub transfer: SetupFailureTransfer,
}
redacted!(FailedSession);

macro_rules! result_list {
    ($list:ident, $item:ident, $asn_list:ident, $asn_item:ident, $field:ident, $transfer:ident, $depth:literal, $max:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq)]
        pub struct $list(Vec<$item>);
        redacted!($list);
        impl $list {
            /// Require 1–256 entries and unique session IDs.
            pub fn new(values: Vec<$item>) -> Result<Self, DecodeError> {
                validate_ids(values.iter().map(|v| v.id), values.len())?;
                Ok(Self(values))
            }
            /// Explicit results in received order.
            pub fn values(&self) -> &[$item] {
                &self.0
            }
            /// Preflight exact capacity, then use the qualified generated
            /// root encoder. No resource or procedure state is changed.
            pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
                let mut length = 1;
                capacity(length, ctx)?;
                let mut transfers = Vec::with_capacity(self.0.len());
                for value in &self.0 {
                    let transfer = value.transfer.encode(ctx)?;
                    add_size(
                        &mut length,
                        2 + constructed::open_type_len(transfer.as_bytes().len())?,
                        ctx,
                    )?;
                    transfers.push(transfer);
                }
                let values = self
                    .0
                    .iter()
                    .zip(&transfers)
                    .map(|(value, transfer)| {
                        asn::$asn_item::new(
                            asn::PDUSessionID(value.id.value()),
                            transfer.as_bytes().to_vec().into(),
                            None,
                        )
                    })
                    .collect();
                encode_list(&asn::$asn_list(values), length)
            }
            /// Preflight physical counts, duplicates, flags, padding and
            /// contained root lengths before generated list materialization.
            /// The depth and transfer limits are specific to this result kind.
            pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
                preflight_results(input, ctx, $depth, $max)?;
                let value: asn::$asn_list = decode_leaf(input)?;
                let nested = DecodeContext {
                    max_depth: ctx.max_depth.saturating_sub(3),
                    ..ctx
                };
                let values = value
                    .0
                    .iter()
                    .map(|value| {
                        Ok($item {
                            id: SessionId::new(value.p_dusession_id.0),
                            transfer: $transfer::decode(value.$field.as_ref(), nested)?,
                        })
                    })
                    .collect::<Result<Vec<_>, DecodeError>>()?;
                Ok(Self(values))
            }
        }
    };
}
result_list!(SuccessfulSessions, SuccessfulSession, PDUSessionResourceSetupListCxtRes, PDUSessionResourceSetupItemCxtRes, p_dusession_resource_setup_response_transfer, SetupResponseTransfer, 9, 176,
    "Nonempty successful-session list (depth nine). Context and PDU Setup response roots have independently identical layouts.");
result_list!(FailedSessions, FailedSession, PDUSessionResourceFailedToSetupListCxtFail, PDUSessionResourceFailedToSetupItemCxtFail, p_dusession_resource_setup_unsuccessful_transfer, SetupFailureTransfer, 6, 2,
    "Nonempty failed-session list (depth six). Context failure, context response and PDU Setup response roots have independently identical layouts.");

/// Paired optional session result lists with no session in both outcomes.
/// Empty results are representable for context responses without requested
/// resources; the enclosing PDU Setup procedure must require a nonempty result.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionResults {
    successful: Option<SuccessfulSessions>,
    failed: Option<FailedSessions>,
}
redacted!(SessionResults);
impl SessionResults {
    /// Reject overlapping successful/failed session IDs.
    pub fn new(
        successful: Option<SuccessfulSessions>,
        failed: Option<FailedSessions>,
    ) -> Result<Self, DecodeError> {
        let mut seen = [0; 4];
        if let Some(list) = &successful {
            for value in list.values() {
                unique_id(&mut seen, value.id)?;
            }
        }
        if let Some(list) = &failed {
            for value in list.values() {
                unique_id(&mut seen, value.id)?;
            }
        }
        Ok(Self { successful, failed })
    }
    /// Explicit successful list, if the enclosing message includes it.
    pub const fn successful(&self) -> Option<&SuccessfulSessions> {
        self.successful.as_ref()
    }
    /// Explicit failed list, if the enclosing message includes it.
    pub const fn failed(&self) -> Option<&FailedSessions> {
        self.failed.as_ref()
    }
    /// Whether neither result list is present. Procedure-specific presence
    /// rules remain the enclosing message's responsibility.
    pub const fn is_empty(&self) -> bool {
        self.successful.is_none() && self.failed.is_none()
    }
}

pub(super) fn validate_ids(
    ids: impl Iterator<Item = SessionId>,
    count: usize,
) -> Result<(), DecodeError> {
    if count == 0 || count > 256 {
        return Err(invalid("session list count"));
    }
    let mut seen = [0; 4];
    for id in ids {
        unique_id(&mut seen, id)?;
    }
    Ok(())
}
pub(super) fn unique_id(seen: &mut [u64; 4], id: SessionId) -> Result<(), DecodeError> {
    let slot = &mut seen[usize::from(id.value() / 64)];
    let bit = 1_u64 << (id.value() % 64);
    if *slot & bit != 0 {
        return Err(invalid("duplicate or conflicting session result"));
    }
    *slot |= bit;
    Ok(())
}
fn add_size(length: &mut usize, value: usize, ctx: EncodeContext) -> Result<(), EncodeError> {
    *length = length.checked_add(value).ok_or_else(|| {
        EncodeError::new(EncodeErrorCode::Structural {
            reason: "session list length",
        })
    })?;
    capacity(*length, ctx)
}
pub(super) fn encode_list<T: rasn::Encode>(
    value: &T,
    length: usize,
) -> Result<EncodedValue, EncodeError> {
    let wire = Zeroizing::new(rasn::aper::encode(value).map_err(|_| {
        EncodeError::new(EncodeErrorCode::Structural {
            reason: "session list encoding",
        })
    })?);
    if wire.len() != length {
        return Err(EncodeError::new(EncodeErrorCode::Structural {
            reason: "session list framing",
        }));
    }
    Ok(EncodedValue(wire))
}
pub(super) fn preflight_results(
    input: &[u8],
    ctx: DecodeContext,
    depth: usize,
    maximum: usize,
) -> Result<(), DecodeError> {
    bound(input, ctx, depth)?;
    let mut reader = Reader::new(input, ctx);
    let count = reader.count(8, 256, 24)?;
    let mut seen = [0; 4];
    for _ in 0..count {
        reader.flags(2)?;
        reader.align()?;
        unique_id(&mut seen, SessionId::new(reader.bits(8)? as u8))?;
        reader.open_octets(maximum)?;
    }
    reader.finish()
}
