//! Qualified Modify session lists. Identifiers carry no session ownership,
//! NAS forwarding eligibility or request correspondence. The enclosing
//! procedure must correlate every requested session with a result.

use super::modify_request::ModifyRequestTransfer;
use super::modify_results::{ModifyFailureTransfer, ModifyResponseTransfer};
use super::session_lists::{
    encode_list, unique_id, validate_ids, SessionId, SessionTransferDiagnostics,
};
use super::setup_fields::{Reader, Writer};
use super::*;
use opc_types::Snssai;

/// One session modification with optional opaque NAS and S-NSSAI.
pub struct SessionModification<'a> {
    /// Peer session identifier; ownership is caller-owned.
    pub id: SessionId,
    /// Absent and empty NAS remain distinct. Forward only after qualifying success.
    pub nas: Option<NasPdu<'a>>,
    /// Optional S-NSSAI item extension, without authorization or a default.
    pub slice: Option<Snssai>,
    /// Qualified optional root modifications.
    pub transfer: ModifyRequestTransfer,
}
redacted!(SessionModification<'_>);
/// Nonempty 1–256 unique session modification requests.
pub struct SessionModifications<'a>(Vec<SessionModification<'a>>);
redacted!(SessionModifications<'_>);
/// Admitted requests and value-free contained-transfer diagnostics.
#[derive(Debug)]
pub struct AdmittedModifications<'a> {
    /// Fully admitted list; decoding has no resource effects.
    pub requests: SessionModifications<'a>,
    /// Only sessions with retained ignore/notify diagnostics, in wire order.
    pub diagnostics: Vec<SessionTransferDiagnostics>,
}
impl<'a> SessionModifications<'a> {
    /// Require root count and unique session identifiers.
    pub fn new(values: Vec<SessionModification<'a>>) -> Result<Self, DecodeError> {
        validate_ids(values.iter().map(|v| v.id), values.len())?;
        Ok(Self(values))
    }
    /// Explicit requests in received order.
    pub fn values(&self) -> &[SessionModification<'a>] {
        &self.0
    }
    /// Exact capacity preflight followed by qualified fragment framing. The
    /// generated request list mishandles fragmented NAS and transfer payloads.
    /// Canonical construction omits unknown contained-transfer fields.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let mut length = 1;
        capacity(length, ctx)?;
        let mut transfers = Vec::with_capacity(self.0.len());
        for v in &self.0 {
            let transfer = v.transfer.encode(ctx)?;
            add_size(
                &mut length,
                2 + constructed::open_type_len(transfer.as_bytes().len())?,
                ctx,
            )?;
            if let Some(nas) = &v.nas {
                add_size(
                    &mut length,
                    constructed::open_type_len(nas.as_bytes().len())?,
                    ctx,
                )?;
            }
            if let Some(slice) = &v.slice {
                add_size(
                    &mut length,
                    5 + constructed::open_type_len(if slice.sd().is_some() { 5 } else { 2 })?,
                    ctx,
                )?;
            }
            transfers.push(transfer);
        }
        let mut wire = Zeroizing::new(Vec::with_capacity(length));
        wire.push((self.0.len() - 1) as u8);
        for (v, transfer) in self.0.iter().zip(&transfers) {
            wire.push((u8::from(v.nas.is_some()) << 6) | (u8::from(v.slice.is_some()) << 5));
            wire.push(v.id.value());
            if let Some(nas) = &v.nas {
                constructed::write_open_type(&mut wire, nas.as_bytes());
            }
            constructed::write_open_type(&mut wire, transfer.as_bytes());
            if let Some(slice) = &v.slice {
                wire.extend_from_slice(&[0, 0, 0, 148, 0]); // one extension, S-NSSAI/reject
                let mut out = Writer::new(if slice.sd().is_some() { 5 } else { 2 });
                out.snssai(slice)?;
                constructed::write_open_type(&mut wire, out.finish()?.as_bytes());
            }
        }
        if wire.len() != length {
            return Err(encode_invalid());
        }
        Ok(EncodedValue(wire))
    }
    /// Preflight every item and complete physical fragments before allocating
    /// the list or coalescing NAS/transfers. Ordinary NAS borrows input. Depth
    /// is three enclosing layers plus the actual transfer depth (7–13 total).
    /// Outer count and each transfer independently use `max_ies`. Exactly one
    /// S-NSSAI/reject extension is supported; other item extensions reject.
    pub fn decode(
        input: &'a [u8],
        ctx: DecodeContext,
    ) -> Result<AdmittedModifications<'a>, DecodeError> {
        let count = scan_requests(input, ctx, |_, _, _, _| Ok(()))?;
        let mut values = Vec::with_capacity(count);
        let mut diagnostics = Vec::new();
        let nested = nested(ctx);
        scan_requests(input, ctx, |id, nas, slice, transfer| {
            let (_, wire) = aper::open_type(transfer)?;
            let admitted = ModifyRequestTransfer::decode(&wire, nested)?;
            if admitted.ignored_ie_count != 0 || !admitted.notify_ie_ids.is_empty() {
                diagnostics.push(SessionTransferDiagnostics {
                    session: id,
                    ignored_ie_count: admitted.ignored_ie_count,
                    notify_ie_ids: admitted.notify_ie_ids,
                });
            }
            let nas = nas
                .map(|frame| aper::open_type(frame).map(|(_, v)| NasPdu(v)))
                .transpose()?;
            values.push(SessionModification {
                id,
                nas,
                slice,
                transfer: admitted.transfer,
            });
            Ok(())
        })?;
        Ok(AdmittedModifications {
            requests: Self(values),
            diagnostics,
        })
    }
}
fn scan_requests<'a>(
    input: &'a [u8],
    ctx: DecodeContext,
    mut emit: impl FnMut(
        SessionId,
        Option<&'a [u8]>,
        Option<Snssai>,
        &'a [u8],
    ) -> Result<(), DecodeError>,
) -> Result<usize, DecodeError> {
    bound(input, ctx, 7)?;
    let mut reader = Reader::new(input, ctx);
    let count = reader.count(8, 256, 24)?;
    let mut seen = [0; 4];
    for _ in 0..count {
        let flags = reader.bits(3)?;
        if flags & 4 != 0 {
            return Err(unsupported());
        }
        reader.align()?;
        let id = SessionId::new(reader.bits(8)? as u8);
        unique_id(&mut seen, id)?;
        let nas = if flags & 2 != 0 {
            Some(reader.framed_octets(ctx.max_message_len)?)
        } else {
            None
        };
        let transfer = reader.framed_octets(ctx.max_message_len)?;
        let slice = if flags & 1 != 0 {
            reader.align()?;
            if reader.bits(16)? != 0 || reader.bits(16)? != 148 || reader.bits(2)? != 0 {
                return Err(unsupported());
            }
            reader.align()?;
            let wire = reader.open_octets(5)?;
            let mut slice_reader = Reader::new(&wire, ctx);
            let slice = slice_reader.snssai()?;
            slice_reader.finish()?;
            Some(slice)
        } else {
            None
        };
        emit(id, nas, slice, transfer)?;
    }
    reader.finish()?;
    Ok(count)
}
/// A peer-reported successful session modification, including partial flow failures.
#[derive(Clone, PartialEq, Eq)]
pub struct ModifiedSession {
    /// Reported session identifier, without a correspondence claim.
    pub id: SessionId,
    /// Qualified optional tunnel and QFI results.
    pub transfer: ModifyResponseTransfer,
}
redacted!(ModifiedSession);
/// A peer-reported failed session modification.
#[derive(Clone, PartialEq, Eq)]
pub struct FailedModification {
    /// Reported session identifier, without a correspondence claim.
    pub id: SessionId,
    /// Qualified root Cause and optional response diagnostics.
    pub transfer: ModifyFailureTransfer,
}
redacted!(FailedModification);
macro_rules! result_list {
    ($list:ident,$item:ident,$asn_list:ident,$asn_item:ident,$field:ident,$transfer:ident,$depth:literal,$doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, PartialEq, Eq)]
        pub struct $list(Vec<$item>);
        redacted!($list);
        impl $list {
            /// Require 1–256 entries with unique session IDs.
            pub fn new(values: Vec<$item>) -> Result<Self, DecodeError> {
                validate_ids(values.iter().map(|v| v.id), values.len())?;
                Ok(Self(values))
            }
            /// Explicit received reports in wire order.
            pub fn values(&self) -> &[$item] {
                &self.0
            }
            /// Preflight exact size before the qualified generated list encoder.
            pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
                let mut length = 1;
                capacity(length, ctx)?;
                let mut transfers = Vec::with_capacity(self.0.len());
                for v in &self.0 {
                    let t = v.transfer.encode(ctx)?;
                    add_size(
                        &mut length,
                        2 + constructed::open_type_len(t.as_bytes().len())?,
                        ctx,
                    )?;
                    transfers.push(t);
                }
                let values = self
                    .0
                    .iter()
                    .zip(&transfers)
                    .map(|(v, t)| {
                        asn::$asn_item::new(
                            asn::PDUSessionID(v.id.value()),
                            t.as_bytes().to_vec().into(),
                            None,
                        )
                    })
                    .collect();
                encode_list(&asn::$asn_list(values), length)
            }
            /// Preflight all physical framing, counts and IDs before generated
            /// list materialization. Each contained transfer uses an independent
            /// count budget and three fewer depth layers; extensions reject.
            pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
                scan_results(input, ctx, $depth)?;
                let list: asn::$asn_list = decode_leaf(input)?;
                let values = list
                    .0
                    .iter()
                    .map(|v| {
                        Ok($item {
                            id: SessionId::new(v.p_dusession_id.0),
                            transfer: $transfer::decode(v.$field.as_ref(), nested(ctx))?,
                        })
                    })
                    .collect::<Result<Vec<_>, DecodeError>>()?;
                Ok(Self(values))
            }
        }
    };
}
result_list!(
    ModifiedSessions,
    ModifiedSession,
    PDUSessionResourceModifyListModRes,
    PDUSessionResourceModifyItemModRes,
    p_dusession_resource_modify_response_transfer,
    ModifyResponseTransfer,
    4,
    "Nonempty successful reports; depth four for empty roots, seven/eight with fields."
);
result_list!(
    FailedModifications,
    FailedModification,
    PDUSessionResourceFailedToModifyListModRes,
    PDUSessionResourceFailedToModifyItemModRes,
    p_dusession_resource_modify_unsuccessful_transfer,
    ModifyFailureTransfer,
    6,
    "Nonempty failed reports; depth six, or eight with diagnostic items."
);
fn scan_results(input: &[u8], ctx: DecodeContext, depth: usize) -> Result<(), DecodeError> {
    bound(input, ctx, depth)?;
    let mut reader = Reader::new(input, ctx);
    let count = reader.count(8, 256, 24)?;
    let mut seen = [0; 4];
    for _ in 0..count {
        reader.flags(2)?;
        reader.align()?;
        unique_id(&mut seen, SessionId::new(reader.bits(8)? as u8))?;
        reader.framed_octets(ctx.max_message_len)?;
    }
    reader.finish()
}
fn nested(ctx: DecodeContext) -> DecodeContext {
    DecodeContext {
        max_depth: ctx.max_depth.saturating_sub(3),
        ..ctx
    }
}
fn add_size(length: &mut usize, value: usize, ctx: EncodeContext) -> Result<(), EncodeError> {
    *length = length.checked_add(value).ok_or_else(encode_invalid)?;
    capacity(*length, ctx)
}
fn encode_invalid() -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural {
        reason: "modify session list encoding",
    })
}
