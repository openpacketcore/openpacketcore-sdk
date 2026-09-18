//! Bounded Modify response and unsuccessful transfers (TS 38.413 8.2.3,
//! 9.3.4.4 / 9.3.4.17). These reports do not prove request correspondence or
//! resource changes. Session ownership, NAS forwarding and prescribed error
//! responses remain caller-owned. A failed session is carried in the enclosing
//! Modify Response; it is not an unsuccessful NGAP procedure outcome.

use super::modify_fields::{
    read_transport, write_transport, ModifiedQosFlows, QosFlowCause, QosFlowCauses,
};
use super::release::Cause;
use super::reset_fields::{
    encode_root, read_diagnostic_header, read_diagnostic_item, write_diagnostics,
    CriticalityDiagnostics, DiagnosticItem, DiagnosticItems, Sink,
};
use super::resource_fields::{DownlinkTransport, QosFlowId, UplinkTransport};
use super::resource_results::{cause_width, read_cause, unique, write_cause};
use super::session_lists::encode_list;
use super::setup_fields::Reader;
use super::*;

/// Optional root reports. Empty and failed-flow-only roots remain representable:
/// other requested AMBR, tunnel or release changes may have succeeded. Only the
/// caller can determine whether this result matches the original request.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ModifyResponseTransfer {
    /// New N3IWF-side endpoint for downlink delivery, when reported.
    pub downlink: Option<DownlinkTransport>,
    /// Core-side endpoint identifying the bearer, when reported.
    pub uplink: Option<UplinkTransport>,
    /// Unique QFIs reported successfully added or modified.
    pub accepted: Option<ModifiedQosFlows>,
    /// Unique failed QFIs with root Causes, disjoint from accepted QFIs.
    pub failed: Option<QosFlowCauses>,
}
redacted!(ModifyResponseTransfer);

impl ModifyResponseTransfer {
    fn validate(&self) -> Result<(), DecodeError> {
        let mut seen = 0;
        if let Some(values) = &self.accepted {
            for &qfi in values.values() {
                unique(&mut seen, qfi)?;
            }
        }
        if let Some(values) = &self.failed {
            for value in values.values() {
                unique(&mut seen, value.qfi)?;
            }
        }
        Ok(())
    }
    /// Encode qualified root fields after exact sizing and cross-list checks.
    /// Retain the qualified generated encoder without tunnels; tunnel-bearing
    /// layouts require explicit parent-offset framing. Extra tunnels and
    /// extension fields are outside this initial typed subset.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        self.validate().map_err(|_| {
            EncodeError::new(EncodeErrorCode::Structural {
                reason: "conflicting modify result qfi",
            })
        })?;
        if self.downlink.is_none() && self.uplink.is_none() {
            let mut bits = 7;
            if let Some(values) = &self.accepted {
                bits += 6 + 9 * values.values().len();
            }
            if let Some(values) = &self.failed {
                bits += 6 + values
                    .values()
                    .iter()
                    .map(|v| 13 + cause_width(v.cause.class()))
                    .sum::<usize>();
            }
            let length = bits.div_ceil(8);
            capacity(length, ctx)?;
            let accepted = self.accepted.as_ref().map(|values| {
                asn::QosFlowAddOrModifyResponseList(
                    values
                        .values()
                        .iter()
                        .map(|qfi| {
                            asn::QosFlowAddOrModifyResponseItem::new(
                                asn::QosFlowIdentifier(qfi.value().into()),
                                None,
                            )
                        })
                        .collect(),
                )
            });
            let failed = self
                .failed
                .as_ref()
                .map(|values| {
                    values
                        .values()
                        .iter()
                        .map(|v| {
                            Ok(asn::QosFlowWithCauseItem::new(
                                asn::QosFlowIdentifier(v.qfi.value().into()),
                                v.cause.generated()?,
                                None,
                            ))
                        })
                        .collect::<Result<Vec<_>, EncodeError>>()
                        .map(asn::QosFlowListWithCause)
                })
                .transpose()?;
            return encode_list(
                &asn::PDUSessionResourceModifyResponseTransfer::new(
                    None, None, accepted, None, failed, None,
                ),
                length,
            );
        }
        encode_root(ctx, |out| write_response(out, self))
    }
    /// Require depth one for an empty root, four for tunnels/accepted QFIs and
    /// five with failures. The combined accepted/failed count uses `max_ies`. Flags,
    /// count, uniqueness, alignment and exact framing preflight precedes either
    /// vector allocation; the generic allocation budget remains advisory.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (mut value, accepted_count, failed_count) = scan_response(input, ctx, |_| {}, |_| {})?;
        if accepted_count == 0
            && failed_count == 0
            && value.downlink.is_none()
            && value.uplink.is_none()
        {
            let _: asn::PDUSessionResourceModifyResponseTransfer = decode_leaf(input)?;
        }
        let mut accepted = Vec::with_capacity(accepted_count);
        let mut failed = Vec::with_capacity(failed_count);
        if accepted_count != 0 || failed_count != 0 {
            scan_response(input, ctx, |v| accepted.push(v), |v| failed.push(v))?;
        }
        if accepted_count != 0 {
            value.accepted = Some(ModifiedQosFlows::new(accepted)?);
        }
        if failed_count != 0 {
            value.failed = Some(QosFlowCauses::new(failed)?);
        }
        Ok(value)
    }
}

fn write_response(out: &mut dyn Sink, value: &ModifyResponseTransfer) -> Result<(), EncodeError> {
    let flags = (u16::from(value.downlink.is_some()) << 5)
        | (u16::from(value.uplink.is_some()) << 4)
        | (u16::from(value.accepted.is_some()) << 3)
        | (u16::from(value.failed.is_some()) << 1);
    out.bits(flags, 7)?;
    if let Some(v) = value.downlink {
        write_transport(out, v.address(), v.teid())?;
    }
    if let Some(v) = value.uplink {
        write_transport(out, v.address(), v.teid())?;
    }
    if let Some(values) = &value.accepted {
        out.bits((values.values().len() - 1) as u16, 6)?;
        for qfi in values.values() {
            out.bits(0, 3)?;
            out.bits(u16::from(qfi.value()), 6)?;
        }
    }
    if let Some(values) = &value.failed {
        out.bits((values.values().len() - 1) as u16, 6)?;
        for v in values.values() {
            out.bits(0, 3)?;
            out.bits(u16::from(v.qfi.value()), 6)?;
            write_cause(out, v.cause)?;
        }
    }
    Ok(())
}
fn scan_response(
    input: &[u8],
    ctx: DecodeContext,
    mut accepted: impl FnMut(QosFlowId),
    mut failed: impl FnMut(QosFlowCause),
) -> Result<(ModifyResponseTransfer, usize, usize), DecodeError> {
    bound(input, ctx, 1)?;
    let mut reader = Reader::new(input, ctx);
    let flags = reader.bits(7)?;
    if flags & !0b111010 != 0 {
        return Err(unsupported());
    }
    crate::enforce_depth(
        if flags & 2 != 0 {
            5
        } else if flags != 0 {
            4
        } else {
            1
        },
        ctx,
    )?;
    let mut value = ModifyResponseTransfer::default();
    if flags & 32 != 0 {
        let (address, teid) = read_transport(&mut reader)?;
        value.downlink = Some(DownlinkTransport::new(address, teid));
    }
    if flags & 16 != 0 {
        let (address, teid) = read_transport(&mut reader)?;
        value.uplink = Some(UplinkTransport::new(address, teid));
    }
    let mut seen = 0;
    let accepted_count = if flags & 8 != 0 {
        let count = reader.count(6, 64, 9)?;
        for _ in 0..count {
            reader.flags(3)?;
            let qfi = QosFlowId::new(reader.bits(6)? as u8)?;
            unique(&mut seen, qfi)?;
            accepted(qfi);
        }
        count
    } else {
        0
    };
    let failed_count = if flags & 2 != 0 {
        let count = reader.count(6, 64, 14)?;
        for _ in 0..count {
            reader.flags(3)?;
            let qfi = QosFlowId::new(reader.bits(6)? as u8)?;
            unique(&mut seen, qfi)?;
            failed(QosFlowCause {
                qfi,
                cause: read_cause(&mut reader)?,
            });
        }
        count
    } else {
        0
    };
    reader.finish()?;
    Ok((value, accepted_count, failed_count))
}

/// A failed session's root Cause and optional response diagnostics. Procedure
/// code and triggering outcome are inapplicable in same-procedure responses;
/// repeated diagnostic IE identifiers remain in wire order.
#[derive(Clone, PartialEq, Eq)]
pub struct ModifyFailureTransfer {
    /// Reported root Cause; retry, rollback and procedure actions are external.
    pub cause: Cause,
    /// Optional qualified root diagnostics, including an empty root object.
    pub diagnostics: Option<CriticalityDiagnostics>,
}
redacted!(ModifyFailureTransfer);
impl ModifyFailureTransfer {
    /// Encode with exact output preflight. Cause-only transfers retain the
    /// independently qualified generated encoder; diagnostics use the qualified
    /// explicit layout at their actual parent bit offset.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        if let Some(value) = &self.diagnostics {
            response_diagnostics(value).map_err(|_| {
                EncodeError::new(EncodeErrorCode::Structural {
                    reason: "response diagnostic header applicability",
                })
            })?;
            encode_root(ctx, |out| {
                out.bits(2, 3)?;
                write_cause(out, self.cause)?;
                write_diagnostics(out, value)
            })
        } else {
            capacity((7 + cause_width(self.cause.class())).div_ceil(8), ctx)?;
            encode_leaf(
                &asn::PDUSessionResourceModifyUnsuccessfulTransfer::new(
                    self.cause.generated()?,
                    None,
                    None,
                ),
                ctx,
            )
        }
    }
    /// Require depth three, or five with diagnostic items. Complete physical
    /// preflight precedes item allocation; `max_ies` bounds that list. Root
    /// optional/extension flags and nonzero padding are rejected explicitly.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (mut value, count) = scan_failure(input, ctx, |_| {})?;
        if value.diagnostics.is_none() {
            let generated: asn::PDUSessionResourceModifyUnsuccessfulTransfer = decode_leaf(input)?;
            value.cause = Cause::from_generated(generated.cause)?;
        }
        if count != 0 {
            let mut items = Vec::with_capacity(count);
            scan_failure(input, ctx, |v| items.push(v))?;
            if let Some(diagnostics) = &mut value.diagnostics {
                diagnostics.ies = Some(DiagnosticItems::new(items)?);
            }
        }
        Ok(value)
    }
}
pub(super) use super::reset_fields::response_diagnostics;
fn scan_failure(
    input: &[u8],
    ctx: DecodeContext,
    mut emit: impl FnMut(DiagnosticItem),
) -> Result<(ModifyFailureTransfer, usize), DecodeError> {
    bound(input, ctx, 3)?;
    let mut reader = Reader::new(input, ctx);
    let flags = reader.bits(3)?;
    if flags & !2 != 0 {
        return Err(unsupported());
    }
    let cause = read_cause(&mut reader)?;
    let mut count = 0;
    let diagnostics = if flags & 2 != 0 {
        let (header, items) = read_diagnostic_header(&mut reader)?;
        response_diagnostics(&header)?;
        if items {
            crate::enforce_depth(5, ctx)?;
            count = reader.count(8, 256, 22)?;
            for _ in 0..count {
                emit(read_diagnostic_item(&mut reader)?);
            }
        }
        Some(header)
    } else {
        None
    };
    reader.finish()?;
    Ok((ModifyFailureTransfer { cause, diagnostics }, count))
}
