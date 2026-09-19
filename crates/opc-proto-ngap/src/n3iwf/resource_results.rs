//! Qualified setup response/failure transfers for caller-owned procedures.
//! Results describe a peer's report; they do not install a tunnel or change
//! QoS state. The caller must correlate each QFI with the original request.

use super::release::{Cause, CauseClass};
use super::reset_fields::CriticalityDiagnostics;
use super::resource_fields::{DownlinkTransport, QosFlowId};
use super::security_fields::SecurityResult;
use super::setup_fields::Reader;
use super::*;

/// A failed flow with its explicit root Cause.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FailedQosFlow {
    /// Reported flow identifier, without a resource-ownership claim.
    pub qfi: QosFlowId,
    /// Peer-reported failure cause.
    pub cause: Cause,
}
redacted!(FailedQosFlow);

mod tunnels;
pub use tunnels::{AssociatedQosFlow, DownlinkQosTunnel, QosFlowMapping, SetupResponseTransfer};

/// An entirely failed session's root Cause and optional response diagnostics.
/// Procedure code and triggering outcome are inapplicable in same-procedure
/// responses. Repeated diagnostic IE identifiers remain in wire order.
/// Extensions remain unsupported; retry and resource effects are external.
#[derive(Clone, PartialEq, Eq)]
pub struct SetupFailureTransfer {
    /// Peer-reported cause; selecting a response or retry is caller-owned.
    pub cause: Cause,
    /// Optional qualified root diagnostics, including an empty root object.
    pub diagnostics: Option<CriticalityDiagnostics>,
}
redacted!(SetupFailureTransfer);
impl SetupFailureTransfer {
    /// Preflight exact output capacity before allocation. The Setup and Modify
    /// failure roots share an independently qualified bit layout, including
    /// diagnostics at the actual parent offset after each root Cause.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        super::modify_results::encode_failure(self.cause, self.diagnostics.as_ref(), ctx)
    }
    /// Require depth three, or five with diagnostic items. Complete physical
    /// preflight precedes item allocation; `max_ies` bounds that list. Enforce
    /// response applicability, exact framing and zero alignment/final padding.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        let value = super::modify_results::ModifyFailureTransfer::decode(input, ctx)?;
        Ok(Self {
            cause: value.cause,
            diagnostics: value.diagnostics,
        })
    }
}

pub(super) fn unique(seen: &mut u64, qfi: QosFlowId) -> Result<(), DecodeError> {
    let bit = 1_u64 << qfi.value();
    if *seen & bit != 0 {
        return Err(invalid("duplicate or conflicting resource result"));
    }
    *seen |= bit;
    Ok(())
}
fn write_octets(
    writer: &mut dyn super::reset_fields::Sink,
    bytes: &[u8],
) -> Result<(), EncodeError> {
    for byte in bytes {
        writer.bits(u16::from(*byte), 8)?;
    }
    Ok(())
}
fn read_octets<const N: usize>(reader: &mut Reader<'_>) -> Result<[u8; N], DecodeError> {
    let mut bytes = [0; N];
    for byte in &mut bytes {
        *byte = reader.bits(8)? as u8;
    }
    Ok(bytes)
}
pub(super) fn cause_width(class: CauseClass) -> usize {
    match class {
        CauseClass::RadioNetwork => 6,
        CauseClass::Transport => 1,
        CauseClass::Nas => 2,
        CauseClass::Protocol | CauseClass::Misc => 3,
    }
}
pub(super) fn write_cause(
    writer: &mut dyn super::reset_fields::Sink,
    cause: Cause,
) -> Result<(), EncodeError> {
    let class = match cause.class() {
        CauseClass::RadioNetwork => 0,
        CauseClass::Transport => 1,
        CauseClass::Nas => 2,
        CauseClass::Protocol => 3,
        CauseClass::Misc => 4,
    };
    writer.bits(class, 3)?;
    writer.bits(0, 1)?;
    writer.bits(u16::from(cause.code()), cause_width(cause.class()))
}
pub(super) fn read_cause(reader: &mut Reader<'_>) -> Result<Cause, DecodeError> {
    let class = match reader.bits(3)? {
        0 => CauseClass::RadioNetwork,
        1 => CauseClass::Transport,
        2 => CauseClass::Nas,
        3 => CauseClass::Protocol,
        4 => CauseClass::Misc,
        _ => return Err(unsupported()),
    };
    reader.flags(1)?;
    Cause::new(class, reader.bits(cause_width(class))? as u8)
}
