//! Qualified setup response/failure transfers for caller-owned procedures.
//! Results describe a peer's report; they do not install a tunnel or change
//! QoS state. The caller must correlate each QFI with the original request.

use super::release::{Cause, CauseClass};
use super::resource_fields::{DownlinkTransport, QosFlowId};
use super::setup_fields::{Reader, Writer};
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

/// One downlink transport with 1–64 accepted flows and optional failed flows.
/// Duplicate QFIs and overlap between accepted/failed results are rejected.
/// Additional tunnels, mapping indications, security results and extensions
/// require further qualification and are explicitly unsupported here.
#[derive(Clone, PartialEq, Eq)]
pub struct SetupResponseTransfer {
    downlink: DownlinkTransport,
    accepted: Vec<QosFlowId>,
    failed: Vec<FailedQosFlow>,
}
redacted!(SetupResponseTransfer);

impl SetupResponseTransfer {
    /// Require nonempty accepted results and a unique, disjoint QFI domain.
    /// An entirely failed session uses `SetupFailureTransfer` instead.
    pub fn new(
        downlink: DownlinkTransport,
        accepted: Vec<QosFlowId>,
        failed: Vec<FailedQosFlow>,
    ) -> Result<Self, DecodeError> {
        if accepted.is_empty() || accepted.len() > 64 || failed.len() > 64 {
            return Err(invalid("resource result count"));
        }
        let mut seen = 0;
        for qfi in accepted.iter().copied().chain(failed.iter().map(|v| v.qfi)) {
            unique(&mut seen, qfi)?;
        }
        Ok(Self {
            downlink,
            accepted,
            failed,
        })
    }
    /// Explicit downlink endpoint, distinct from the request's uplink value.
    pub const fn downlink(&self) -> DownlinkTransport {
        self.downlink
    }
    /// Explicit accepted identifiers, in received order.
    pub fn accepted(&self) -> &[QosFlowId] {
        &self.accepted
    }
    /// Explicit failure records, in received order.
    pub fn failed(&self) -> &[FailedQosFlow] {
        &self.failed
    }
    /// Encode only the independently qualified root layout. Exact capacity
    /// is checked before allocating the bounded result buffer.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        // Five transfer flags, two TNL flags, four transport flags and eight
        // address-length bits align to three octets at the address boundary.
        let address_bits = if self.downlink.address().is_ipv4() {
            32
        } else {
            128
        };
        let mut bits = 24 + address_bits + 32 + 6 + self.accepted.len() * 10;
        if !self.failed.is_empty() {
            bits += 6 + self
                .failed
                .iter()
                .map(|v| 13 + cause_width(v.cause.class()))
                .sum::<usize>();
        }
        let length = bits.div_ceil(8);
        capacity(length, ctx)?;
        let mut writer = Writer::new(length);
        writer.bits(if self.failed.is_empty() { 0 } else { 2 }, 5)?;
        writer.bits(0, 2)?;
        writer.bits(0, 4)?;
        writer.bits((address_bits - 1) as u16, 8)?;
        writer.align();
        match self.downlink.address() {
            IpAddr::V4(value) => write_octets(&mut writer, &value.octets())?,
            IpAddr::V6(value) => write_octets(&mut writer, &value.octets())?,
        }
        write_octets(&mut writer, &self.downlink.teid().to_be_bytes())?;
        writer.bits((self.accepted.len() - 1) as u16, 6)?;
        for qfi in &self.accepted {
            writer.bits(0, 4)?;
            writer.bits(u16::from(qfi.value()), 6)?;
        }
        if !self.failed.is_empty() {
            writer.bits((self.failed.len() - 1) as u16, 6)?;
            for value in &self.failed {
                writer.bits(0, 3)?;
                writer.bits(u16::from(value.qfi.value()), 6)?;
                write_cause(&mut writer, value.cause)?;
            }
        }
        writer.finish()
    }
    /// Decode a bounded root transfer with depth six. `max_ies` bounds the
    /// combined accepted/failed flow count before either vector is allocated.
    /// Extension/optional flags are checked before their payloads are read.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 6)?;
        let mut reader = Reader::new(input, ctx);
        let flags = reader.bits(5)?;
        if flags & !2 != 0 {
            return Err(unsupported());
        }
        reader.flags(2)?;
        reader.flags(4)?;
        let address_bits = reader.bits(8)? + 1;
        if !matches!(address_bits, 32 | 128) {
            return Err(unsupported());
        }
        reader.align()?;
        let address = if address_bits == 32 {
            IpAddr::V4(std::net::Ipv4Addr::from(read_octets::<4>(&mut reader)?))
        } else {
            IpAddr::V6(std::net::Ipv6Addr::from(read_octets::<16>(&mut reader)?))
        };
        let downlink =
            DownlinkTransport::new(address, u32::from_be_bytes(read_octets(&mut reader)?));
        let count = reader.count(6, 64, 10)?;
        let mut accepted = Vec::with_capacity(count);
        let mut seen = 0;
        for _ in 0..count {
            reader.flags(4)?;
            let qfi = QosFlowId::new(reader.bits(6)? as u8)?;
            unique(&mut seen, qfi)?;
            accepted.push(qfi);
        }
        let mut failed = Vec::new();
        if flags & 2 != 0 {
            let count = reader.count(6, 64, 14)?;
            failed = Vec::with_capacity(count);
            for _ in 0..count {
                reader.flags(3)?;
                let qfi = QosFlowId::new(reader.bits(6)? as u8)?;
                unique(&mut seen, qfi)?;
                failed.push(FailedQosFlow {
                    qfi,
                    cause: read_cause(&mut reader)?,
                });
            }
        }
        reader.finish()?;
        Ok(Self {
            downlink,
            accepted,
            failed,
        })
    }
}

/// An entirely failed session's setup transfer, carrying a root Cause.
/// Criticality diagnostics and extensions remain unsupported.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SetupFailureTransfer {
    /// Peer-reported cause; selecting a response or retry is caller-owned.
    pub cause: Cause,
}
redacted!(SetupFailureTransfer);
impl SetupFailureTransfer {
    /// Encode the independently qualified generated root transfer.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity((7 + cause_width(self.cause.class())).div_ceil(8), ctx)?;
        encode_leaf(
            &asn::PDUSessionResourceSetupUnsuccessfulTransfer::new(
                self.cause.generated()?,
                None,
                None,
            ),
            ctx,
        )
    }
    /// Decode with depth three. Reject extension/optional payloads before
    /// generated materialization; require exact framing and zero padding.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 3)?;
        let first = *input
            .first()
            .ok_or_else(|| invalid("missing failure transfer"))?;
        if first & 0xe0 != 0 || (first >> 2) & 7 >= 5 || first & 2 != 0 {
            return Err(unsupported());
        }
        // Generated decoding consumes final padding without requiring zero.
        // Preflight the complete fixed root shape before invoking it.
        let bits: usize = 7 + match (first >> 2) & 7 {
            0 => 6,
            1 => 1,
            2 => 2,
            _ => 3,
        };
        let length = bits.div_ceil(8);
        let padding_mask = (1_u8 << (length * 8 - bits)) - 1;
        if input.len() != length || input[length - 1] & padding_mask != 0 {
            return Err(invalid("failure transfer framing"));
        }
        let value: asn::PDUSessionResourceSetupUnsuccessfulTransfer = decode_leaf(input)?;
        Ok(Self {
            cause: Cause::from_generated(value.cause)?,
        })
    }
}

fn unique(seen: &mut u64, qfi: QosFlowId) -> Result<(), DecodeError> {
    let bit = 1_u64 << qfi.value();
    if *seen & bit != 0 {
        return Err(invalid("duplicate or conflicting resource result"));
    }
    *seen |= bit;
    Ok(())
}
fn write_octets(writer: &mut Writer, bytes: &[u8]) -> Result<(), EncodeError> {
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
fn cause_width(class: CauseClass) -> usize {
    match class {
        CauseClass::RadioNetwork => 6,
        CauseClass::Transport => 1,
        CauseClass::Nas => 2,
        CauseClass::Protocol | CauseClass::Misc => 3,
    }
}
fn write_cause(writer: &mut Writer, cause: Cause) -> Result<(), EncodeError> {
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
fn read_cause(reader: &mut Reader<'_>) -> Result<Cause, DecodeError> {
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
