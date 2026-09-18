//! Independently qualified root lists for PDU Session Resource Modify.
//! These fields describe requests or reports; ownership, request correlation,
//! conditional presence and resource effects belong to the enclosing procedure.

use super::release::Cause;
use super::resource_fields::{DownlinkTransport, NonGbrFlow, QosFlowId, UplinkTransport};
use super::resource_results::{cause_width, read_cause, unique};
use super::session_lists::encode_list;
use super::setup_fields::{Reader, Writer};
use super::*;

/// A QFI with absent parameters or explicit standardized non-GBR 5QI 9
/// parameters. Absence is preserved; it neither supplies defaults nor proves
/// that the flow exists. Other profiles and optional fields are unsupported.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum QosFlowModification {
    /// Only the identifier was supplied.
    Identifier(QosFlowId),
    /// Explicit 5QI 9 and root allocation/retention priority.
    NonGbr(NonGbrFlow),
}
redacted!(QosFlowModification);
impl QosFlowModification {
    /// Explicit flow identifier for caller-owned correlation.
    pub const fn qfi(self) -> QosFlowId {
        match self {
            Self::Identifier(value) => value,
            Self::NonGbr(value) => value.qfi(),
        }
    }
}

/// One through 64 unique add/modify requests, preserving optional parameters.
#[derive(Clone, PartialEq, Eq)]
pub struct QosFlowModifications(Vec<QosFlowModification>);
redacted!(QosFlowModifications);
impl QosFlowModifications {
    /// Validate the root count and unique identifiers without reordering.
    pub fn new(values: Vec<QosFlowModification>) -> Result<Self, DecodeError> {
        validate_qfis(values.iter().map(|v| v.qfi()), values.len())?;
        Ok(Self(values))
    }
    /// Explicit requests in wire order.
    pub fn values(&self) -> &[QosFlowModification] {
        &self.0
    }
    /// Encode the qualified root after exact sizing. The generated encoder is
    /// retained for identifier-only lists; nested parameter encoding fails
    /// independent vectors and uses a bounded explicit layout instead.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let mut bits: usize = 6;
        let mut parameters = false;
        for value in &self.0 {
            bits += 11;
            if matches!(value, QosFlowModification::NonGbr(_)) {
                parameters = true;
                bits = (bits + 13).div_ceil(8) * 8 + 18;
            }
        }
        let length = bits.div_ceil(8);
        capacity(length, ctx)?;
        if !parameters {
            let values = self
                .0
                .iter()
                .map(|v| {
                    asn::QosFlowAddOrModifyRequestItem::new(
                        asn::QosFlowIdentifier(v.qfi().value().into()),
                        None,
                        None,
                        None,
                    )
                })
                .collect();
            return encode_list(&asn::QosFlowAddOrModifyRequestList(values), length);
        }
        let mut writer = Writer::new(length);
        writer.bits((self.0.len() - 1) as u16, 6)?;
        for value in &self.0 {
            let present = matches!(value, QosFlowModification::NonGbr(_));
            writer.bits(if present { 4 } else { 0 }, 4)?;
            writer.bits(u16::from(value.qfi().value()), 7)?;
            if let QosFlowModification::NonGbr(value) = value {
                writer.bits(0, 13)?; // root parameters, non-dynamic descriptor and 5QI
                writer.align();
                writer.bits(9, 8)?;
                writer.bits(0, 2)?; // ARP extensions
                writer.bits(u16::from(value.priority() - 1), 4)?;
                writer.bits(u16::from(value.may_preempt()), 2)?;
                writer.bits(u16::from(value.preemptable()), 2)?;
            }
        }
        writer.finish()
    }
    /// Require depth three for identifiers or six with parameters. Complete
    /// count, flags, padding and uniqueness preflight precedes vector allocation.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        let count = scan_requests(input, ctx, |_| {})?;
        let mut values = Vec::with_capacity(count);
        scan_requests(input, ctx, |v| values.push(v))?;
        Ok(Self(values))
    }
}

fn scan_requests(
    input: &[u8],
    ctx: DecodeContext,
    mut emit: impl FnMut(QosFlowModification),
) -> Result<usize, DecodeError> {
    bound(input, ctx, 3)?;
    let mut reader = Reader::new(input, ctx);
    let count = reader.count(6, 64, 11)?;
    let mut seen = 0;
    for _ in 0..count {
        let flags = reader.bits(4)?;
        if flags & !4 != 0 {
            return Err(unsupported());
        }
        reader.flags(1)?;
        let qfi = QosFlowId::new(reader.bits(6)? as u8)?;
        unique(&mut seen, qfi)?;
        if flags & 4 == 0 {
            emit(QosFlowModification::Identifier(qfi));
        } else {
            crate::enforce_depth(6, ctx)?;
            reader.flags(13)?;
            reader.align()?;
            if reader.bits(8)? != 9 {
                return Err(unsupported());
            }
            reader.flags(2)?;
            let priority = reader.bits(4)? as u8 + 1;
            reader.flags(1)?;
            let may_preempt = reader.bits(1)? != 0;
            reader.flags(1)?;
            let preemptable = reader.bits(1)? != 0;
            emit(QosFlowModification::NonGbr(NonGbrFlow::new(
                qfi,
                priority,
                may_preempt,
                preemptable,
            )?));
        }
    }
    reader.finish()?;
    Ok(count)
}

/// One through 64 unique successfully added/modified QFIs. This report does
/// not establish request correspondence or prove that resources were changed.
#[derive(Clone, PartialEq, Eq)]
pub struct ModifiedQosFlows(Vec<QosFlowId>);
redacted!(ModifiedQosFlows);
impl ModifiedQosFlows {
    /// Enforce count and uniqueness while preserving order.
    pub fn new(values: Vec<QosFlowId>) -> Result<Self, DecodeError> {
        validate_qfis(values.iter().copied(), values.len())?;
        Ok(Self(values))
    }
    /// Explicit reported QFIs.
    pub fn values(&self) -> &[QosFlowId] {
        &self.0
    }
    /// Retain the qualified generated encoder after exact capacity preflight.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let length = (6 + self.0.len() * 9).div_ceil(8);
        capacity(length, ctx)?;
        let values = self
            .0
            .iter()
            .map(|qfi| {
                asn::QosFlowAddOrModifyResponseItem::new(
                    asn::QosFlowIdentifier(qfi.value().into()),
                    None,
                )
            })
            .collect();
        encode_list(&asn::QosFlowAddOrModifyResponseList(values), length)
    }
    /// Decode root entries with depth three; preflight before allocation.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        let count = scan_modified(input, ctx, |_| {})?;
        let mut values = Vec::with_capacity(count);
        scan_modified(input, ctx, |v| values.push(v))?;
        Ok(Self(values))
    }
}
fn scan_modified(
    input: &[u8],
    ctx: DecodeContext,
    mut emit: impl FnMut(QosFlowId),
) -> Result<usize, DecodeError> {
    bound(input, ctx, 3)?;
    let mut reader = Reader::new(input, ctx);
    let count = reader.count(6, 64, 9)?;
    let mut seen = 0;
    for _ in 0..count {
        reader.flags(3)?;
        let qfi = QosFlowId::new(reader.bits(6)? as u8)?;
        unique(&mut seen, qfi)?;
        emit(qfi);
    }
    reader.finish()?;
    Ok(count)
}

/// A QFI with a root Cause. The enclosing procedure determines whether this
/// describes a release request, failed modification or another qualified use.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct QosFlowCause {
    /// Explicit identifier without ownership evidence.
    pub qfi: QosFlowId,
    /// Explicit root cause without a local effect.
    pub cause: Cause,
}
redacted!(QosFlowCause);

/// One through 64 unique QFI/Cause entries in received order.
#[derive(Clone, PartialEq, Eq)]
pub struct QosFlowCauses(Vec<QosFlowCause>);
redacted!(QosFlowCauses);
impl QosFlowCauses {
    /// Require the root count and unique identifiers.
    pub fn new(values: Vec<QosFlowCause>) -> Result<Self, DecodeError> {
        validate_qfis(values.iter().map(|v| v.qfi), values.len())?;
        Ok(Self(values))
    }
    /// Explicit reports, without selecting procedure effects.
    pub fn values(&self) -> &[QosFlowCause] {
        &self.0
    }
    /// Retain generated root encoding after exact capacity preflight.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let bits = 6 + self
            .0
            .iter()
            .map(|v| 13 + cause_width(v.cause.class()))
            .sum::<usize>();
        let length = bits.div_ceil(8);
        capacity(length, ctx)?;
        let values = self
            .0
            .iter()
            .map(|v| {
                Ok(asn::QosFlowWithCauseItem::new(
                    asn::QosFlowIdentifier(v.qfi.value().into()),
                    v.cause.generated()?,
                    None,
                ))
            })
            .collect::<Result<_, EncodeError>>()?;
        encode_list(&asn::QosFlowListWithCause(values), length)
    }
    /// Decode with depth four. Complete physical and uniqueness checks precede
    /// vector allocation; root optional fields and extensions are unsupported.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        let count = scan_causes(input, ctx, |_| {})?;
        let mut values = Vec::with_capacity(count);
        scan_causes(input, ctx, |v| values.push(v))?;
        Ok(Self(values))
    }
}
fn scan_causes(
    input: &[u8],
    ctx: DecodeContext,
    mut emit: impl FnMut(QosFlowCause),
) -> Result<usize, DecodeError> {
    bound(input, ctx, 4)?;
    let mut reader = Reader::new(input, ctx);
    let count = reader.count(6, 64, 14)?;
    let mut seen = 0;
    for _ in 0..count {
        reader.flags(3)?;
        let qfi = QosFlowId::new(reader.bits(6)? as u8)?;
        unique(&mut seen, qfi)?;
        emit(QosFlowCause {
            qfi,
            cause: read_cause(&mut reader)?,
        });
    }
    reader.finish()?;
    Ok(count)
}

/// A requested uplink endpoint and the downlink endpoint identifying the
/// existing bearer. Direction remains explicit; existence is caller-checked.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UplinkModification {
    /// Requested endpoint at the core for uplink delivery.
    pub uplink: UplinkTransport,
    /// Endpoint at the N3IWF identifying the existing bearer.
    pub downlink: DownlinkTransport,
}
redacted!(UplinkModification);

/// One through four ordered root tunnel pairs. Repeated pairs are preserved;
/// the codec does not infer bearer ownership or perform a tunnel update.
#[derive(Clone, PartialEq, Eq)]
pub struct UplinkModifications(Vec<UplinkModification>);
redacted!(UplinkModifications);
impl UplinkModifications {
    /// Require the ASN.1 root list count, without inventing endpoint policy.
    pub fn new(values: Vec<UplinkModification>) -> Result<Self, DecodeError> {
        if values.is_empty() || values.len() > 4 {
            return Err(invalid("uplink modification count"));
        }
        Ok(Self(values))
    }
    /// Explicit pairs in wire order.
    pub fn values(&self) -> &[UplinkModification] {
        &self.0
    }
    /// Encode the independently qualified root. The generated list encoder
    /// fails embedded transport alignment; sizing precedes allocation.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let mut bits: usize = 2;
        for value in &self.0 {
            bits += 2;
            for address in [value.uplink.address(), value.downlink.address()] {
                bits = (bits + 12).div_ceil(8) * 8;
                bits += if address.is_ipv4() { 32 } else { 128 };
                bits += 32;
            }
        }
        let length = bits.div_ceil(8);
        capacity(length, ctx)?;
        let mut writer = Writer::new(length);
        writer.bits((self.0.len() - 1) as u16, 2)?;
        for value in &self.0 {
            writer.bits(0, 2)?;
            write_transport(&mut writer, value.uplink.address(), value.uplink.teid())?;
            write_transport(&mut writer, value.downlink.address(), value.downlink.teid())?;
        }
        writer.finish()
    }
    /// Require depth five. Validate all addresses, flags, counts, alignment and
    /// exact framing before allocating the result vector. Only IPv4/IPv6 GTP
    /// roots are qualified; dual-address bit strings and extensions fail.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        let count = scan_tunnels(input, ctx, |_| {})?;
        let mut values = Vec::with_capacity(count);
        scan_tunnels(input, ctx, |v| values.push(v))?;
        Ok(Self(values))
    }
}
fn scan_tunnels(
    input: &[u8],
    ctx: DecodeContext,
    mut emit: impl FnMut(UplinkModification),
) -> Result<usize, DecodeError> {
    bound(input, ctx, 5)?;
    let mut reader = Reader::new(input, ctx);
    let count = reader.count(2, 4, 154)?;
    for _ in 0..count {
        reader.flags(2)?;
        let (address, teid) = read_transport(&mut reader)?;
        let uplink = UplinkTransport::new(address, teid);
        let (address, teid) = read_transport(&mut reader)?;
        let downlink = DownlinkTransport::new(address, teid);
        emit(UplinkModification { uplink, downlink });
    }
    reader.finish()?;
    Ok(count)
}
fn write_transport(writer: &mut Writer, address: IpAddr, teid: u32) -> Result<(), EncodeError> {
    writer.bits(0, 4)?;
    writer.bits(if address.is_ipv4() { 31 } else { 127 }, 8)?;
    writer.align();
    match address {
        IpAddr::V4(value) => write_octets(writer, &value.octets())?,
        IpAddr::V6(value) => write_octets(writer, &value.octets())?,
    }
    write_octets(writer, &teid.to_be_bytes())
}
fn read_transport(reader: &mut Reader<'_>) -> Result<(IpAddr, u32), DecodeError> {
    reader.flags(4)?;
    let bits = reader.bits(8)? + 1;
    if !matches!(bits, 32 | 128) {
        return Err(unsupported());
    }
    reader.align()?;
    let address = if bits == 32 {
        IpAddr::V4(std::net::Ipv4Addr::from(read_octets::<4>(reader)?))
    } else {
        IpAddr::V6(std::net::Ipv6Addr::from(read_octets::<16>(reader)?))
    };
    Ok((address, u32::from_be_bytes(read_octets(reader)?)))
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
fn validate_qfis(qfis: impl Iterator<Item = QosFlowId>, count: usize) -> Result<(), DecodeError> {
    if count == 0 || count > 64 {
        return Err(invalid("modify flow count"));
    }
    let mut seen = 0;
    for qfi in qfis {
        unique(&mut seen, qfi)?;
    }
    Ok(())
}
