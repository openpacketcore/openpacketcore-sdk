#![forbid(unsafe_code)]

//! Typed PFCP Information Elements (TS 29.244 §8.2).
//!
//! This module builds on the raw TLV layer ([`InformationElement`]) to provide
//! structured decode/encode for the session-management IE set. Unknown and
//! vendor-specific IEs retain byte-exact raw preservation.
//!
//! @spec 3GPP TS29244 R18 8.2
//! @req REQ-3GPP-TS29244-R18-8.2-001

use bytes::{Bytes, BytesMut};
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, EncodeContext, EncodeError, SpecRef,
};

use crate::InformationElement;

mod grouped;
mod simple;

use simple::SimpleIe;

#[cfg(test)]
mod tests;

pub use grouped::{
    CreateFar, CreatePdr, CreateQer, CreateUrr, CreatedPdr, ForwardingParameters, Pdi, UpdateQer,
};
pub use simple::{
    ApplyAction, Cause, CauseValue, DestinationInterface, FSeid, FTeid, FarId, Gate, GateStatus,
    Gbr, Mbr, NetworkInstance, NodeId, NodeIdType, OuterHeaderCreation, OuterHeaderRemoval, PdrId,
    Precedence, QerId, Qfi, RecoveryTimeStamp, SourceInterface, UeIpAddress, UrrId,
};

/// A decoded PFCP IE — either a known typed IE or a raw-preserving fallback.
///
/// @spec 3GPP TS29244 R18 8.2
/// @req REQ-3GPP-TS29244-R18-8.2-002
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedIe {
    /// Create PDR (grouped IE, type 1).
    CreatePdr(CreatePdr),
    /// PDI (grouped IE, type 2).
    Pdi(Pdi),
    /// Create FAR (grouped IE, type 3).
    CreateFar(CreateFar),
    /// Forwarding Parameters (grouped IE, type 4).
    ForwardingParameters(ForwardingParameters),
    /// Create URR (grouped IE, type 6).
    CreateUrr(CreateUrr),
    /// Create QER (grouped IE, type 7).
    CreateQer(CreateQer),
    /// Update QER (grouped IE, type 14).
    UpdateQer(UpdateQer),
    /// Created PDR (grouped IE, type 8).
    CreatedPdr(CreatedPdr),
    /// Cause (type 19).
    Cause(Cause),
    /// Source Interface (type 20).
    SourceInterface(SourceInterface),
    /// F-TEID (type 21).
    FTeid(FTeid),
    /// Network Instance (type 22).
    NetworkInstance(NetworkInstance),
    /// Gate Status (type 25).
    GateStatus(GateStatus),
    /// Maximum Bit Rate (type 26).
    Mbr(Mbr),
    /// Guaranteed Bit Rate (type 27).
    Gbr(Gbr),
    /// Precedence (type 29).
    Precedence(Precedence),
    /// Apply Action (type 44).
    ApplyAction(ApplyAction),
    /// Destination Interface (type 42).
    DestinationInterface(DestinationInterface),
    /// PDR ID (type 56).
    PdrId(PdrId),
    /// F-SEID (type 57).
    FSeid(FSeid),
    /// Node ID (type 60).
    NodeId(NodeId),
    /// URR ID (type 81).
    UrrId(UrrId),
    /// UE IP Address (type 93).
    UeIpAddress(UeIpAddress),
    /// Outer Header Removal (type 95).
    OuterHeaderRemoval(OuterHeaderRemoval),
    /// Recovery Time Stamp (type 96).
    RecoveryTimeStamp(RecoveryTimeStamp),
    /// Outer Header Creation (type 84).
    OuterHeaderCreation(OuterHeaderCreation),
    /// FAR ID (type 108).
    FarId(FarId),
    /// QER ID (type 109).
    QerId(QerId),
    /// QoS Flow Identifier (type 124).
    Qfi(Qfi),
    /// Unknown or vendor IE preserved byte-exact.
    Raw(InformationElement),
}

impl TypedIe {
    /// Decode a single IE from the input buffer, dispatching to the typed
    /// decoder when the type code is known.
    ///
    /// `depth` tracks grouped-IE nesting; `ctx.max_depth` is enforced.
    ///
    /// @spec 3GPP TS29244 R18 8.1.1, 8.2
    /// @req REQ-3GPP-TS29244-R18-8.2-003
    pub fn decode(input: &[u8], ctx: DecodeContext, depth: usize) -> DecodeResult<'_, Self> {
        let spec_ref = SpecRef::new("3gpp", "TS29244", "8.1.1");
        if depth > ctx.max_depth {
            return Err(DecodeError::new(DecodeErrorCode::DepthExceeded, 0).with_spec_ref(spec_ref));
        }

        let (remaining, raw) = InformationElement::decode(input)?;
        let typed = Self::decode_from_raw(raw, ctx, depth)?;
        Ok((remaining, typed))
    }

    /// Convert an already-decoded raw IE into a typed IE.
    ///
    /// This is the internal dispatch point used by both top-level decode and
    /// grouped-IE recursion.
    fn decode_from_raw(
        raw: InformationElement,
        ctx: DecodeContext,
        depth: usize,
    ) -> Result<Self, DecodeError> {
        let spec_ref = SpecRef::new("3gpp", "TS29244", "8.2");
        let value = &raw.value[..];
        let offset = 0usize;

        let result = match raw.ie_type {
            1 => Self::CreatePdr(decode_grouped(value, ctx, depth)?),
            2 => Self::Pdi(decode_grouped(value, ctx, depth)?),
            3 => Self::CreateFar(decode_grouped(value, ctx, depth)?),
            4 => Self::ForwardingParameters(decode_grouped(value, ctx, depth)?),
            6 => Self::CreateUrr(decode_grouped(value, ctx, depth)?),
            7 => Self::CreateQer(decode_grouped(value, ctx, depth)?),
            14 => Self::UpdateQer(decode_grouped(value, ctx, depth)?),
            8 => Self::CreatedPdr(decode_grouped(value, ctx, depth)?),
            19 => Self::Cause(simple::Cause::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            20 => Self::SourceInterface(simple::SourceInterface::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            21 => Self::FTeid(simple::FTeid::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            22 => Self::NetworkInstance(simple::NetworkInstance::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            25 => Self::GateStatus(simple::GateStatus::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            26 => Self::Mbr(simple::Mbr::decode_value(value, offset, spec_ref.clone())?),
            27 => Self::Gbr(simple::Gbr::decode_value(value, offset, spec_ref.clone())?),
            29 => Self::Precedence(simple::Precedence::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            42 => Self::DestinationInterface(simple::DestinationInterface::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            44 => Self::ApplyAction(simple::ApplyAction::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            56 => Self::PdrId(simple::PdrId::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            57 => Self::FSeid(simple::FSeid::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            60 => Self::NodeId(simple::NodeId::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            81 => Self::UrrId(simple::UrrId::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            84 => Self::OuterHeaderCreation(simple::OuterHeaderCreation::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            93 => Self::UeIpAddress(simple::UeIpAddress::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            95 => Self::OuterHeaderRemoval(simple::OuterHeaderRemoval::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            96 => Self::RecoveryTimeStamp(simple::RecoveryTimeStamp::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            108 => Self::FarId(simple::FarId::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            109 => Self::QerId(simple::QerId::decode_value(
                value,
                offset,
                spec_ref.clone(),
            )?),
            124 => Self::Qfi(simple::Qfi::decode_value(value, offset, spec_ref.clone())?),
            _ => Self::Raw(raw),
        };

        Ok(result)
    }

    /// Encode this typed IE into a buffer.
    ///
    /// Unknown/vendor IEs are encoded via the raw TLV layer.
    ///
    /// @spec 3GPP TS29244 R18 8.1.1, 8.2
    /// @req REQ-3GPP-TS29244-R18-8.2-004
    pub fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        match self {
            Self::Raw(raw) => raw.encode(dst),
            other => {
                let (ie_type, value) = other.encode_value_parts(ctx)?;
                let ie = InformationElement {
                    ie_type,
                    enterprise_id: 0,
                    value,
                };
                ie.encode(dst)
            }
        }
    }

    /// Encode only the value octets of this typed IE.
    ///
    /// The returned bytes are exactly the IE value field (no type or length
    /// header). Grouped IEs are recursively encoded in place. This is the
    /// building block for [`InformationElement::from_typed`].
    ///
    /// @spec 3GPP TS29244 R18 8.1.1, 8.2
    /// @req REQ-3GPP-TS29244-R18-8.2-005
    ///
    /// # Example
    ///
    /// ```rust
    /// use opc_proto_pfcp::ie::{FSeid, TypedIe};
    ///
    /// let fseid = FSeid {
    ///     v4: true,
    ///     v6: false,
    ///     seid: 1,
    ///     ipv4: Some([127, 0, 0, 1]),
    ///     ipv6: None,
    /// };
    /// let value = TypedIe::FSeid(fseid).encode_value().expect("valid F-SEID");
    /// assert!(!value.is_empty());
    /// ```
    pub fn encode_value(&self) -> Result<Bytes, EncodeError> {
        match self {
            Self::Raw(raw) => Ok(raw.value.clone()),
            other => other
                .encode_value_parts(EncodeContext::default())
                .map(|(_, v)| v),
        }
    }

    /// Encode the inner value and return the IE type code.
    fn encode_value_parts(&self, ctx: EncodeContext) -> Result<(u16, Bytes), EncodeError> {
        let mut buf = BytesMut::new();
        let ie_type = match self {
            Self::CreatePdr(v) => {
                encode_grouped(v, &mut buf, ctx)?;
                1
            }
            Self::Pdi(v) => {
                encode_grouped(v, &mut buf, ctx)?;
                2
            }
            Self::CreateFar(v) => {
                encode_grouped(v, &mut buf, ctx)?;
                3
            }
            Self::ForwardingParameters(v) => {
                encode_grouped(v, &mut buf, ctx)?;
                4
            }
            Self::CreateUrr(v) => {
                encode_grouped(v, &mut buf, ctx)?;
                6
            }
            Self::CreateQer(v) => {
                encode_grouped(v, &mut buf, ctx)?;
                7
            }
            Self::UpdateQer(v) => {
                encode_grouped(v, &mut buf, ctx)?;
                14
            }
            Self::CreatedPdr(v) => {
                encode_grouped(v, &mut buf, ctx)?;
                8
            }
            Self::Cause(v) => {
                v.encode_value(&mut buf)?;
                19
            }
            Self::SourceInterface(v) => {
                v.encode_value(&mut buf)?;
                20
            }
            Self::FTeid(v) => {
                v.encode_value(&mut buf)?;
                21
            }
            Self::NetworkInstance(v) => {
                v.encode_value(&mut buf)?;
                22
            }
            Self::GateStatus(v) => {
                v.encode_value(&mut buf)?;
                25
            }
            Self::Mbr(v) => {
                v.encode_value(&mut buf)?;
                26
            }
            Self::Gbr(v) => {
                v.encode_value(&mut buf)?;
                27
            }
            Self::Precedence(v) => {
                v.encode_value(&mut buf)?;
                29
            }
            Self::ApplyAction(v) => {
                v.encode_value(&mut buf)?;
                44
            }
            Self::DestinationInterface(v) => {
                v.encode_value(&mut buf)?;
                42
            }
            Self::PdrId(v) => {
                v.encode_value(&mut buf)?;
                56
            }
            Self::FSeid(v) => {
                v.encode_value(&mut buf)?;
                57
            }
            Self::NodeId(v) => {
                v.encode_value(&mut buf)?;
                60
            }
            Self::UrrId(v) => {
                v.encode_value(&mut buf)?;
                81
            }
            Self::UeIpAddress(v) => {
                v.encode_value(&mut buf)?;
                93
            }
            Self::OuterHeaderRemoval(v) => {
                v.encode_value(&mut buf)?;
                95
            }
            Self::RecoveryTimeStamp(v) => {
                v.encode_value(&mut buf)?;
                96
            }
            Self::OuterHeaderCreation(v) => {
                v.encode_value(&mut buf)?;
                84
            }
            Self::FarId(v) => {
                v.encode_value(&mut buf)?;
                108
            }
            Self::QerId(v) => {
                v.encode_value(&mut buf)?;
                109
            }
            Self::Qfi(v) => {
                v.encode_value(&mut buf)?;
                124
            }
            Self::Raw(_) => unreachable!("Raw handled in outer match"),
        };
        Ok((ie_type, buf.freeze()))
    }

    /// The IE type code for this IE.
    pub fn ie_type(&self) -> u16 {
        match self {
            Self::CreatePdr(_) => 1,
            Self::Pdi(_) => 2,
            Self::CreateFar(_) => 3,
            Self::ForwardingParameters(_) => 4,
            Self::CreateUrr(_) => 6,
            Self::CreateQer(_) => 7,
            Self::UpdateQer(_) => 14,
            Self::CreatedPdr(_) => 8,
            Self::Cause(_) => 19,
            Self::SourceInterface(_) => 20,
            Self::FTeid(_) => 21,
            Self::NetworkInstance(_) => 22,
            Self::GateStatus(_) => 25,
            Self::Mbr(_) => 26,
            Self::Gbr(_) => 27,
            Self::Precedence(_) => 29,
            Self::ApplyAction(_) => 44,
            Self::DestinationInterface(_) => 42,
            Self::PdrId(_) => 56,
            Self::FSeid(_) => 57,
            Self::NodeId(_) => 60,
            Self::UrrId(_) => 81,
            Self::UeIpAddress(_) => 93,
            Self::OuterHeaderRemoval(_) => 95,
            Self::RecoveryTimeStamp(_) => 96,
            Self::OuterHeaderCreation(_) => 84,
            Self::FarId(_) => 108,
            Self::QerId(_) => 109,
            Self::Qfi(_) => 124,
            Self::Raw(raw) => raw.ie_type,
        }
    }
}

/// Decode a grouped IE: its value is a sequence of TLV IEs.
fn decode_grouped<T>(value: &[u8], ctx: DecodeContext, depth: usize) -> Result<T, DecodeError>
where
    T: GroupedIe,
{
    if depth.saturating_add(1) > ctx.max_depth {
        let spec_ref = SpecRef::new("3gpp", "TS29244", "8.1.1");
        return Err(DecodeError::new(DecodeErrorCode::DepthExceeded, 0).with_spec_ref(spec_ref));
    }

    T::decode_members(value, ctx, depth.saturating_add(1))
}

/// Encode a grouped IE: encode each member IE in order.
fn encode_grouped<T>(grouped: &T, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError>
where
    T: GroupedIe,
{
    grouped.encode_members(dst, ctx)
}

/// Trait for grouped IEs that contain a sequence of member IEs.
pub trait GroupedIe: Sized {
    /// Decode from the grouped IE value buffer (already past the TLV header).
    fn decode_members(input: &[u8], ctx: DecodeContext, depth: usize) -> Result<Self, DecodeError>;

    /// Encode member IEs into the grouped IE value buffer.
    fn encode_members(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError>;
}
