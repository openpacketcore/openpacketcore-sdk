//! Typed FQ-CSID values (TS 29.274 V19.6.0, clause 8.62).
//!
//! Decode a [`RawIe`] after the generic IE layer has checked framing. The
//! four-bit count permits at most fifteen CSIDs. Counts other than one are
//! restricted to Delete PDN Connection Set Requests by clause 8.62; enclosing
//! procedure policy remains caller-owned. Address allocation, global unicast
//! suitability and Node-ID/CSID uniqueness are also the creating node's duties.
//!
//! Unknown trailing octets are ignored for this extendable IE (clause 7.7.7).
//! This decoder does not evaluate the header spare nibble (clause 7.7.8).
//! Generic Strict and ProcedureAware framing rejects nonzero header spares
//! before this value decoder. Canonical output carries zero spares; retain the
//! original raw IE for byte-exact forwarding.
//!
//! @spec 3GPP TS29274 V19.6.0 8.62, 7.7.7, 7.7.8
//! @req REQ-3GPP-TS29274-R19-FQ-CSID-001
//!
//! ```
//! use opc_proto_gtpv2c::{FqCsid, FqCsidNodeId};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let value = FqCsid::new(FqCsidNodeId::Ipv4([192, 0, 2, 1]), &[7])?;
//! let ie = value.to_raw_ie(2)?;
//! assert_eq!(ie.ie_type, 132);
//! assert_eq!(FqCsid::decode_from_raw(&ie.as_borrowed())?, Some(value));
//! # Ok(())
//! # }
//! ```

use std::fmt;

use bytes::{BufMut, BytesMut};

use super::{CauseValue, OwnedRawIe, RawIe};

/// FQ-CSID IE type assigned by TS 29.274 clause 8.62.
pub const IE_TYPE_FQ_CSID: u8 = 132;
/// Maximum CSID count representable by Figure 8.62-1's four-bit field.
pub const MAX_FQ_CSID_COUNT: usize = 15;

/// A value-free local construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FqCsidBuildError {
    /// A count exceeded its four-bit representation.
    TooManyCsids,
    /// MCC exceeded three decimal digits.
    InvalidMcc,
    /// MNC exceeded three decimal digits.
    InvalidMnc,
    /// The operator-assigned ID exceeded twelve bits.
    InvalidOperatorId,
    /// The enclosing IE instance exceeded four bits.
    InvalidInstance,
}

impl FqCsidBuildError {
    /// Stable machine-readable label that contains no supplied value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TooManyCsids => "gtpv2c_fq_csid_too_many_csids",
            Self::InvalidMcc => "gtpv2c_fq_csid_invalid_mcc",
            Self::InvalidMnc => "gtpv2c_fq_csid_invalid_mnc",
            Self::InvalidOperatorId => "gtpv2c_fq_csid_invalid_operator_id",
            Self::InvalidInstance => "gtpv2c_fq_csid_invalid_instance",
        }
    }
}

impl fmt::Display for FqCsidBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::error::Error for FqCsidBuildError {}

/// A value-free failure in an FQ-CSID's known fields.
///
/// Generic IE framing failures are returned by the existing raw IE decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FqCsidDecodeError {
    /// The Node-ID Type / CSID count octet was absent.
    MissingTypeAndCount,
    /// The selected Node-ID representation was incomplete.
    TruncatedNodeId,
    /// The count required more complete CSIDs than the value contained.
    TruncatedCsids,
    /// The Node-ID Type was reserved in clause 8.62.
    ReservedNodeIdType,
    /// The binary MCC/MNC field exceeded the two three-digit components.
    InvalidMccMnc,
}

impl FqCsidDecodeError {
    /// Stable machine-readable label that contains no received value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingTypeAndCount => "gtpv2c_fq_csid_missing_type_and_count",
            Self::TruncatedNodeId => "gtpv2c_fq_csid_truncated_node_id",
            Self::TruncatedCsids => "gtpv2c_fq_csid_truncated_csids",
            Self::ReservedNodeIdType => "gtpv2c_fq_csid_reserved_node_id_type",
            Self::InvalidMccMnc => "gtpv2c_fq_csid_invalid_mcc_mnc",
        }
    }

    /// Cause for a mandatory or verifiable conditional IE in a Request.
    ///
    /// This is the clause 7.7.7 / 7.7.8 value-error classification, not a
    /// response plan. The enclosing procedure must decide presence rules,
    /// optional-IE discard, Response notification, and Echo special handling.
    #[must_use]
    pub const fn mandatory_request_cause(self) -> CauseValue {
        match self {
            Self::MissingTypeAndCount | Self::TruncatedNodeId | Self::TruncatedCsids => {
                CauseValue::InvalidLength
            }
            Self::ReservedNodeIdType | Self::InvalidMccMnc => CauseValue::MandatoryIeIncorrect,
        }
    }
}

impl fmt::Display for FqCsidDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::error::Error for FqCsidDecodeError {}

/// The binary MCC/MNC-plus-operator-ID Node-ID form of clause 8.62.
///
/// This form carries no separate two-/three-digit MNC-length indication.
/// Private fields preserve the decimal and twelve-bit construction bounds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FqCsidMccMncNodeId {
    mcc: u16,
    mnc: u16,
    operator_id: u16,
}

impl FqCsidMccMncNodeId {
    /// Validate numeric MCC/MNC components and the operator-assigned ID.
    ///
    /// # Errors
    /// Returns a value-free error if MCC or MNC exceeds 999, or ID exceeds 4095.
    pub fn new(mcc: u16, mnc: u16, operator_id: u16) -> Result<Self, FqCsidBuildError> {
        if mcc > 999 {
            return Err(FqCsidBuildError::InvalidMcc);
        }
        if mnc > 999 {
            return Err(FqCsidBuildError::InvalidMnc);
        }
        if operator_id > 4095 {
            return Err(FqCsidBuildError::InvalidOperatorId);
        }
        Ok(Self {
            mcc,
            mnc,
            operator_id,
        })
    }
    /// Numeric Mobile Country Code, before binary packing.
    #[must_use]
    pub const fn mcc(self) -> u16 {
        self.mcc
    }
    /// Numeric Mobile Network Code, before binary packing.
    #[must_use]
    pub const fn mnc(self) -> u16 {
        self.mnc
    }
    /// Twelve-bit operator-assigned Node-ID component.
    #[must_use]
    pub const fn operator_id(self) -> u16 {
        self.operator_id
    }
}

impl fmt::Debug for FqCsidMccMncNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FqCsidMccMncNodeId(<redacted>)")
    }
}

/// Supported Node-ID representations from the extensible clause 8.62 registry.
///
/// Address fields are fixed-width wire values. The creating node must select
/// a suitable global unicast address; this codec does not query allocation,
/// routing or operator-assigned uniqueness.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FqCsidNodeId {
    /// Node-ID Type 0: four address octets.
    Ipv4([u8; 4]),
    /// Node-ID Type 1: sixteen address octets.
    Ipv6([u8; 16]),
    /// Node-ID Type 2: binary decimal components plus an operator-assigned ID.
    MccMnc(FqCsidMccMncNodeId),
}

impl FqCsidNodeId {
    const fn wire_type(self) -> u8 {
        match self {
            Self::Ipv4(_) => 0,
            Self::Ipv6(_) => 1,
            Self::MccMnc(_) => 2,
        }
    }
}
impl fmt::Debug for FqCsidNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FqCsidNodeId")
            .field("type", &self.wire_type())
            .finish_non_exhaustive()
    }
}

/// A bounded, validated FQ-CSID value beside the generic IE framing layer.
///
/// All unsigned CSID values and counts 0 through 15 are representable. Clause
/// 8.62 permits counts other than one only in Delete PDN Connection Set
/// Requests; a caller composing another procedure must enforce that context.
/// No received spare fields or unknown extension octets become typed values.
#[derive(Clone, PartialEq, Eq)]
pub struct FqCsid {
    node_id: FqCsidNodeId,
    csids: [u16; MAX_FQ_CSID_COUNT],
    count: u8,
}

impl FqCsid {
    /// Construct a value with at most fifteen CSIDs.
    ///
    /// # Errors
    /// Returns [`FqCsidBuildError::TooManyCsids`] for a count above fifteen.
    pub fn new(node_id: FqCsidNodeId, csids: &[u16]) -> Result<Self, FqCsidBuildError> {
        let count = u8::try_from(csids.len()).map_err(|_| FqCsidBuildError::TooManyCsids)?;
        if csids.len() > MAX_FQ_CSID_COUNT {
            return Err(FqCsidBuildError::TooManyCsids);
        }
        let mut stored = [0; MAX_FQ_CSID_COUNT];
        stored[..csids.len()].copy_from_slice(csids);
        Ok(Self {
            node_id,
            csids: stored,
            count,
        })
    }

    /// Return the supported Node-ID value.
    #[must_use]
    pub const fn node_id(&self) -> &FqCsidNodeId {
        &self.node_id
    }
    /// Return exactly the advertised CSIDs, without padding or extension data.
    #[must_use]
    pub fn csids(&self) -> &[u16] {
        &self.csids[..usize::from(self.count)]
    }

    /// Decode a value whose TLIV framing was handled by the generic IE layer.
    ///
    /// Unrelated IE types return `Ok(None)` without interpreting their values.
    /// Unknown extension octets are ignored. This decoder does not evaluate
    /// the header spare nibble; generic Strict and ProcedureAware framing
    /// rejects nonzero header spares before this value decoder.
    ///
    /// # Errors
    /// Returns value-free errors for truncated known fields, a reserved Node-ID
    /// Type or an invalid binary MCC/MNC component.
    pub fn decode_from_raw(raw: &RawIe<'_>) -> Result<Option<Self>, FqCsidDecodeError> {
        if raw.ie_type != IE_TYPE_FQ_CSID {
            return Ok(None);
        }
        let (&flags, rest) = raw
            .value
            .split_first()
            .ok_or(FqCsidDecodeError::MissingTypeAndCount)?;
        let kind = flags >> 4;
        let node_len = match kind {
            0 | 2 => 4,
            1 => 16,
            _ => return Err(FqCsidDecodeError::ReservedNodeIdType),
        };
        let node = rest
            .get(..node_len)
            .ok_or(FqCsidDecodeError::TruncatedNodeId)?;
        let count = usize::from(flags & 15);
        let encoded_csids = rest
            .get(node_len..node_len + count * 2)
            .ok_or(FqCsidDecodeError::TruncatedCsids)?;
        let node_id = match kind {
            0 => {
                let mut address = [0; 4];
                address.copy_from_slice(node);
                FqCsidNodeId::Ipv4(address)
            }
            1 => {
                let mut address = [0; 16];
                address.copy_from_slice(node);
                FqCsidNodeId::Ipv6(address)
            }
            _ => {
                let packed = u32::from_be_bytes([node[0], node[1], node[2], node[3]]);
                let decimal = packed >> 12;
                let mcc =
                    u16::try_from(decimal / 1000).map_err(|_| FqCsidDecodeError::InvalidMccMnc)?;
                let mnc =
                    u16::try_from(decimal % 1000).map_err(|_| FqCsidDecodeError::InvalidMccMnc)?;
                let operator_id =
                    u16::try_from(packed & 4095).map_err(|_| FqCsidDecodeError::InvalidMccMnc)?;
                let value = FqCsidMccMncNodeId::new(mcc, mnc, operator_id)
                    .map_err(|_| FqCsidDecodeError::InvalidMccMnc)?;
                FqCsidNodeId::MccMnc(value)
            }
        };
        let mut csids = [0; MAX_FQ_CSID_COUNT];
        let (pairs, _) = encoded_csids.as_chunks::<2>();
        for (slot, pair) in csids.iter_mut().zip(pairs) {
            *slot = u16::from_be_bytes(*pair);
        }
        Ok(Some(Self {
            node_id,
            csids,
            count: flags & 15,
        }))
    }

    /// Build an owned raw IE with zero spare bits and only known value octets.
    ///
    /// The existing [`OwnedRawIe::encode`] remains the framing authority.
    ///
    /// # Errors
    /// Returns [`FqCsidBuildError::InvalidInstance`] above instance fifteen.
    pub fn to_raw_ie(&self, instance: u8) -> Result<OwnedRawIe, FqCsidBuildError> {
        if instance > 15 {
            return Err(FqCsidBuildError::InvalidInstance);
        }
        let mut value = BytesMut::with_capacity(17 + MAX_FQ_CSID_COUNT * 2);
        value.put_u8((self.node_id.wire_type() << 4) | self.count);
        match self.node_id {
            FqCsidNodeId::Ipv4(address) => value.extend_from_slice(&address),
            FqCsidNodeId::Ipv6(address) => value.extend_from_slice(&address),
            FqCsidNodeId::MccMnc(id) => value.put_u32(
                ((u32::from(id.mcc) * 1000 + u32::from(id.mnc)) << 12) | u32::from(id.operator_id),
            ),
        }
        for csid in self.csids() {
            value.put_u16(*csid);
        }
        Ok(OwnedRawIe {
            ie_type: IE_TYPE_FQ_CSID,
            instance,
            spare: 0,
            value: value.freeze(),
        })
    }
}

impl fmt::Debug for FqCsid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FqCsid")
            .field("node_id", &self.node_id)
            .field("csid_count", &self.count)
            .finish_non_exhaustive()
    }
}
