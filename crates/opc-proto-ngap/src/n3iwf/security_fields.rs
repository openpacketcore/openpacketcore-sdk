//! Bounded user-plane security indications and peer-reported results.
//! These values do not select, install or prove cryptographic protection.
//! Downlink-rate IE extensions and future ASN.1 roots remain unsupported.
use super::setup_fields::{Reader, Writer};
use super::*;

/// A peer's root user-plane protection requirement.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProtectionRequirement {
    /// The peer requires this protection.
    Required,
    /// The peer prefers this protection.
    Preferred,
    /// The peer indicates this protection is not needed.
    NotNeeded,
}
redacted!(ProtectionRequirement);
impl ProtectionRequirement {
    /// Require one of the three ASN.1 root indices.
    pub fn new(value: u8) -> Result<Self, DecodeError> {
        match value {
            0 => Ok(Self::Required),
            1 => Ok(Self::Preferred),
            2 => Ok(Self::NotNeeded),
            _ => Err(invalid("protection requirement root index")),
        }
    }
    /// Explicit ASN.1 root index, without applying the peer's policy.
    pub const fn value(self) -> u8 {
        match self {
            Self::Required => 0,
            Self::Preferred => 1,
            Self::NotNeeded => 2,
        }
    }
}

/// Maximum integrity-protected uplink rate reported by the peer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MaximumIntegrityRate {
    /// The 64 kbit/s root value.
    Bitrate64Kbps,
    /// The maximum UE rate, without inferring a numeric rate here.
    MaximumUeRate,
}
redacted!(MaximumIntegrityRate);
impl MaximumIntegrityRate {
    /// Require one of the two ASN.1 root indices.
    pub fn new(value: u8) -> Result<Self, DecodeError> {
        match value {
            0 => Ok(Self::Bitrate64Kbps),
            1 => Ok(Self::MaximumUeRate),
            _ => Err(invalid("integrity rate root index")),
        }
    }
    /// Explicit ASN.1 root index.
    pub const fn value(self) -> u8 {
        match self {
            Self::Bitrate64Kbps => 0,
            Self::MaximumUeRate => 1,
        }
    }
}

/// Root security requirements and their conditional uplink integrity rate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecurityIndication {
    integrity: ProtectionRequirement,
    confidentiality: ProtectionRequirement,
    uplink_rate: Option<MaximumIntegrityRate>,
}
redacted!(SecurityIndication);
impl SecurityIndication {
    /// TS 38.413 9.3.1.27 requires the UL rate for Required or Preferred
    /// integrity. A supplied rate is also retained with NotNeeded.
    pub fn new(
        integrity: ProtectionRequirement,
        confidentiality: ProtectionRequirement,
        uplink_rate: Option<MaximumIntegrityRate>,
    ) -> Result<Self, DecodeError> {
        if integrity != ProtectionRequirement::NotNeeded && uplink_rate.is_none() {
            return Err(invalid("missing conditional integrity rate ul"));
        }
        Ok(Self {
            integrity,
            confidentiality,
            uplink_rate,
        })
    }
    /// Explicit integrity requirement, without installing protection.
    pub const fn integrity(self) -> ProtectionRequirement {
        self.integrity
    }
    /// Explicit confidentiality requirement, without installing protection.
    pub const fn confidentiality(self) -> ProtectionRequirement {
        self.confidentiality
    }
    /// Explicit optional UL rate. No separate DL rate extension is admitted.
    pub const fn uplink_rate(self) -> Option<MaximumIntegrityRate> {
        self.uplink_rate
    }
    /// Encode the independently qualified two-octet generated root.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity(2, ctx)?;
        let integrity = match self.integrity {
            ProtectionRequirement::Required => asn::IntegrityProtectionIndication::required,
            ProtectionRequirement::Preferred => asn::IntegrityProtectionIndication::preferred,
            ProtectionRequirement::NotNeeded => asn::IntegrityProtectionIndication::not_needed,
        };
        let confidentiality = match self.confidentiality {
            ProtectionRequirement::Required => asn::ConfidentialityProtectionIndication::required,
            ProtectionRequirement::Preferred => asn::ConfidentialityProtectionIndication::preferred,
            ProtectionRequirement::NotNeeded => {
                asn::ConfidentialityProtectionIndication::not_needed
            }
        };
        let rate = self.uplink_rate.map(|rate| match rate {
            MaximumIntegrityRate::Bitrate64Kbps => {
                asn::MaximumIntegrityProtectedDataRate::bitrate64kbs
            }
            MaximumIntegrityRate::MaximumUeRate => {
                asn::MaximumIntegrityProtectedDataRate::maximum_UE_rate
            }
        });
        encode_leaf(
            &asn::SecurityIndication::new(integrity, confidentiality, rate, None),
            ctx,
        )
    }
    /// Decode at depth two, rejecting extensions, invalid roots, nonzero
    /// padding and trailing bytes before enforcing the conditional UL rate.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 2)?;
        let mut reader = Reader::new(input, ctx);
        reader.flags(1)?;
        let has_rate = reader.bits(1)? != 0;
        reader.flags(1)?;
        reader.flags(1)?;
        let integrity = ProtectionRequirement::new(reader.bits(2)? as u8)?;
        reader.flags(1)?;
        let confidentiality = ProtectionRequirement::new(reader.bits(2)? as u8)?;
        let rate = if has_rate {
            reader.flags(1)?;
            Some(MaximumIntegrityRate::new(reader.bits(1)? as u8)?)
        } else {
            None
        };
        reader.finish()?;
        Self::new(integrity, confidentiality, rate)
    }
}

/// A peer's integrity and confidentiality reports, without cryptographic proof.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecurityResult {
    integrity_performed: bool,
    confidentiality_performed: bool,
}
redacted!(SecurityResult);
impl SecurityResult {
    /// Bind explicit peer reports; neither value proves installed protection.
    pub const fn new(integrity_performed: bool, confidentiality_performed: bool) -> Self {
        Self {
            integrity_performed,
            confidentiality_performed,
        }
    }
    /// Whether the peer reported that integrity protection was performed.
    pub const fn integrity_performed(self) -> bool {
        self.integrity_performed
    }
    /// Whether the peer reported that confidentiality protection was performed.
    pub const fn confidentiality_performed(self) -> bool {
        self.confidentiality_performed
    }
    /// Encode the independently qualified one-octet generated root.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity(1, ctx)?;
        let integrity = if self.integrity_performed {
            asn::IntegrityProtectionResult::performed
        } else {
            asn::IntegrityProtectionResult::not_performed
        };
        let confidentiality = if self.confidentiality_performed {
            asn::ConfidentialityProtectionResult::performed
        } else {
            asn::ConfidentialityProtectionResult::not_performed
        };
        encode_leaf(
            &asn::SecurityResult::new(integrity, confidentiality, None),
            ctx,
        )
    }
    /// Decode at depth two, with exact padding and no extension payloads.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 2)?;
        let mut reader = Reader::new(input, ctx);
        let result = Self::read(&mut reader)?;
        reader.finish()?;
        Ok(result)
    }
    // A contained SEQUENCE starts at the parent's current bit offset; leaf
    // octet padding must not be inserted before a following failed-flow list.
    pub(super) fn write(self, writer: &mut Writer) -> Result<(), EncodeError> {
        writer.bits(0, 2)?;
        writer.bits(u16::from(!self.integrity_performed), 2)?;
        writer.bits(u16::from(!self.confidentiality_performed), 2)
    }
    pub(super) fn read(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        reader.flags(2)?;
        reader.flags(1)?;
        let integrity = reader.bits(1)? == 0;
        reader.flags(1)?;
        let confidentiality = reader.bits(1)? == 0;
        Ok(Self::new(integrity, confidentiality))
    }
}

/// The root network-instance value, without selecting a transport resource.
/// Common Network Instance precedence requires separate field qualification.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NetworkInstance(u16);
redacted!(NetworkInstance);
impl NetworkInstance {
    /// Require the root range 1..=256. Extension integers are unsupported.
    pub fn new(value: u16) -> Result<Self, DecodeError> {
        if !(1..=256).contains(&value) {
            return Err(invalid("network instance root range"));
        }
        Ok(Self(value))
    }
    /// Explicit root value, without resolving it to a local network.
    pub const fn value(self) -> u16 {
        self.0
    }
    /// Encode the independently qualified two-octet generated root.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity(2, ctx)?;
        encode_leaf(&asn::NetworkInstance(self.0.into()), ctx)
    }
    /// Decode at depth one, requiring zero alignment padding and exact length.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 1)?;
        let mut reader = Reader::new(input, ctx);
        reader.flags(1)?;
        reader.align()?;
        let value = Self::new(reader.bits(8)? + 1)?;
        reader.finish()?;
        Ok(value)
    }
}
