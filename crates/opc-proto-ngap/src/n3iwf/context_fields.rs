//! Root fields shared by Initial Context Setup and other admitted outcomes.
//!
//! These values confer no subscription, slice or cryptographic authority.
//! TS 29.413 marks UE Security Capabilities receiver-ignored for N3IWF Initial
//! Context Setup: its construction helper does not imply receive processing.
use super::setup_fields::{Reader, Size, Writer};
use super::*;
use opc_types::Snssai;

pub use super::setup_fields::Guami;

/// Root Allowed NSSAI, containing one through eight shared SDK slice IDs.
/// Admission validates the wire shape; the AMF/caller owns authorization.
#[derive(Clone, PartialEq, Eq)]
pub struct AllowedNssai(Vec<Snssai>);
redacted!(AllowedNssai);
impl AllowedNssai {
    /// Require the ASN.1 root count, without selecting/authorizing slices.
    pub fn new(values: Vec<Snssai>) -> Result<Self, DecodeError> {
        if values.is_empty() || values.len() > 8 {
            return Err(invalid("allowed nssai root count"));
        }
        Ok(Self(values))
    }
    /// Explicit access to the advertised values.
    pub fn values(&self) -> &[Snssai] {
        &self.0
    }
    /// Encode the root list with exact-size preflight. The generated SEQUENCE
    /// OF encoder does not preserve offsets when optional SD octets align.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let mut size = Size(3);
        for slice in &self.0 {
            size.0 += 2;
            size.snssai(slice);
        }
        capacity(size.bytes(), ctx)?;
        let mut writer = Writer::new(size.bytes());
        writer.bits((self.0.len() - 1) as u16, 3)?;
        for slice in &self.0 {
            writer.bits(0, 2)?;
            writer.snssai(slice)?;
        }
        writer.finish()
    }
    /// Decode the bounded root list, rejecting item/S-NSSAI extensions before
    /// allocation. Count is bounded by `max_ies`; depth four is required.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 4)?;
        let mut reader = Reader::new(input, ctx);
        let count = reader.count(3, 8, 13)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            reader.flags(2)?;
            values.push(reader.snssai()?);
        }
        reader.finish()?;
        Ok(Self(values))
    }
}

/// Root Partially Allowed NSSAI with one through eight slice identifiers.
/// This is distinct from Allowed NSSAI and confers no slice authorization.
#[derive(Clone, PartialEq, Eq)]
pub struct PartiallyAllowedNssai(AllowedNssai);
redacted!(PartiallyAllowedNssai);
impl PartiallyAllowedNssai {
    /// Require the root list count. The enclosing message checks the combined
    /// count and disjointness with its separate Allowed NSSAI list.
    pub fn new(values: Vec<Snssai>) -> Result<Self, DecodeError> {
        AllowedNssai::new(values).map(Self)
    }
    /// Explicit access to the advertised values, preserving their order.
    pub fn values(&self) -> &[Snssai] {
        self.0.values()
    }
    /// Encode the root list. Its item layout matches Allowed NSSAI in the
    /// pinned Release 18 ASN.1; independent complete-message vectors qualify
    /// reuse of that layout, including optional SD alignment.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        self.0.encode(ctx)
    }
    /// Decode the bounded root list with depth four and `max_ies` limits.
    /// Extensions, trailing bytes and invalid padding fail explicitly.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        AllowedNssai::decode(input, ctx).map(Self)
    }
}

pub(super) fn validate_slice_lists(
    allowed: Option<&AllowedNssai>,
    partial: Option<&PartiallyAllowedNssai>,
) -> Result<(), DecodeError> {
    if let Some(partial) = partial {
        let allowed = allowed.map(AllowedNssai::values).unwrap_or_default();
        if allowed.len() + partial.values().len() > 8 {
            return Err(invalid(
                "combined allowed and partially allowed nssai count",
            ));
        }
        if partial.values().iter().any(|slice| allowed.contains(slice)) {
            return Err(invalid("overlapping allowed and partially allowed nssai"));
        }
    }
    Ok(())
}

/// Four explicit 16-bit root algorithm masks for UE Security Capabilities
/// construction. Bit 15 is the first ASN.1 bit. No algorithm is selected here.
///
/// TS 29.413 requires N3IWF Initial Context Setup to check mandatory presence
/// while ignoring received contents. This helper provides construction only;
/// whole-message admission is a separate boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecurityAlgorithmMasks {
    nr_encryption: u16,
    nr_integrity: u16,
    eutra_encryption: u16,
    eutra_integrity: u16,
}
redacted!(SecurityAlgorithmMasks);
impl SecurityAlgorithmMasks {
    /// Bind caller-provided masks, without interpreting or selecting algorithms.
    pub const fn new(
        nr_encryption: u16,
        nr_integrity: u16,
        eutra_encryption: u16,
        eutra_integrity: u16,
    ) -> Self {
        Self {
            nr_encryption,
            nr_integrity,
            eutra_encryption,
            eutra_integrity,
        }
    }
    /// Explicit access to NR encryption bits.
    pub const fn nr_encryption(self) -> u16 {
        self.nr_encryption
    }
    /// Explicit access to NR integrity bits.
    pub const fn nr_integrity(self) -> u16 {
        self.nr_integrity
    }
    /// Explicit access to E-UTRA encryption bits.
    pub const fn eutra_encryption(self) -> u16 {
        self.eutra_encryption
    }
    /// Explicit access to E-UTRA integrity bits.
    pub const fn eutra_integrity(self) -> u16 {
        self.eutra_integrity
    }
    /// Encode the generated root SEQUENCE and four fixed-size masks.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity(9, ctx)?;
        let bits = |value: u16| rasn::types::BitString::from_slice(&value.to_be_bytes());
        encode_leaf(
            &asn::UESecurityCapabilities::new(
                asn::NRencryptionAlgorithms(bits(self.nr_encryption)),
                asn::NRintegrityProtectionAlgorithms(bits(self.nr_integrity)),
                asn::EUTRAencryptionAlgorithms(bits(self.eutra_encryption)),
                asn::EUTRAintegrityProtectionAlgorithms(bits(self.eutra_integrity)),
                None,
            ),
            ctx,
        )
    }
}
