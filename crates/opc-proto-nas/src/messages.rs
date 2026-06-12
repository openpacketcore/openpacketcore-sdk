//! Parsed 5GMM message bodies (TS 24.501 §8.2).
//!
//! v1 adds IE-level decoding for Registration Request and Registration Accept:
//! mandatory fields are structured, optional IEs are iterated and preserved
//! raw so that decode → encode is byte-exact even when the decoder does not
//! understand an IE's semantics.

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, Encode, EncodeContext,
    EncodeError, OwnedDecode, SpecRef,
};

use crate::identity::MobileIdentity;

fn spec_ref() -> SpecRef {
    SpecRef::new("3gpp", "TS24501", "8.2")
}

fn message_spec_ref(section: &'static str) -> SpecRef {
    SpecRef::new("3gpp", "TS24501", section)
}

/// 5GS registration-type values (TS 24.501 §9.11.3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationType {
    /// Initial registration (001).
    InitialRegistration = 0x01,
    /// Mobility registration updating (010).
    MobilityRegistrationUpdating = 0x02,
    /// Periodic registration updating (011).
    PeriodicRegistrationUpdating = 0x03,
    /// Emergency registration (100).
    EmergencyRegistration = 0x04,
}

impl RegistrationType {
    /// Map the 3-bit value to the enum; `None` for reserved codes.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value & 0x07 {
            0x01 => Self::InitialRegistration,
            0x02 => Self::MobilityRegistrationUpdating,
            0x03 => Self::PeriodicRegistrationUpdating,
            0x04 => Self::EmergencyRegistration,
            _ => return None,
        })
    }
}

/// 5GS registration-result values (TS 24.501 §9.11.3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationResult {
    /// 3GPP access (001).
    Access3gpp = 0x01,
    /// Non-3GPP access (010).
    AccessNon3gpp = 0x02,
    /// 3GPP access and non-3GPP access (011).
    AccessBoth = 0x03,
}

impl RegistrationResult {
    /// Map the 3-bit value to the enum; `None` for reserved codes.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value & 0x07 {
            0x01 => Self::Access3gpp,
            0x02 => Self::AccessNon3gpp,
            0x03 => Self::AccessBoth,
            _ => return None,
        })
    }
}

/// ngKSI carried in the first half-octet of a Registration Request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NasKeySetIdentifier {
    /// Key set identifier value (0–7, bits 5–7).
    pub value: u8,
    /// `true` when no native 5G NAS security context is available (bit 8).
    pub no_key_available: bool,
}

/// A raw optional IE, preserving its original bytes for byte-exact re-encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalIe {
    /// Information-element identifier.
    pub iei: u8,
    /// Value bytes excluding IEI and length octets.
    ///
    /// For type-1 half-octet IEs this is empty because the value is part of
    /// the same octet as the IEI.
    pub value: Bytes,
    /// Full original IE bytes (iei + length + value, or the single type-1
    /// octet). Re-encoding writes this verbatim.
    pub raw: Bytes,
}

/// Format of an optional IE, used to locate its length field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OptionalIeFormat {
    /// Type 1: single octet, IEI in high nibble, value in low nibble.
    Type1,
    /// Type 3: IEI followed by a fixed-length value of `usize` octets.
    Type3(usize),
    /// Type 4: IEI followed by a one-octet length.
    Type4,
    /// Type 6 (extended): IEI followed by a two-octet length.
    Type6,
}

fn optional_ie_format(iei: u8) -> OptionalIeFormat {
    match iei {
        // Known TLV-E IEs used by Registration Request/Accept.
        0x72 | 0x75 | 0x77 | 0x78 | 0x79 | 0x7A | 0x7B | 0x7C => OptionalIeFormat::Type6,
        // Known type-3 TV IEs (value length after the IEI octet).
        0x52 => OptionalIeFormat::Type3(6), // Last visited registered TAI
        // Known type-4 TLV IEs.
        0x10 | 0x11 | 0x15 | 0x17 | 0x18 | 0x21 | 0x25 | 0x26 | 0x27 | 0x2B | 0x2E | 0x2F
        | 0x31 | 0x34 | 0x40 | 0x4A | 0x50 | 0x54 | 0x5D | 0x5E => OptionalIeFormat::Type4,
        // Type-1 half-octet IEIs have the high nibble in the range A-F.
        _ if (iei >> 4) >= 0x0A => OptionalIeFormat::Type1,
        // Extended-length IEIs occupy the 0x70-0x7F range.
        _ if (0x70..=0x7F).contains(&iei) => OptionalIeFormat::Type6,
        // Default: assume type-4 TLV. Unknown type-1/type-3 IEs require a
        // registry entry to round-trip correctly; this is documented in
        // CONFORMANCE.md.
        _ => OptionalIeFormat::Type4,
    }
}

fn decode_optional_ies(input: &[u8], ctx: DecodeContext) -> DecodeResult<'_, Vec<OptionalIe>> {
    let mut out = Vec::new();
    let mut rest = input;
    let mut offset = 0usize;

    while !rest.is_empty() {
        if out.len() >= ctx.max_ies {
            return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                .with_spec_ref(spec_ref()));
        }
        let iei = rest[0];
        let format = optional_ie_format(iei);
        let ie = match format {
            OptionalIeFormat::Type1 => {
                let raw = Bytes::copy_from_slice(&rest[..1]);
                rest = &rest[1..];
                offset += 1;
                OptionalIe {
                    iei,
                    value: Bytes::new(),
                    raw,
                }
            }
            OptionalIeFormat::Type3(value_len) => {
                let total = 1usize.saturating_add(value_len);
                if rest.len() < total {
                    return Err(DecodeError::new(DecodeErrorCode::Truncated, offset)
                        .with_spec_ref(spec_ref()));
                }
                let raw = Bytes::copy_from_slice(&rest[..total]);
                let value = Bytes::copy_from_slice(&rest[1..total]);
                rest = &rest[total..];
                offset += total;
                OptionalIe { iei, value, raw }
            }
            OptionalIeFormat::Type4 => {
                if rest.len() < 2 {
                    return Err(DecodeError::new(DecodeErrorCode::Truncated, offset)
                        .with_spec_ref(spec_ref()));
                }
                let value_len = usize::from(rest[1]);
                let total = 2usize.saturating_add(value_len);
                if rest.len() < total {
                    return Err(DecodeError::new(DecodeErrorCode::Truncated, offset)
                        .with_spec_ref(spec_ref()));
                }
                let raw = Bytes::copy_from_slice(&rest[..total]);
                let value = Bytes::copy_from_slice(&rest[2..total]);
                rest = &rest[total..];
                offset += total;
                OptionalIe { iei, value, raw }
            }
            OptionalIeFormat::Type6 => {
                if rest.len() < 3 {
                    return Err(DecodeError::new(DecodeErrorCode::Truncated, offset)
                        .with_spec_ref(spec_ref()));
                }
                let value_len = usize::from(u16::from_be_bytes([rest[1], rest[2]]));
                let total = 3usize.saturating_add(value_len);
                if rest.len() < total {
                    return Err(DecodeError::new(DecodeErrorCode::Truncated, offset)
                        .with_spec_ref(spec_ref()));
                }
                let raw = Bytes::copy_from_slice(&rest[..total]);
                let value = Bytes::copy_from_slice(&rest[3..total]);
                rest = &rest[total..];
                offset += total;
                OptionalIe { iei, value, raw }
            }
        };
        out.push(ie);
    }

    Ok((&[], out))
}

/// Decoded Registration Request body (TS 24.501 §8.2.6).
///
/// The first octet carries the 5GS registration type (low nibble) and ngKSI
/// (high nibble). The mandatory 5GS mobile identity follows as an LV-E
/// (two-octet length + value). All remaining bytes are optional IEs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationRequest {
    /// 5GS registration type.
    pub registration_type: RegistrationType,
    /// Follow-on request pending bit (bit 4 of the first body octet).
    pub follow_on_request: bool,
    /// NAS key set identifier.
    pub ng_ksi: NasKeySetIdentifier,
    /// Decoded 5GS mobile identity.
    pub mobile_identity: MobileIdentity,
    /// Original first body octet (registration type + ngKSI).
    pub raw_first_octet: u8,
    /// Original LV-E bytes for the mobile identity (length + value).
    pub raw_mobile_identity_lv: Bytes,
    /// Optional IEs in message order, raw-preserved.
    pub optional_ies: Vec<OptionalIe>,
}

impl RegistrationRequest {
    /// Decode a Registration Request from its body bytes (everything after the
    /// 3-octet plain 5GMM header).
    pub fn decode_body(input: &[u8], ctx: DecodeContext) -> DecodeResult<'_, Self> {
        if input.len() > ctx.max_message_len {
            return Err(DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 0)
                .with_spec_ref(message_spec_ref("8.2.6")));
        }
        if input.len() < 4 {
            // First octet + 2-octet LV-E length + at least one value octet.
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0)
                .with_spec_ref(message_spec_ref("8.2.6")));
        }

        let raw_first_octet = input[0];
        let registration_type =
            RegistrationType::from_u8(raw_first_octet & 0x07).ok_or_else(|| {
                DecodeError::new(
                    DecodeErrorCode::InvalidEnumValue {
                        field: "5gs_registration_type",
                        value: u64::from(raw_first_octet & 0x07),
                    },
                    0,
                )
                .with_spec_ref(message_spec_ref("9.11.3.7"))
            })?;
        let follow_on_request = (raw_first_octet & 0x08) != 0;
        let ng_ksi = NasKeySetIdentifier {
            value: (raw_first_octet >> 4) & 0x07,
            no_key_available: (raw_first_octet & 0x80) != 0,
        };

        let mi_len = usize::from(u16::from_be_bytes([input[1], input[2]]));
        let mi_end = 3usize.saturating_add(mi_len);
        if mi_end > input.len() {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 1)
                .with_spec_ref(message_spec_ref("9.11.3.4")));
        }
        if mi_len < 6 {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "5GS mobile identity length below minimum",
                },
                1,
            )
            .with_spec_ref(message_spec_ref("9.11.3.4")));
        }

        let raw_mobile_identity_lv = Bytes::copy_from_slice(&input[1..mi_end]);
        let mobile_identity = MobileIdentity::decode(&input[3..mi_end]).map_err(|e| {
            DecodeError::new(e.code().clone(), 3).with_spec_ref(
                e.spec_ref()
                    .cloned()
                    .unwrap_or_else(|| message_spec_ref("9.11.3.4")),
            )
        })?;

        let (_, optional_ies) = decode_optional_ies(&input[mi_end..], ctx)?;

        Ok((
            &[],
            Self {
                registration_type,
                follow_on_request,
                ng_ksi,
                mobile_identity,
                raw_first_octet,
                raw_mobile_identity_lv,
                optional_ies,
            },
        ))
    }
}

impl<'a> BorrowDecode<'a> for RegistrationRequest {
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        Self::decode_body(input, ctx)
    }
}

impl OwnedDecode for RegistrationRequest {
    fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (_, msg) = Self::decode(&input, ctx)?;
        Ok(msg)
    }
}

impl Encode for RegistrationRequest {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let len = self.wire_len(ctx)?;
        ctx.check_capacity(len)?;
        dst.reserve(len);
        dst.put_u8(self.raw_first_octet);
        dst.extend_from_slice(&self.raw_mobile_identity_lv);
        for ie in &self.optional_ies {
            dst.extend_from_slice(&ie.raw);
        }
        Ok(())
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        let mut len = 1usize.saturating_add(self.raw_mobile_identity_lv.len());
        for ie in &self.optional_ies {
            len = len.saturating_add(ie.raw.len());
        }
        Ok(len)
    }
}

/// Decoded Registration Accept body (TS 24.501 §8.2.7).
///
/// The mandatory 5GS registration result is an LV IE (one-octet length +
/// one-octet value). All remaining bytes are optional IEs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationAccept {
    /// 5GS registration result.
    pub registration_result: RegistrationResult,
    /// Original LV bytes for the registration result.
    pub raw_registration_result_lv: Bytes,
    /// Optional IEs in message order, raw-preserved.
    pub optional_ies: Vec<OptionalIe>,
}

impl RegistrationAccept {
    /// Decode a Registration Accept from its body bytes.
    pub fn decode_body(input: &[u8], ctx: DecodeContext) -> DecodeResult<'_, Self> {
        if input.len() > ctx.max_message_len {
            return Err(DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 0)
                .with_spec_ref(message_spec_ref("8.2.7")));
        }
        if input.len() < 2 {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0)
                .with_spec_ref(message_spec_ref("8.2.7")));
        }

        let result_len = usize::from(input[0]);
        let result_end = 1usize.saturating_add(result_len);
        if result_end > input.len() {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0)
                .with_spec_ref(message_spec_ref("9.11.3.6")));
        }
        if result_len != 1 {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "5GS registration result length must be 1",
                },
                0,
            )
            .with_spec_ref(message_spec_ref("9.11.3.6")));
        }

        let raw_registration_result_lv = Bytes::copy_from_slice(&input[0..result_end]);
        let registration_result =
            RegistrationResult::from_u8(input[result_len]).ok_or_else(|| {
                DecodeError::new(
                    DecodeErrorCode::InvalidEnumValue {
                        field: "5gs_registration_result",
                        value: u64::from(input[result_len]),
                    },
                    result_len,
                )
                .with_spec_ref(message_spec_ref("9.11.3.6"))
            })?;

        let (_, optional_ies) = decode_optional_ies(&input[result_end..], ctx)?;

        Ok((
            &[],
            Self {
                registration_result,
                raw_registration_result_lv,
                optional_ies,
            },
        ))
    }
}

impl<'a> BorrowDecode<'a> for RegistrationAccept {
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        Self::decode_body(input, ctx)
    }
}

impl OwnedDecode for RegistrationAccept {
    fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (_, msg) = Self::decode(&input, ctx)?;
        Ok(msg)
    }
}

impl Encode for RegistrationAccept {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let len = self.wire_len(ctx)?;
        ctx.check_capacity(len)?;
        dst.reserve(len);
        dst.extend_from_slice(&self.raw_registration_result_lv);
        for ie in &self.optional_ies {
            dst.extend_from_slice(&ie.raw);
        }
        Ok(())
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        let mut len = self.raw_registration_result_lv.len();
        for ie in &self.optional_ies {
            len = len.saturating_add(ie.raw.len());
        }
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use opc_protocol::{BorrowDecode, Encode};

    fn round_trip_body<T>(bytes: &[u8])
    where
        for<'a> T: BorrowDecode<'a> + Encode,
    {
        let (_, msg) = T::decode(bytes, DecodeContext::default()).unwrap();
        let mut buf = BytesMut::new();
        msg.encode(&mut buf, EncodeContext::default()).unwrap();
        assert_eq!(&buf[..], bytes, "{}", std::any::type_name::<T>());
    }

    #[test]
    fn registration_request_minimal() {
        // 0x01 -> ngKSI=0, registration type=initial, FOR=0.
        // Mobile identity: LV-E length 7, SUCI type 1, SUPI format 0, PLMN
        // 0x02F839, routing indicator 0x21 0xF3, null scheme, pki 0, scheme
        // output 0x13 0x57.
        let body: &[u8] = &[
            0x01, // reg type + ngKSI
            0x00, 0x0A, // LV-E length
            0x01, 0x02, 0xF8, 0x39, 0x21, 0xF3, 0x00, 0x00, 0x13, 0x57,
        ];
        let (_, req) = RegistrationRequest::decode_body(body, DecodeContext::default()).unwrap();
        assert_eq!(req.registration_type, RegistrationType::InitialRegistration);
        assert!(!req.follow_on_request);
        assert_eq!(req.ng_ksi.value, 0);
        assert!(!req.ng_ksi.no_key_available);
        assert_eq!(
            req.mobile_identity.identity_type,
            crate::identity::IdentityType::Suci
        );
        assert!(req.optional_ies.is_empty());
        round_trip_body::<RegistrationRequest>(body);
    }

    #[test]
    fn registration_request_with_optional_ies() {
        // Minimal body plus a TLV IE (IEI 0x2E, length 2, value 0x80 0x00)
        // and a type-1 IE (IEI 0xB0).
        let body: &[u8] = &[
            0x01, 0x00, 0x0A, 0x01, 0x02, 0xF8, 0x39, 0x21, 0xF3, 0x00, 0x00, 0x13, 0x57, 0x2E,
            0x02, 0x80, 0x00, 0xB0,
        ];
        let (_, req) = RegistrationRequest::decode_body(body, DecodeContext::default()).unwrap();
        assert_eq!(req.optional_ies.len(), 2);
        assert_eq!(req.optional_ies[0].iei, 0x2E);
        assert_eq!(&req.optional_ies[0].value[..], &[0x80, 0x00]);
        assert_eq!(req.optional_ies[1].iei, 0xB0);
        round_trip_body::<RegistrationRequest>(body);
    }

    #[test]
    fn registration_accept_minimal() {
        let body: &[u8] = &[0x01, 0x01]; // LV length=1, value=1 (3GPP access)
        let (_, acc) = RegistrationAccept::decode_body(body, DecodeContext::default()).unwrap();
        assert_eq!(acc.registration_result, RegistrationResult::Access3gpp);
        assert!(acc.optional_ies.is_empty());
        round_trip_body::<RegistrationAccept>(body);
    }

    #[test]
    fn registration_accept_with_guti() {
        // 5GS registration result + 5G-GUTI TLV-E (IEI 0x77, length 13, 13
        // content octets).
        let guti_content = &[
            0xF2u8, 0x02, 0xF8, 0x39, 0x11, 0x01, 0x41, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        let mut body = vec![0x01, 0x01];
        body.push(0x77);
        body.extend_from_slice(&(guti_content.len() as u16).to_be_bytes());
        body.extend_from_slice(guti_content);

        let (_, acc) = RegistrationAccept::decode_body(&body, DecodeContext::default()).unwrap();
        assert_eq!(acc.registration_result, RegistrationResult::Access3gpp);
        assert_eq!(acc.optional_ies.len(), 1);
        assert_eq!(acc.optional_ies[0].iei, 0x77);
        assert_eq!(&acc.optional_ies[0].value[..], guti_content);
        round_trip_body::<RegistrationAccept>(&body);
    }

    #[test]
    fn registration_request_truncated_identity_length_rejected() {
        let body: &[u8] = &[0x01, 0x00, 0x10, 0x01];
        assert!(RegistrationRequest::decode_body(body, DecodeContext::default()).is_err());
    }
}
