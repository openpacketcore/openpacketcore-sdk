//! Initial 3GPP Diameter application dictionary skeletons.
//!
//! The `app-*` features record product-neutral application identifiers and
//! placeholder dictionary entries for later AVP/command additions. They do not
//! implement Gx/Rf/S6a/S6b/SWm/SWx business behavior, realm routing, or
//! charging policy.

use crate::base;
use crate::dictionary::{ApplicationDefinition, Dictionary, DictionarySet};
use crate::VendorId;

/// 3GPP vendor identifier used in Diameter Vendor-Specific-Application-Id AVPs.
pub const VENDOR_ID_3GPP: VendorId = VendorId::new(10415);

#[cfg(feature = "app-gx")]
pub use gx::APPLICATION_ID as APPLICATION_ID_GX;
#[cfg(feature = "app-rf")]
pub use rf::APPLICATION_ID as APPLICATION_ID_RF_ACCOUNTING;
#[cfg(feature = "app-s6a")]
pub use s6a::APPLICATION_ID as APPLICATION_ID_S6A_S6D;
#[cfg(feature = "app-s6b")]
pub use s6b::APPLICATION_ID as APPLICATION_ID_S6B;
#[cfg(feature = "app-swm")]
pub use swm::APPLICATION_ID as APPLICATION_ID_SWM;
#[cfg(feature = "app-swx")]
pub use swx::APPLICATION_ID as APPLICATION_ID_SWX;

/// 3GPP Gx application dictionary skeleton.
#[cfg(feature = "app-gx")]
pub mod gx {
    use super::{ApplicationDefinition, VENDOR_ID_3GPP};
    use crate::ApplicationId;
    use opc_protocol::SpecRef;

    /// 3GPP Gx application identifier.
    pub const APPLICATION_ID: ApplicationId = ApplicationId::new(16_777_238);

    /// 3GPP Gx application definition.
    pub const APPLICATION: ApplicationDefinition = ApplicationDefinition::new(
        APPLICATION_ID,
        "3GPP Gx",
        Some(VENDOR_ID_3GPP),
        SpecRef::new("3gpp", "TS29212", "Gx Diameter application"),
    );
}

/// 3GPP Rf accounting application dictionary.
#[cfg(feature = "app-rf")]
pub mod rf;

/// 3GPP S6a/S6d application dictionary skeleton.
#[cfg(feature = "app-s6a")]
pub mod s6a {
    use super::{ApplicationDefinition, VENDOR_ID_3GPP};
    use crate::ApplicationId;
    use opc_protocol::SpecRef;

    /// 3GPP S6a/S6d application identifier.
    pub const APPLICATION_ID: ApplicationId = ApplicationId::new(16_777_251);

    /// 3GPP S6a/S6d application definition.
    pub const APPLICATION: ApplicationDefinition = ApplicationDefinition::new(
        APPLICATION_ID,
        "3GPP S6a/S6d",
        Some(VENDOR_ID_3GPP),
        SpecRef::new("3gpp", "TS29272", "S6a/S6d Diameter application"),
    );
}

/// 3GPP S6b application dictionary skeleton.
#[cfg(feature = "app-s6b")]
pub mod s6b {
    use super::{ApplicationDefinition, VENDOR_ID_3GPP};
    use crate::ApplicationId;
    use opc_protocol::SpecRef;

    /// 3GPP S6b application identifier.
    pub const APPLICATION_ID: ApplicationId = ApplicationId::new(16_777_272);

    /// 3GPP S6b application definition.
    pub const APPLICATION: ApplicationDefinition = ApplicationDefinition::new(
        APPLICATION_ID,
        "3GPP S6b",
        Some(VENDOR_ID_3GPP),
        SpecRef::new("3gpp", "TS29273", "S6b Diameter application"),
    );
}

/// 3GPP SWm Diameter-EAP application dictionary.
#[cfg(feature = "app-swm")]
pub mod swm;

/// 3GPP SWx application dictionary skeleton.
#[cfg(feature = "app-swx")]
pub mod swx {
    use super::{ApplicationDefinition, VENDOR_ID_3GPP};
    use crate::ApplicationId;
    use opc_protocol::SpecRef;

    /// 3GPP SWx application identifier.
    pub const APPLICATION_ID: ApplicationId = ApplicationId::new(16_777_265);

    /// 3GPP SWx application definition.
    pub const APPLICATION: ApplicationDefinition = ApplicationDefinition::new(
        APPLICATION_ID,
        "3GPP SWx",
        Some(VENDOR_ID_3GPP),
        SpecRef::new("3gpp", "TS29273", "SWx Diameter application"),
    );
}

const APP_APPLICATIONS: &[ApplicationDefinition] = &[
    #[cfg(feature = "app-rf")]
    rf::APPLICATION,
    #[cfg(feature = "app-gx")]
    gx::APPLICATION,
    #[cfg(feature = "app-s6a")]
    s6a::APPLICATION,
    #[cfg(feature = "app-s6b")]
    s6b::APPLICATION,
    #[cfg(feature = "app-swm")]
    swm::APPLICATION,
    #[cfg(feature = "app-swx")]
    swx::APPLICATION,
];

const APP_COMMANDS: [crate::dictionary::CommandDefinition; 0] = [];
const APP_AVPS: [crate::dictionary::AvpDefinition; 0] = [];

/// Static initial 3GPP application dictionary scaffold.
pub static APP_DICTIONARY: Dictionary = Dictionary::new(
    "diameter-3gpp-app-scaffold",
    APP_APPLICATIONS,
    &APP_COMMANDS,
    &APP_AVPS,
);

static APP_DICTIONARY_REFS: &[&Dictionary] = &[
    base::dictionary(),
    &APP_DICTIONARY,
    #[cfg(feature = "app-rf")]
    rf::dictionary(),
    #[cfg(feature = "app-swm")]
    swm::dictionary(),
];

/// Dictionary set layering RFC 6733 base metadata before 3GPP application metadata.
pub static APP_DICTIONARIES: DictionarySet<'static> = DictionarySet::new(APP_DICTIONARY_REFS);

/// Return the static initial 3GPP application dictionary scaffold.
pub const fn dictionary() -> &'static Dictionary {
    &APP_DICTIONARY
}

/// Shared encode/decode utilities for application-specific typed helpers.
#[allow(dead_code)]
pub(crate) mod builder_helpers {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str;

    use bytes::{BufMut, BytesMut};
    use opc_protocol::{
        BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, Encode, EncodeContext,
        EncodeError, SpecRef, UnknownIePolicy,
    };

    use crate::dictionary::CommandKind;
    use crate::{
        ApplicationId, AvpCode, AvpHeader, CommandCode, CommandFlags, Header, OwnedMessage, RawAvp,
        VendorId, DIAMETER_HEADER_LEN, MAX_U24,
    };

    /// Append a raw AVP with an explicit header.
    pub(crate) fn append_avp(
        dst: &mut BytesMut,
        header: AvpHeader,
        value: &[u8],
        ctx: EncodeContext,
    ) -> Result<(), EncodeError> {
        let avp = RawAvp {
            header,
            value,
            padding: &[],
        };
        let canonical_ctx = EncodeContext {
            raw_preserving: false,
            ..ctx
        };
        avp.encode(dst, canonical_ctx)
    }

    /// Append a UTF-8 string AVP.
    pub(crate) fn append_utf8_avp(
        dst: &mut BytesMut,
        code: AvpCode,
        value: &str,
        mandatory: bool,
        ctx: EncodeContext,
    ) -> Result<(), EncodeError> {
        append_avp(dst, AvpHeader::ietf(code, mandatory), value.as_bytes(), ctx)
    }

    /// Append an opaque octet-string AVP.
    pub(crate) fn append_octet_string_avp(
        dst: &mut BytesMut,
        code: AvpCode,
        value: &[u8],
        mandatory: bool,
        ctx: EncodeContext,
    ) -> Result<(), EncodeError> {
        append_avp(dst, AvpHeader::ietf(code, mandatory), value, ctx)
    }

    /// Append an unsigned 32-bit AVP.
    pub(crate) fn append_u32_avp(
        dst: &mut BytesMut,
        code: AvpCode,
        value: u32,
        mandatory: bool,
        ctx: EncodeContext,
    ) -> Result<(), EncodeError> {
        append_avp(
            dst,
            AvpHeader::ietf(code, mandatory),
            &value.to_be_bytes(),
            ctx,
        )
    }

    /// Append an unsigned 64-bit AVP.
    pub(crate) fn append_u64_avp(
        dst: &mut BytesMut,
        code: AvpCode,
        value: u64,
        mandatory: bool,
        ctx: EncodeContext,
    ) -> Result<(), EncodeError> {
        append_avp(
            dst,
            AvpHeader::ietf(code, mandatory),
            &value.to_be_bytes(),
            ctx,
        )
    }

    /// Append a vendor-specific octet-string AVP.
    pub(crate) fn append_vendor_octet_string_avp(
        dst: &mut BytesMut,
        code: AvpCode,
        vendor_id: VendorId,
        value: &[u8],
        mandatory: bool,
        ctx: EncodeContext,
    ) -> Result<(), EncodeError> {
        append_avp(
            dst,
            AvpHeader::vendor(code, vendor_id, mandatory),
            value,
            ctx,
        )
    }

    /// Append a vendor-specific unsigned 32-bit AVP.
    pub(crate) fn append_vendor_u32_avp(
        dst: &mut BytesMut,
        code: AvpCode,
        vendor_id: VendorId,
        value: u32,
        mandatory: bool,
        ctx: EncodeContext,
    ) -> Result<(), EncodeError> {
        append_avp(
            dst,
            AvpHeader::vendor(code, vendor_id, mandatory),
            &value.to_be_bytes(),
            ctx,
        )
    }

    /// Encode a Diameter Address value (address-family prefix per RFC 6733 §4.3).
    pub(crate) fn encode_address_value(dst: &mut BytesMut, addr: IpAddr) {
        match addr {
            IpAddr::V4(v4) => {
                dst.put_u16(1);
                dst.put_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                dst.put_u16(2);
                dst.put_slice(&v6.octets());
            }
        }
    }

    /// Build a full Diameter message from raw AVPs.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_message(
        flags: CommandFlags,
        command_code: CommandCode,
        application_id: ApplicationId,
        raw_avps: BytesMut,
        hop_by_hop_identifier: u32,
        end_to_end_identifier: u32,
        ctx: EncodeContext,
        section: &'static str,
    ) -> Result<OwnedMessage, EncodeError> {
        let length = DIAMETER_HEADER_LEN
            .checked_add(raw_avps.len())
            .ok_or_else(EncodeError::length_overflow)?;
        if length > MAX_U24 as usize {
            return Err(
                EncodeError::length_overflow().with_spec_ref(app_spec("ietf", "RFC6733", section))
            );
        }
        ctx.check_capacity(length)?;
        let length = u32::try_from(length).map_err(|_| EncodeError::length_overflow())?;
        Ok(OwnedMessage {
            header: Header::new(
                flags,
                command_code,
                application_id,
                hop_by_hop_identifier,
                end_to_end_identifier,
            )
            .with_length(length),
            raw_avps: raw_avps.freeze(),
        })
    }

    /// Return command flags for an application request.
    pub(crate) const fn app_request_flags() -> CommandFlags {
        CommandFlags::request(true)
    }

    /// Return command flags for an application answer.
    pub(crate) const fn app_answer_flags(error: bool) -> CommandFlags {
        CommandFlags::answer(true, error)
    }

    /// Return true when a result code requires the Diameter E bit on an answer.
    pub(crate) const fn result_code_requires_error_bit(result_code: u32) -> bool {
        result_code >= 3000 && result_code < 4000
    }

    /// Iterate over raw AVPs with absolute offsets and depth awareness.
    pub(crate) fn for_each_avp<F>(
        input: &[u8],
        ctx: DecodeContext,
        base_offset: usize,
        depth: usize,
        mut visit: F,
    ) -> Result<(), DecodeError>
    where
        F: FnMut(usize, RawAvp<'_>) -> Result<(), DecodeError>,
    {
        if depth > ctx.max_depth {
            return Err(
                DecodeError::new(DecodeErrorCode::DepthExceeded, base_offset)
                    .with_spec_ref(app_spec("ietf", "RFC6733", "4")),
            );
        }
        let mut remaining = input;
        let mut relative_offset = 0usize;
        let mut avp_count = 0usize;
        while !remaining.is_empty() {
            let offset = offset_add(base_offset, relative_offset, "4")?;
            avp_count = avp_count.checked_add(1).ok_or_else(|| {
                DecodeError::new(DecodeErrorCode::LengthOverflow, offset)
                    .with_spec_ref(app_spec("ietf", "RFC6733", "4"))
            })?;
            if avp_count > ctx.max_ies {
                return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                    .with_spec_ref(app_spec("ietf", "RFC6733", "4")));
            }
            let before = remaining.len();
            let (next, avp) = match RawAvp::decode(remaining, ctx) {
                Ok(decoded) => decoded,
                Err(error) => return Err(shift_app_error(error, offset)),
            };
            visit(offset, avp)?;
            let consumed = before.checked_sub(next.len()).ok_or_else(|| {
                DecodeError::new(DecodeErrorCode::LengthOverflow, offset)
                    .with_spec_ref(app_spec("ietf", "RFC6733", "4"))
            })?;
            relative_offset = relative_offset.checked_add(consumed).ok_or_else(|| {
                DecodeError::new(DecodeErrorCode::LengthOverflow, offset)
                    .with_spec_ref(app_spec("ietf", "RFC6733", "4"))
            })?;
            remaining = next;
        }
        Ok(())
    }

    /// Parse a four-octet unsigned value.
    pub(crate) fn parse_u32_value(
        value: &[u8],
        offset: usize,
        section: &'static str,
    ) -> Result<u32, DecodeError> {
        match value {
            [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => Err(DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "diameter Unsigned32 or Enumerated AVP value must be four octets",
                },
                offset,
            )
            .with_spec_ref(app_spec("ietf", "RFC6733", section))),
        }
    }

    /// Parse an eight-octet unsigned value.
    pub(crate) fn parse_u64_value(
        value: &[u8],
        offset: usize,
        section: &'static str,
    ) -> Result<u64, DecodeError> {
        match value {
            [a, b, c, d, e, f, g, h] => Ok(u64::from_be_bytes([*a, *b, *c, *d, *e, *f, *g, *h])),
            _ => Err(DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "diameter Unsigned64 AVP value must be eight octets",
                },
                offset,
            )
            .with_spec_ref(app_spec("ietf", "RFC6733", section))),
        }
    }

    /// Parse a UTF-8 string value.
    pub(crate) fn parse_utf8_value(
        value: &[u8],
        offset: usize,
        section: &'static str,
    ) -> Result<String, DecodeError> {
        str::from_utf8(value)
            .map_err(|_| {
                decode_structural_error(
                    "diameter UTF-8 or DiameterIdentity AVP is not valid UTF-8",
                    offset,
                    section,
                )
            })
            .map(|s| s.to_owned())
    }

    /// Parse a non-empty UTF-8 or DiameterIdentity value.
    pub(crate) fn parse_string_value(
        value: &[u8],
        offset: usize,
        section: &'static str,
    ) -> Result<String, DecodeError> {
        let parsed = parse_utf8_value(value, offset, section)?;
        if parsed.is_empty() {
            return Err(decode_structural_error(
                "diameter UTF-8 or DiameterIdentity AVP must not be empty",
                offset,
                section,
            ));
        }
        Ok(parsed)
    }

    /// Parse a Diameter Address value into an IP address.
    pub(crate) fn parse_address_value(
        value: &[u8],
        offset: usize,
        section: &'static str,
    ) -> Result<IpAddr, DecodeError> {
        match value {
            [0, 1, a, b, c, d] => Ok(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
            [0, 2, rest @ ..] if rest.len() == 16 => {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(rest);
                Ok(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            [0, 1, ..] | [0, 2, ..] => Err(DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "diameter Address value length does not match its address family",
                },
                offset,
            )
            .with_spec_ref(app_spec("ietf", "RFC6733", section))),
            [family_hi, family_lo, ..] => {
                let family = u16::from_be_bytes([*family_hi, *family_lo]);
                Err(DecodeError::new(
                    DecodeErrorCode::InvalidEnumValue {
                        field: "Address AddressType",
                        value: u64::from(family),
                    },
                    offset,
                )
                .with_spec_ref(app_spec("ietf", "RFC6733", section)))
            }
            _ => Err(DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason:
                        "diameter Address value must contain an address family and address bytes",
                },
                offset,
            )
            .with_spec_ref(app_spec("ietf", "RFC6733", section))),
        }
    }

    /// Reject duplicate occurrences of a required AVP.
    pub(crate) fn set_once<T>(
        slot: &mut Option<T>,
        value: T,
        offset: usize,
        section: &'static str,
    ) -> Result<(), DecodeError> {
        if slot.is_some() {
            return Err(DecodeError::new(DecodeErrorCode::DuplicateIe, offset)
                .with_spec_ref(app_spec("ietf", "RFC6733", section)));
        }
        *slot = Some(value);
        Ok(())
    }

    /// Require a parsed field to be present.
    pub(crate) fn require_field<T>(
        field: Option<T>,
        reason: &'static str,
        section: &'static str,
    ) -> Result<T, DecodeError> {
        match field {
            Some(value) => Ok(value),
            None => Err(decode_structural_error(
                reason,
                DIAMETER_HEADER_LEN,
                section,
            )),
        }
    }

    /// Either accept or reject an unknown AVP based on policy and the M bit.
    pub(crate) fn handle_unknown_avp(
        ctx: DecodeContext,
        avp: &RawAvp<'_>,
        offset: usize,
        section: &'static str,
    ) -> Result<(), DecodeError> {
        if ctx.unknown_ie_policy == UnknownIePolicy::Reject || avp.header.flags.is_mandatory() {
            Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, offset)
                .with_spec_ref(app_spec("ietf", "RFC6733", section)))
        } else {
            Ok(())
        }
    }

    /// Verify the command header matches an expected application procedure.
    pub(crate) fn ensure_app_header(
        message: &crate::Message<'_>,
        command_code: CommandCode,
        application_id: ApplicationId,
        kind: CommandKind,
        section: &'static str,
    ) -> Result<(), DecodeError> {
        if message.header.command_code != command_code {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidEnumValue {
                    field: "Diameter application command code",
                    value: u64::from(message.header.command_code.get()),
                },
                5,
            )
            .with_spec_ref(app_spec("ietf", "RFC6733", section)));
        }
        if message.header.flags.command_kind() != kind {
            return Err(decode_structural_error(
                "diameter application request/answer flag does not match parser",
                4,
                section,
            ));
        }
        if message.header.application_id != application_id {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidEnumValue {
                    field: "Diameter application identifier",
                    value: u64::from(message.header.application_id.get()),
                },
                8,
            )
            .with_spec_ref(app_spec("ietf", "RFC6733", section)));
        }
        Ok(())
    }

    pub(crate) fn offset_add(
        base: usize,
        delta: usize,
        section: &'static str,
    ) -> Result<usize, DecodeError> {
        base.checked_add(delta).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, base)
                .with_spec_ref(app_spec("ietf", "RFC6733", section))
        })
    }

    fn shift_app_error(error: DecodeError, base_offset: usize) -> DecodeError {
        let offset = match base_offset.checked_add(error.offset()) {
            Some(offset) => offset,
            None => return DecodeError::new(DecodeErrorCode::LengthOverflow, base_offset),
        };
        let shifted = DecodeError::new(error.code().clone(), offset);
        match error.spec_ref().cloned() {
            Some(spec_ref) => shifted.with_spec_ref(spec_ref),
            None => shifted,
        }
    }

    fn decode_structural_error(
        reason: &'static str,
        offset: usize,
        section: &'static str,
    ) -> DecodeError {
        DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
            .with_spec_ref(app_spec("ietf", "RFC6733", section))
    }

    pub(crate) fn app_spec(
        organization: &'static str,
        spec: &'static str,
        section: &'static str,
    ) -> SpecRef {
        SpecRef::new(organization, spec, section)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "app-gx")]
    fn app_dictionary_contains_gx_application() {
        let gx = APP_DICTIONARIES.find_application(APPLICATION_ID_GX);
        assert!(matches!(gx, Some(definition) if definition.name() == "3GPP Gx"));
    }

    #[test]
    #[cfg(feature = "app-rf")]
    fn app_dictionary_contains_rf_application() {
        let rf = APP_DICTIONARIES.find_application(APPLICATION_ID_RF_ACCOUNTING);
        assert!(
            matches!(rf, Some(definition) if definition.name() == "3GPP Rf accounting over Diameter accounting")
        );
    }

    #[test]
    #[cfg(feature = "app-s6a")]
    fn app_dictionary_contains_s6a_application() {
        let s6a = APP_DICTIONARIES.find_application(APPLICATION_ID_S6A_S6D);
        assert!(matches!(s6a, Some(definition) if definition.name() == "3GPP S6a/S6d"));
    }

    #[test]
    #[cfg(feature = "app-s6b")]
    fn app_dictionary_contains_s6b_application() {
        let s6b = APP_DICTIONARIES.find_application(APPLICATION_ID_S6B);
        assert!(matches!(s6b, Some(definition) if definition.name() == "3GPP S6b"));
    }

    #[test]
    #[cfg(feature = "app-swm")]
    fn app_dictionary_contains_swm_application() {
        let swm = APP_DICTIONARIES.find_application(APPLICATION_ID_SWM);
        assert!(matches!(swm, Some(definition) if definition.name() == "3GPP SWm"));
    }

    #[test]
    #[cfg(feature = "app-swx")]
    fn app_dictionary_contains_swx_application() {
        let swx = APP_DICTIONARIES.find_application(APPLICATION_ID_SWX);
        assert!(matches!(swx, Some(definition) if definition.name() == "3GPP SWx"));
    }
}
