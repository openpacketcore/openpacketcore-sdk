//! Typed subscriber authorization values carried by SWm DEA.
//!
//! These values are syntax-checked independently from the request. The SWm
//! request/answer boundary applies the request-conditioned authorization rules
//! before an answer can be originated or accepted as a correlated response.

use bytes::BytesMut;
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, DuplicateIePolicy, EncodeContext, EncodeError,
    SpecRef, UnknownIePolicy,
};
use std::{collections::HashSet, error::Error, fmt};

use super::{
    builder_helpers, DiameterEapRetention, SwmAdditionalAvp, AVP_3GPP_CHARGING_CHARACTERISTICS,
    AVP_APN_OI_REPLACEMENT, AVP_CORE_NETWORK_RESTRICTIONS, AVP_MPS_PRIORITY, AVP_UE_USAGE_TYPE,
    VENDOR_ID_3GPP,
};
use crate::apps::subscription_id::{self, SubscriptionIdType, AVP_SUBSCRIPTION_ID};
use crate::avp::dictionary::{Redacted, Sensitive};
use crate::{AvpHeader, RawAvp};

const MAX_APN_OI_TEXT_LEN: usize = 253;
const MAX_DOMAIN_LABEL_LEN: usize = 63;
const CORE_NETWORK_ASSIGNED_MASK: u32 = 1 << 1;
const MPS_ASSIGNED_MASK: u32 = (1 << 0) | (1 << 1) | (1 << 2);

/// A validated APN-OI-Replacement domain name.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmApnOiReplacement(Redacted<String>);

impl SwmApnOiReplacement {
    /// Validate and retain an APN-OI-Replacement presentation string.
    ///
    /// TS 29.272 requires the case-insensitive suffix
    /// `mncNNN.mccNNN.gprs`, with exactly three digits in each PLMN label.
    /// Optional preceding labels follow TS 23.003 and RFC 1035/1123: ASCII
    /// letters, digits, and interior hyphens, with labels no longer than 63
    /// octets.
    pub fn new(value: impl Into<String>) -> Result<Self, SwmDeaAuthorizationValueError> {
        let value = value.into();
        if !valid_apn_oi_replacement(&value) {
            return Err(SwmDeaAuthorizationValueError::InvalidApnOiReplacement);
        }
        Ok(Self(Redacted::from(value)))
    }

    /// Return the validated domain name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl fmt::Debug for SwmApnOiReplacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmApnOiReplacement(<redacted>)")
    }
}

/// A canonical international E.164 number for the SWm Subscription-Id.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmE164Number(Sensitive<String>);

impl SwmE164Number {
    /// Validate one international E.164 number.
    ///
    /// The wire form is the international number itself: one through fifteen
    /// decimal digits beginning with 1 through 9. Dialling prefixes,
    /// presentation characters, and zero-prefixed dummy values are not part of
    /// the E.164 number.
    pub fn new(value: impl Into<String>) -> Result<Self, SwmDeaAuthorizationValueError> {
        let value = Sensitive::from(value.into());
        if value.is_empty()
            || value.len() > subscription_id::MAX_E164_DIGITS
            || !value.as_bytes().iter().all(u8::is_ascii_digit)
            || !value
                .as_bytes()
                .first()
                .is_some_and(|digit| matches!(*digit, b'1'..=b'9'))
        {
            return Err(SwmDeaAuthorizationValueError::InvalidE164Number);
        }
        Ok(Self(value))
    }

    /// Return the validated decimal digits.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl zeroize::Zeroize for SwmE164Number {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl zeroize::ZeroizeOnDrop for SwmE164Number {}

impl fmt::Debug for SwmE164Number {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmE164Number(<redacted>)")
    }
}

/// The RFC 4006 Subscription-Id form allowed by TS 29.273 on SWm DEA.
///
/// SWm restricts the group to `END_USER_E164` carrying the available MSISDN.
/// Parser-retained unknown optional children remain sealed and are exposed
/// only as a count so their potentially sensitive values cannot leak.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmSubscriptionId {
    e164: SwmE164Number,
    additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmSubscriptionId {
    /// Construct the SWm E.164/MSISDN Subscription-Id form.
    #[must_use]
    pub fn e164(value: SwmE164Number) -> Self {
        Self {
            e164: value,
            additional_avps: Vec::new(),
        }
    }

    /// Return the validated E.164 value.
    #[must_use]
    pub const fn value(&self) -> &SwmE164Number {
        &self.e164
    }

    /// Return the number of parser-retained optional grouped extensions.
    #[must_use]
    pub fn additional_avp_count(&self) -> usize {
        self.additional_avps.len()
    }
}

impl fmt::Debug for SwmSubscriptionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmSubscriptionId")
            .field("kind", &"e164")
            .field("value", &"<redacted>")
            .field("additional_avp_count", &self.additional_avps.len())
            .finish()
    }
}

/// Two-octet 3GPP charging characteristics carried as four hexadecimal UTF-8
/// characters by TS 29.061.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SwmChargingCharacteristics([u8; 2]);

impl SwmChargingCharacteristics {
    /// Construct charging characteristics from the normative two octets.
    #[must_use]
    pub const fn from_octets(octets: [u8; 2]) -> Self {
        Self(octets)
    }

    /// Return the two charging-characteristics octets.
    #[must_use]
    pub const fn octets(self) -> [u8; 2] {
        self.0
    }
}

impl fmt::Debug for SwmChargingCharacteristics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmChargingCharacteristics(<redacted>)")
    }
}

/// UE usage characteristics used for Dedicated Core Network selection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SwmUeUsageType(u8);

impl SwmUeUsageType {
    /// Construct an assigned 0..=255 UE-Usage-Type value.
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Return the wire value.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Return whether this is in TS 29.272's operator-specific range.
    #[must_use]
    pub const fn is_operator_specific(self) -> bool {
        self.0 >= 128
    }
}

impl fmt::Debug for SwmUeUsageType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmUeUsageType(<redacted>)")
    }
}

/// Assigned Core-Network-Restrictions bits from TS 29.272.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct SwmCoreNetworkRestrictions {
    five_gc_not_allowed: bool,
}

impl fmt::Debug for SwmCoreNetworkRestrictions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmCoreNetworkRestrictions(<redacted>)")
    }
}

impl SwmCoreNetworkRestrictions {
    /// No assigned core-network restriction is set.
    pub const NONE: Self = Self {
        five_gc_not_allowed: false,
    };

    /// Construct a restriction that disallows 5GC access.
    #[must_use]
    pub const fn five_gc_not_allowed() -> Self {
        Self {
            five_gc_not_allowed: true,
        }
    }

    /// Return whether 5GC access is disallowed.
    #[must_use]
    pub const fn disallows_five_gc(self) -> bool {
        self.five_gc_not_allowed
    }

    /// Return the canonical assigned-bit wire mask.
    #[must_use]
    pub const fn bits(self) -> u32 {
        if self.five_gc_not_allowed {
            CORE_NETWORK_ASSIGNED_MASK
        } else {
            0
        }
    }

    const fn from_wire_bits(bits: u32) -> Self {
        // TS 29.272 says deprecated bit 0 and unassigned bits are discarded.
        Self {
            five_gc_not_allowed: bits & CORE_NETWORK_ASSIGNED_MASK != 0,
        }
    }
}

/// Assigned MPS-Priority subscription bits from TS 29.272.
///
/// The type retains the complete assigned mask. A SWm DEA may carry the AVP
/// only when [`Self::has_eps_priority`] is true, as required by TS 29.273.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct SwmMpsPriority {
    cs: bool,
    eps: bool,
    messaging: bool,
}

impl fmt::Debug for SwmMpsPriority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmMpsPriority(<redacted>)")
    }
}

impl SwmMpsPriority {
    /// Construct an empty MPS priority mask.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            cs: false,
            eps: false,
            messaging: false,
        }
    }

    /// Set or clear the CS-domain priority bit.
    #[must_use]
    pub const fn with_cs_priority(mut self, enabled: bool) -> Self {
        self.cs = enabled;
        self
    }

    /// Set or clear the EPS-domain priority bit consumed by SWm.
    #[must_use]
    pub const fn with_eps_priority(mut self, enabled: bool) -> Self {
        self.eps = enabled;
        self
    }

    /// Set or clear the messaging priority bit.
    #[must_use]
    pub const fn with_messaging_priority(mut self, enabled: bool) -> Self {
        self.messaging = enabled;
        self
    }

    /// Return whether CS priority is enabled.
    #[must_use]
    pub const fn has_cs_priority(self) -> bool {
        self.cs
    }

    /// Return whether EPS priority is enabled.
    #[must_use]
    pub const fn has_eps_priority(self) -> bool {
        self.eps
    }

    /// Return whether messaging priority is enabled.
    #[must_use]
    pub const fn has_messaging_priority(self) -> bool {
        self.messaging
    }

    /// Return the canonical assigned-bit wire mask.
    #[must_use]
    pub const fn bits(self) -> u32 {
        (self.cs as u32) | ((self.eps as u32) << 1) | ((self.messaging as u32) << 2)
    }

    const fn from_wire_bits(bits: u32) -> Self {
        // TS 29.272 requires receivers to discard unassigned bits.
        let assigned = bits & MPS_ASSIGNED_MASK;
        Self {
            cs: assigned & (1 << 0) != 0,
            eps: assigned & (1 << 1) != 0,
            messaging: assigned & (1 << 2) != 0,
        }
    }
}

/// Optional top-level subscriber authorization facts carried by one SWm DEA.
///
/// The bundle is intentionally non-exhaustive and uses checked typed values,
/// allowing future standard fields without creating another collection of
/// loosely related raw scalars on `SwmDiameterEapAnswer`.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SwmDeaSubscriberAuthorization {
    pub(super) apn_oi_replacement: Option<SwmApnOiReplacement>,
    pub(super) subscription_id: Option<SwmSubscriptionId>,
    pub(super) charging_characteristics: Option<SwmChargingCharacteristics>,
    pub(super) ue_usage_type: Option<SwmUeUsageType>,
    pub(super) core_network_restrictions: Option<SwmCoreNetworkRestrictions>,
    pub(super) mps_priority: Option<SwmMpsPriority>,
}

impl SwmDeaSubscriberAuthorization {
    /// Construct an empty authorization bundle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            apn_oi_replacement: None,
            subscription_id: None,
            charging_characteristics: None,
            ue_usage_type: None,
            core_network_restrictions: None,
            mps_priority: None,
        }
    }

    /// Set the APN-OI-Replacement value.
    #[must_use]
    pub fn with_apn_oi_replacement(mut self, value: SwmApnOiReplacement) -> Self {
        self.apn_oi_replacement = Some(value);
        self
    }

    /// Set the E.164/MSISDN Subscription-Id.
    #[must_use]
    pub fn with_subscription_id(mut self, value: SwmSubscriptionId) -> Self {
        self.subscription_id = Some(value);
        self
    }

    /// Set the 3GPP charging characteristics.
    #[must_use]
    pub const fn with_charging_characteristics(
        mut self,
        value: SwmChargingCharacteristics,
    ) -> Self {
        self.charging_characteristics = Some(value);
        self
    }

    /// Set the UE usage type.
    #[must_use]
    pub const fn with_ue_usage_type(mut self, value: SwmUeUsageType) -> Self {
        self.ue_usage_type = Some(value);
        self
    }

    /// Set the core-network restriction mask.
    #[must_use]
    pub const fn with_core_network_restrictions(
        mut self,
        value: SwmCoreNetworkRestrictions,
    ) -> Self {
        self.core_network_restrictions = Some(value);
        self
    }

    /// Set the MPS priority mask.
    ///
    /// A containing SWm DEA is valid only when `value` has
    /// `MPS-EPS-Priority` set.
    #[must_use]
    pub const fn with_mps_priority(mut self, value: SwmMpsPriority) -> Self {
        self.mps_priority = Some(value);
        self
    }

    /// Return the APN-OI-Replacement value.
    #[must_use]
    pub const fn apn_oi_replacement(&self) -> Option<&SwmApnOiReplacement> {
        self.apn_oi_replacement.as_ref()
    }

    /// Return the E.164/MSISDN Subscription-Id.
    #[must_use]
    pub const fn subscription_id(&self) -> Option<&SwmSubscriptionId> {
        self.subscription_id.as_ref()
    }

    /// Return the charging characteristics.
    #[must_use]
    pub const fn charging_characteristics(&self) -> Option<SwmChargingCharacteristics> {
        self.charging_characteristics
    }

    /// Return the UE usage type.
    #[must_use]
    pub const fn ue_usage_type(&self) -> Option<SwmUeUsageType> {
        self.ue_usage_type
    }

    /// Return the core-network restrictions.
    #[must_use]
    pub const fn core_network_restrictions(&self) -> Option<SwmCoreNetworkRestrictions> {
        self.core_network_restrictions
    }

    /// Return the MPS priority mask.
    #[must_use]
    pub const fn mps_priority(&self) -> Option<SwmMpsPriority> {
        self.mps_priority
    }

    /// Return whether no subscriber authorization value is present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.apn_oi_replacement.is_none()
            && self.subscription_id.is_none()
            && self.charging_characteristics.is_none()
            && self.ue_usage_type.is_none()
            && self.core_network_restrictions.is_none()
            && self.mps_priority.is_none()
    }
}

impl fmt::Debug for SwmDeaSubscriberAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmDeaSubscriberAuthorization")
            .field(
                "apn_oi_replacement_present",
                &self.apn_oi_replacement.is_some(),
            )
            .field("subscription_id_present", &self.subscription_id.is_some())
            .field(
                "charging_characteristics_present",
                &self.charging_characteristics.is_some(),
            )
            .field("ue_usage_type_present", &self.ue_usage_type.is_some())
            .field(
                "core_network_restrictions_present",
                &self.core_network_restrictions.is_some(),
            )
            .field("mps_priority_present", &self.mps_priority.is_some())
            .finish()
    }
}

/// Redaction-safe validation failure for a public DEA authorization value.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwmDeaAuthorizationValueError {
    /// APN-OI-Replacement is not a valid bounded domain presentation.
    InvalidApnOiReplacement,
    /// The E.164 number is empty, zero-prefixed, too long, or non-decimal.
    InvalidE164Number,
}

impl SwmDeaAuthorizationValueError {
    /// Return a stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidApnOiReplacement => "swm_dea_invalid_apn_oi_replacement",
            Self::InvalidE164Number => "swm_dea_invalid_e164_number",
        }
    }
}

impl fmt::Display for SwmDeaAuthorizationValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SwmDeaAuthorizationValueError {}

pub(super) fn append_authorization(
    dst: &mut BytesMut,
    authorization: &SwmDeaSubscriberAuthorization,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    if let Some(value) = authorization.apn_oi_replacement.as_ref() {
        append_apn_oi_replacement_avp(dst, value, ctx)?;
    }
    if let Some(value) = authorization.subscription_id.as_ref() {
        let mut grouped = BytesMut::new();
        subscription_id::append_subscription_id_value_fields(
            &mut grouped,
            SubscriptionIdType::EndUserE164,
            value.e164.as_str(),
            ctx,
        )?;
        for extension in &value.additional_avps {
            extension.append_to(&mut grouped, ctx)?;
        }
        builder_helpers::append_avp(
            dst,
            AvpHeader::ietf(AVP_SUBSCRIPTION_ID, true),
            &grouped,
            ctx,
        )?;
    }
    if let Some(value) = authorization.charging_characteristics {
        append_charging_characteristics_avp(dst, value, ctx)?;
    }
    if let Some(value) = authorization.ue_usage_type {
        builder_helpers::append_vendor_u32_avp(
            dst,
            AVP_UE_USAGE_TYPE,
            VENDOR_ID_3GPP,
            u32::from(value.value()),
            false,
            ctx,
        )?;
    }
    if let Some(value) = authorization.core_network_restrictions {
        builder_helpers::append_vendor_u32_avp(
            dst,
            AVP_CORE_NETWORK_RESTRICTIONS,
            VENDOR_ID_3GPP,
            value.bits(),
            false,
            ctx,
        )?;
    }
    if let Some(value) = authorization.mps_priority {
        builder_helpers::append_vendor_u32_avp(
            dst,
            AVP_MPS_PRIORITY,
            VENDOR_ID_3GPP,
            value.bits(),
            false,
            ctx,
        )?;
    }
    Ok(())
}

pub(super) fn append_apn_oi_replacement_avp(
    dst: &mut BytesMut,
    value: &SwmApnOiReplacement,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_APN_OI_REPLACEMENT, VENDOR_ID_3GPP, true),
        value.as_str().as_bytes(),
        ctx,
    )
}

pub(super) fn append_charging_characteristics_avp(
    dst: &mut BytesMut,
    value: SwmChargingCharacteristics,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let octets = value.octets();
    let encoded = [
        encode_hex_nibble(octets[0] >> 4),
        encode_hex_nibble(octets[0] & 0x0f),
        encode_hex_nibble(octets[1] >> 4),
        encode_hex_nibble(octets[1] & 0x0f),
    ];
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_3GPP_CHARGING_CHARACTERISTICS, VENDOR_ID_3GPP, false),
        &encoded,
        ctx,
    )
}

pub(super) fn parse_apn_oi_replacement(
    avp: &RawAvp<'_>,
    offset: usize,
    value_offset: usize,
) -> Result<SwmApnOiReplacement, DecodeError> {
    validate_3gpp_flags(avp, offset, None, false, "TS29272", "7.3.32")?;
    if avp.value.is_empty() || avp.value.len() > MAX_APN_OI_TEXT_LEN || !avp.value.is_ascii() {
        return Err(decode_value_error(
            "APN-OI-Replacement has invalid domain syntax",
            value_offset,
            "3gpp",
            "TS29272",
            "7.3.32",
        ));
    }
    let value = std::str::from_utf8(avp.value).map_err(|_| {
        decode_value_error(
            "APN-OI-Replacement has invalid domain syntax",
            value_offset,
            "3gpp",
            "TS29272",
            "7.3.32",
        )
    })?;
    if !valid_apn_oi_replacement(value) {
        return Err(decode_value_error(
            "APN-OI-Replacement has invalid domain syntax",
            value_offset,
            "3gpp",
            "TS29272",
            "7.3.32",
        ));
    }
    Ok(SwmApnOiReplacement(Redacted::from(value.to_owned())))
}

pub(super) fn parse_subscription_id(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    offset: usize,
    value_offset: usize,
    retention: &mut DiameterEapRetention,
) -> Result<SwmSubscriptionId, DecodeError> {
    validate_base_subscription_flags(&avp.header, offset)?;
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    let parsed = subscription_id::parse_subscription_id_with_unknown(
        avp.value,
        ctx,
        value_offset,
        1,
        true,
        |child_offset, child| {
            builder_helpers::handle_unknown_avp(ctx, child, child_offset, "8.46")?;
            if ctx.duplicate_ie_policy == DuplicateIePolicy::Reject
                && !additional_keys.insert(child.header.key())
            {
                return Err(DecodeError::new(DecodeErrorCode::DuplicateIe, child_offset)
                    .with_spec_ref(SpecRef::new("ietf", "RFC4006", "8.46")));
            }
            if ctx.unknown_ie_policy == UnknownIePolicy::Preserve {
                retention.account(child, child_offset, "8.46", ctx)?;
                additional_avps.push(SwmAdditionalAvp::from_raw_exact(child));
            }
            Ok(())
        },
    )?;
    if parsed.subscription_id_type != SubscriptionIdType::EndUserE164 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidEnumValue {
                field: "SWm Subscription-Id-Type",
                value: u64::from(parsed.subscription_id_type.value()),
            },
            value_offset,
        )
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "7.1.2.1.1/2")));
    }
    let e164 = SwmE164Number::new(parsed.subscription_id_data.into_inner()).map_err(|_| {
        decode_value_error(
            "SWm Subscription-Id-Data is not an international E.164 number",
            value_offset,
            "ietf",
            "RFC4006",
            "8.48",
        )
    })?;
    Ok(SwmSubscriptionId {
        e164,
        additional_avps,
    })
}

pub(super) fn parse_charging_characteristics(
    avp: &RawAvp<'_>,
    offset: usize,
    value_offset: usize,
) -> Result<SwmChargingCharacteristics, DecodeError> {
    validate_3gpp_flags(avp, offset, None, true, "TS29061", "16.4.7")?;
    if avp.value.len() != 4 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidLength {
                reason: "3GPP-Charging-Characteristics must contain four hexadecimal characters",
            },
            value_offset,
        )
        .with_spec_ref(SpecRef::new("3gpp", "TS29061", "16.4.7")));
    }
    let high = decode_hex_pair(avp.value[0], avp.value[1]).ok_or_else(|| {
        decode_value_error(
            "3GPP-Charging-Characteristics contains non-hexadecimal syntax",
            value_offset,
            "3gpp",
            "TS29061",
            "16.4.7",
        )
    })?;
    let low = decode_hex_pair(avp.value[2], avp.value[3]).ok_or_else(|| {
        decode_value_error(
            "3GPP-Charging-Characteristics contains non-hexadecimal syntax",
            value_offset,
            "3gpp",
            "TS29061",
            "16.4.7",
        )
    })?;
    Ok(SwmChargingCharacteristics::from_octets([high, low]))
}

pub(super) fn parse_ue_usage_type(
    avp: &RawAvp<'_>,
    offset: usize,
    value_offset: usize,
) -> Result<SwmUeUsageType, DecodeError> {
    validate_3gpp_flags(avp, offset, None, false, "TS29272", "7.3.202")?;
    let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.3.202")?;
    let value = u8::try_from(value).map_err(|_| {
        DecodeError::new(
            DecodeErrorCode::InvalidEnumValue {
                field: "UE-Usage-Type",
                value: u64::from(value),
            },
            value_offset,
        )
        .with_spec_ref(SpecRef::new("3gpp", "TS29272", "7.3.202"))
    })?;
    Ok(SwmUeUsageType::new(value))
}

pub(super) fn parse_core_network_restrictions(
    avp: &RawAvp<'_>,
    offset: usize,
    value_offset: usize,
) -> Result<SwmCoreNetworkRestrictions, DecodeError> {
    validate_3gpp_flags(avp, offset, None, false, "TS29272", "7.3.230")?;
    let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.3.230")?;
    Ok(SwmCoreNetworkRestrictions::from_wire_bits(value))
}

pub(super) fn parse_mps_priority(
    avp: &RawAvp<'_>,
    offset: usize,
    value_offset: usize,
) -> Result<SwmMpsPriority, DecodeError> {
    validate_3gpp_flags(avp, offset, None, false, "TS29272", "7.3.131")?;
    let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.3.131")?;
    Ok(SwmMpsPriority::from_wire_bits(value))
}

pub(super) fn validate_top_level_identity(
    header: &AvpHeader,
    offset: usize,
) -> Result<(), DecodeError> {
    let valid = if header.code == AVP_SUBSCRIPTION_ID {
        header.vendor_id.is_none()
    } else if matches!(
        header.code,
        AVP_APN_OI_REPLACEMENT
            | AVP_3GPP_CHARGING_CHARACTERISTICS
            | AVP_UE_USAGE_TYPE
            | AVP_CORE_NETWORK_RESTRICTIONS
            | AVP_MPS_PRIORITY
    ) {
        header.vendor_id == Some(VENDOR_ID_3GPP)
    } else {
        true
    };
    if !valid {
        return Err(decode_value_error(
            "SWm subscriber authorization AVP has the wrong vendor identity",
            offset.saturating_add(4),
            "3gpp",
            "TS29273",
            "7.1.2.1.2",
        ));
    }
    Ok(())
}

pub(super) fn has_request_conditioned_values(
    authorization: &SwmDeaSubscriberAuthorization,
) -> bool {
    authorization.apn_oi_replacement.is_some()
}

pub(super) fn validate_result_conditions(
    authorization: &SwmDeaSubscriberAuthorization,
    exact_success: bool,
) -> Result<(), &'static str> {
    if authorization.apn_oi_replacement.is_some() && !exact_success {
        return Err("SWm DEA APN-OI-Replacement requires base DIAMETER_SUCCESS");
    }
    if authorization
        .mps_priority
        .is_some_and(|priority| !priority.has_eps_priority())
    {
        return Err("SWm DEA MPS-Priority must set MPS-EPS-Priority");
    }
    Ok(())
}

pub(super) fn validate_for_request(
    authorization: &SwmDeaSubscriberAuthorization,
    exact_success: bool,
    emergency_requested: bool,
    network_based_mobility_authorized: bool,
) -> Result<(), &'static str> {
    validate_result_conditions(authorization, exact_success)?;
    if authorization.apn_oi_replacement.is_some()
        && (emergency_requested || !network_based_mobility_authorized)
    {
        return Err(
            "SWm DEA APN-OI-Replacement requires successful non-emergency network-based mobility provenance",
        );
    }
    Ok(())
}

fn valid_apn_oi_replacement(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_APN_OI_TEXT_LEN || !value.is_ascii() {
        return false;
    }

    let mut labels = value.rsplit('.');
    let Some(gprs) = labels.next() else {
        return false;
    };
    let Some(mcc) = labels.next() else {
        return false;
    };
    let Some(mnc) = labels.next() else {
        return false;
    };
    if !gprs.eq_ignore_ascii_case("gprs")
        || !valid_plmn_label(mcc, b"mcc")
        || !valid_plmn_label(mnc, b"mnc")
    {
        return false;
    }

    labels.all(valid_domain_label)
}

fn valid_plmn_label(label: &str, prefix: &[u8; 3]) -> bool {
    let bytes = label.as_bytes();
    bytes.len() == 6
        && bytes[..3].eq_ignore_ascii_case(prefix)
        && bytes[3..].iter().all(u8::is_ascii_digit)
}

fn valid_domain_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_DOMAIN_LABEL_LEN
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn validate_base_subscription_flags(header: &AvpHeader, offset: usize) -> Result<(), DecodeError> {
    if header.vendor_id.is_some() {
        return Err(decode_value_error(
            "Subscription-Id must clear V",
            offset.saturating_add(4),
            "ietf",
            "RFC4006",
            "8.46",
        ));
    }
    Ok(())
}

fn validate_3gpp_flags(
    avp: &RawAvp<'_>,
    offset: usize,
    mandatory: Option<bool>,
    protected_may_be_set: bool,
    document: &'static str,
    section: &'static str,
) -> Result<(), DecodeError> {
    if avp.header.vendor_id != Some(VENDOR_ID_3GPP)
        || mandatory.is_some_and(|mandatory| avp.header.flags.is_mandatory() != mandatory)
        || (avp.header.flags.is_protected() && !protected_may_be_set)
    {
        return Err(decode_value_error(
            "SWm subscriber authorization AVP has invalid V/M/P flags",
            offset.saturating_add(4),
            "3gpp",
            document,
            section,
        ));
    }
    Ok(())
}

const fn encode_hex_nibble(value: u8) -> u8 {
    if value < 10 {
        b'0' + value
    } else {
        b'A' + (value - 10)
    }
}

fn decode_hex_pair(high: u8, low: u8) -> Option<u8> {
    let high = decode_hex_nibble(high)?;
    let low = decode_hex_nibble(low)?;
    Some((high << 4) | low)
}

const fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn decode_value_error(
    reason: &'static str,
    offset: usize,
    authority: &'static str,
    document: &'static str,
    section: &'static str,
) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new(authority, document, section))
}
