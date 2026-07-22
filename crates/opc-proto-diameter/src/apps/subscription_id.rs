//! Shared RFC 4006 Subscription-Id model and grouped codec.
//!
//! Rf and SWm both use the legacy `Subscription-Id` grouped AVP. Keeping the
//! group in one codec prevents the child cardinality and flag contracts from
//! drifting between applications.

use bytes::BytesMut;
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, EncodeContext, EncodeError, SpecRef,
};

use super::builder_helpers;
use crate::avp::dictionary::Redacted;
use crate::{AvpCode, AvpHeader, RawAvp};

pub(crate) const MAX_E164_DIGITS: usize = 15;

/// Subscription-Id grouped AVP code (RFC 4006 section 8.46).
pub const AVP_SUBSCRIPTION_ID: AvpCode = AvpCode::new(443);
/// Subscription-Id-Data AVP code (RFC 4006 section 8.48).
pub const AVP_SUBSCRIPTION_ID_DATA: AvpCode = AvpCode::new(444);
/// Subscription-Id-Type AVP code (RFC 4006 section 8.47).
pub const AVP_SUBSCRIPTION_ID_TYPE: AvpCode = AvpCode::new(450);

/// Subscription-Id-Type values from RFC 4006 section 8.47.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubscriptionIdType {
    /// End User E.164.
    EndUserE164,
    /// End User IMSI.
    EndUserImsi,
    /// End User SIP URI.
    EndUserSipUri,
    /// End User NAI.
    EndUserNai,
    /// End User Private.
    EndUserPrivate,
    /// Unknown or application-specific value.
    Other(u32),
}

impl SubscriptionIdType {
    /// Return the wire value for this subscription-id type.
    pub const fn value(self) -> u32 {
        match self {
            Self::EndUserE164 => 0,
            Self::EndUserImsi => 1,
            Self::EndUserSipUri => 2,
            Self::EndUserNai => 3,
            Self::EndUserPrivate => 4,
            Self::Other(value) => value,
        }
    }

    /// Parse a subscription-id type from its wire value.
    pub const fn from_value(value: u32) -> Self {
        match value {
            0 => Self::EndUserE164,
            1 => Self::EndUserImsi,
            2 => Self::EndUserSipUri,
            3 => Self::EndUserNai,
            4 => Self::EndUserPrivate,
            other => Self::Other(other),
        }
    }
}

/// A single subscription identifier carried inside a Subscription-Id group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionId {
    /// Type of subscription identifier.
    pub subscription_id_type: SubscriptionIdType,
    /// Subscription identifier value (redacted in diagnostic output).
    pub subscription_id_data: Redacted<String>,
}

#[cfg(feature = "app-rf")]
pub(crate) fn append_subscription_id_value(
    dst: &mut BytesMut,
    subscription_id: &SubscriptionId,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    append_subscription_id_value_fields(
        dst,
        subscription_id.subscription_id_type,
        subscription_id.subscription_id_data.as_ref(),
        ctx,
    )
}

pub(crate) fn append_subscription_id_value_fields(
    dst: &mut BytesMut,
    subscription_id_type: SubscriptionIdType,
    subscription_id_data: &str,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    builder_helpers::append_u32_avp(
        dst,
        AVP_SUBSCRIPTION_ID_TYPE,
        subscription_id_type.value(),
        true,
        ctx,
    )?;
    builder_helpers::append_utf8_avp(
        dst,
        AVP_SUBSCRIPTION_ID_DATA,
        subscription_id_data,
        true,
        ctx,
    )
}

#[cfg(feature = "app-rf")]
pub(crate) fn append_subscription_id_avp(
    dst: &mut BytesMut,
    subscription_id: &SubscriptionId,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let mut value = BytesMut::new();
    append_subscription_id_value(&mut value, subscription_id, ctx)?;
    builder_helpers::append_avp(dst, AvpHeader::ietf(AVP_SUBSCRIPTION_ID, true), &value, ctx)
}

#[cfg(feature = "app-rf")]
pub(crate) fn parse_subscription_id(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<SubscriptionId, DecodeError> {
    parse_subscription_id_with_unknown(value, ctx, base_offset, depth, false, |offset, avp| {
        builder_helpers::handle_unknown_avp(ctx, avp, offset, "8.46")
    })
}

pub(crate) fn parse_subscription_id_with_unknown<F>(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
    strict_swm_profile: bool,
    mut handle_unknown: F,
) -> Result<SubscriptionId, DecodeError>
where
    F: for<'a> FnMut(usize, &RawAvp<'a>) -> Result<(), DecodeError>,
{
    let mut subscription_id_type = None;
    let mut subscription_id_data = None;
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, avp| {
        let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "8.46")?;
        if strict_swm_profile
            && avp
                .header
                .vendor_id
                .is_some_and(|vendor_id| vendor_id.get() == 0)
        {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "SWm Subscription-Id extension Vendor-Id must be nonzero",
                },
                offset.saturating_add(8),
            )
            .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4.1.1")));
        }
        if strict_swm_profile
            && avp.header.vendor_id.is_some()
            && matches!(
                avp.header.code,
                AVP_SUBSCRIPTION_ID_TYPE | AVP_SUBSCRIPTION_ID_DATA
            )
        {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "Subscription-Id core child code must clear V",
                },
                offset.saturating_add(4),
            )
            .with_spec_ref(SpecRef::new("ietf", "RFC4006", "8.46")));
        }
        if avp.header.vendor_id.is_some() {
            return handle_unknown(offset, &avp);
        }
        if avp.header.code == AVP_SUBSCRIPTION_ID_TYPE {
            if strict_swm_profile {
                validate_required_child_flags(&avp.header, offset)?;
            }
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.47")?;
            builder_helpers::set_once(
                &mut subscription_id_type,
                SubscriptionIdType::from_value(value),
                offset,
                "8.46",
            )?;
        } else if avp.header.code == AVP_SUBSCRIPTION_ID_DATA {
            if strict_swm_profile {
                validate_required_child_flags(&avp.header, offset)?;
                if avp.value.is_empty()
                    || avp.value.len() > MAX_E164_DIGITS
                    || !avp.value.iter().all(u8::is_ascii_digit)
                    || !avp
                        .value
                        .first()
                        .is_some_and(|digit| matches!(*digit, b'1'..=b'9'))
                {
                    return Err(DecodeError::new(
                        DecodeErrorCode::Structural {
                            reason: "SWm Subscription-Id-Data is not an international E.164 number",
                        },
                        value_offset,
                    )
                    .with_spec_ref(SpecRef::new("ietf", "RFC4006", "8.48")));
                }
            }
            let value = builder_helpers::parse_string_value(avp.value, value_offset, "8.48")?;
            builder_helpers::set_once(
                &mut subscription_id_data,
                Redacted::from(value),
                offset,
                "8.46",
            )?;
        } else {
            handle_unknown(offset, &avp)?;
        }
        Ok(())
    })?;
    Ok(SubscriptionId {
        subscription_id_type: subscription_id_type.ok_or_else(|| {
            missing_child_error(
                base_offset,
                "missing Subscription-Id-Type child AVP",
                strict_swm_profile,
            )
        })?,
        subscription_id_data: subscription_id_data.ok_or_else(|| {
            missing_child_error(
                base_offset,
                "missing Subscription-Id-Data child AVP",
                strict_swm_profile,
            )
        })?,
    })
}

fn validate_required_child_flags(header: &AvpHeader, offset: usize) -> Result<(), DecodeError> {
    if header.vendor_id.is_some() || !header.flags.is_mandatory() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "Subscription-Id child must clear V and set M",
            },
            offset.saturating_add(4),
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC4006", "8.46")));
    }
    Ok(())
}

fn missing_child_error(
    base_offset: usize,
    reason: &'static str,
    strict_swm_flags: bool,
) -> DecodeError {
    let spec_ref = if strict_swm_flags {
        SpecRef::new("ietf", "RFC4006", "8.46")
    } else {
        // Preserve the established Rf parser's diagnostic contract exactly.
        SpecRef::new("ietf", "RFC6733", "grouped")
    };
    DecodeError::new(DecodeErrorCode::Structural { reason }, base_offset).with_spec_ref(spec_ref)
}
