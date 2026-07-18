//! Raw-preserving GTPv2-C Information Element container support.
//!
//! @spec 3GPP TS29274 R18 8.2
//! @req REQ-3GPP-TS29274-R18-8.2-001

use bytes::{BufMut, Bytes, BytesMut};

/// Typed S2b-oriented IE decoders and encoders.
pub mod typed;
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, EncodeError, SpecRef,
};
pub use typed::{
    decode_typed_ie_sequence, encode_typed_ie_sequence, AccessPointName,
    AdditionalProtocolConfigurationOptions, AggregateMaximumBitRate, AllocationRetentionPriority,
    ApnRestriction, BearerContext, BearerQos, BearerQosResourceType, BearerQosValidationError,
    Cause, CauseValue, ChargingId, DuplicateIeEvidence, EpsBearerId, FullyQualifiedTeid,
    Indication, IpAddress, PdnAddressAllocation, PdnAddressAllocationError, PdnType, PdnTypeValue,
    PlmnId, PortNumber, ProtocolConfigurationOptions, RatType, RatTypeValue, Recovery,
    SelectionMode, SelectionModeValue, ServingNetwork, TbcdDigits, TwanIdentifier,
    TwanIdentifierError, TwanIdentifierTimestamp, TwanLogicalAccessId, TwanRelayIdentity, TypedIe,
    TypedIeValue, IE_TYPE_AMBR, IE_TYPE_APCO, IE_TYPE_APN, IE_TYPE_APN_RESTRICTION,
    IE_TYPE_BEARER_CONTEXT, IE_TYPE_BEARER_QOS, IE_TYPE_BEARER_TFT, IE_TYPE_CAUSE,
    IE_TYPE_CHARGING_ID, IE_TYPE_EBI, IE_TYPE_F_TEID, IE_TYPE_IMSI, IE_TYPE_INDICATION,
    IE_TYPE_IP_ADDRESS, IE_TYPE_LOAD_CONTROL_INFORMATION, IE_TYPE_MEI, IE_TYPE_MSISDN,
    IE_TYPE_OVERLOAD_CONTROL_INFORMATION, IE_TYPE_PAA, IE_TYPE_PCO, IE_TYPE_PDN_TYPE,
    IE_TYPE_PGW_CHANGE_INFO, IE_TYPE_PORT_NUMBER, IE_TYPE_RAT_TYPE, IE_TYPE_RECOVERY,
    IE_TYPE_SELECTION_MODE, IE_TYPE_SERVING_NETWORK, IE_TYPE_TWAN_IDENTIFIER,
    IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP, MAX_BEARER_QOS_BITRATE_KBPS, MAX_DUPLICATE_IE_EVIDENCE,
    MAX_TWAN_SSID_LEN, MAX_TWAN_SUBFIELD_LEN, PAA_ASSIGNED_IPV6_PREFIX_LENGTH,
};

/// Length, in octets, of the GTPv2-C IE header.
pub const IE_HEADER_LEN: usize = 4;

fn spec_ref() -> SpecRef {
    SpecRef::new("3gpp", "TS29274", "8.2")
}

fn checked_offset(base: usize, delta: usize) -> Result<usize, DecodeError> {
    base.checked_add(delta).ok_or_else(|| {
        DecodeError::new(DecodeErrorCode::LengthOverflow, base).with_spec_ref(spec_ref())
    })
}

/// A borrowed raw GTPv2-C Information Element.
///
/// This raw-preserving layer underpins both forwarding paths and the typed
/// S2b IE subset. Unknown, vendor, unsupported, and future IEs retain their
/// original value bytes for byte-exact forwarding.
///
/// @spec 3GPP TS29274 R18 8.2
/// @req REQ-3GPP-TS29274-R18-8.2-002
/// @conformance s2b-subset
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawIe<'a> {
    /// One-octet IE type code.
    pub ie_type: u8,
    /// Low four-bit IE instance field.
    pub instance: u8,
    /// High four spare bits from the IE instance octet.
    pub spare: u8,
    /// Borrowed IE value bytes.
    pub value: &'a [u8],
}

impl<'a> RawIe<'a> {
    /// Decode one borrowed raw IE from the front of `input`.
    pub fn decode(input: &'a [u8]) -> DecodeResult<'a, Self> {
        decode_raw_ie(input, DecodeContext::default(), 0)
    }

    /// Return the decoded IE value length in octets.
    ///
    /// This is the length carried in the IE header, which always equals
    /// `self.value.len()` for a decoded IE. Encoders recompute the wire length
    /// from `value.len()`.
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Return `true` when this IE carries an empty value.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Return this IE's exact wire length in octets.
    pub fn wire_len(&self) -> Result<usize, EncodeError> {
        IE_HEADER_LEN
            .checked_add(self.value.len())
            .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec_ref()))
    }

    /// Encode this raw IE into `dst` preserving type, instance, spare bits,
    /// and value bytes.
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        let value_len = u16::try_from(self.value.len())
            .map_err(|_| EncodeError::length_overflow().with_spec_ref(spec_ref()))?;
        dst.put_u8(self.ie_type);
        dst.put_u16(value_len);
        dst.put_u8(((self.spare & 0x0f) << 4) | (self.instance & 0x0f));
        dst.put_slice(self.value);
        Ok(())
    }

    /// Produce an owned copy of this raw IE.
    pub fn to_owned_ie(&self) -> OwnedRawIe {
        OwnedRawIe {
            ie_type: self.ie_type,
            instance: self.instance,
            spare: self.spare,
            value: Bytes::copy_from_slice(self.value),
        }
    }
}

/// An owned raw GTPv2-C Information Element.
///
/// @spec 3GPP TS29274 R18 8.2
/// @req REQ-3GPP-TS29274-R18-8.2-003
/// @conformance s2b-subset
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedRawIe {
    /// One-octet IE type code.
    pub ie_type: u8,
    /// Low four-bit IE instance field.
    pub instance: u8,
    /// High four spare bits from the IE instance octet.
    pub spare: u8,
    /// Owned IE value bytes.
    pub value: Bytes,
}

impl OwnedRawIe {
    /// Borrow this owned IE as a [`RawIe`].
    pub fn as_borrowed(&self) -> RawIe<'_> {
        RawIe {
            ie_type: self.ie_type,
            instance: self.instance,
            spare: self.spare,
            value: &self.value,
        }
    }

    /// Return the decoded IE value length in octets.
    pub fn len(&self) -> usize {
        self.as_borrowed().len()
    }

    /// Return `true` when this IE carries an empty value.
    pub fn is_empty(&self) -> bool {
        self.as_borrowed().is_empty()
    }

    /// Return this IE's exact wire length in octets.
    pub fn wire_len(&self) -> Result<usize, EncodeError> {
        self.as_borrowed().wire_len()
    }

    /// Encode this raw IE into `dst` preserving type, instance, spare bits,
    /// and value bytes.
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        self.as_borrowed().encode(dst)
    }
}

/// Iterator over a contiguous GTPv2-C raw IE region.
///
/// Each item is parsed lazily and checked against [`DecodeContext`] limits.
/// On the first decode error the iterator is exhausted.
///
/// @spec 3GPP TS29274 R18 8.2
/// @req REQ-3GPP-TS29274-R18-8.2-004
/// @conformance s2b-subset
pub struct RawIeIterator<'a> {
    remaining: &'a [u8],
    ctx: DecodeContext,
    offset: usize,
    count: usize,
    stopped: bool,
}

impl<'a> RawIeIterator<'a> {
    /// Create an iterator over `region` with the supplied decode context.
    ///
    /// The iterator's internal offset starts at zero; callers that need
    /// absolute offsets within a larger message should use [`Self::new_at_offset`].
    pub const fn new(region: &'a [u8], ctx: DecodeContext) -> Self {
        Self::new_at_offset(region, ctx, 0)
    }

    /// Create an iterator over `region` whose internal offset starts at
    /// `base_offset`.
    ///
    /// This is used when decoding a sub-region (e.g. a grouped IE value) so
    /// that raw parse errors report positions relative to the containing
    /// message rather than to the sub-region.
    pub const fn new_at_offset(region: &'a [u8], ctx: DecodeContext, base_offset: usize) -> Self {
        Self {
            remaining: region,
            ctx,
            offset: base_offset,
            count: 0,
            stopped: false,
        }
    }

    /// Return the current byte offset of the iterator.
    ///
    /// At the start of iteration this equals the `base_offset` supplied to the
    /// constructor; after each yielded IE it is advanced by that IE's wire
    /// length. It therefore points to the start of the next IE to be decoded.
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

impl<'a> Iterator for RawIeIterator<'a> {
    type Item = Result<RawIe<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.stopped || self.remaining.is_empty() {
            return None;
        }

        self.count = match self.count.checked_add(1) {
            Some(count) => count,
            None => {
                self.stopped = true;
                return Some(Err(DecodeError::new(
                    DecodeErrorCode::LengthOverflow,
                    self.offset,
                )
                .with_spec_ref(spec_ref())));
            }
        };
        if self.count > self.ctx.max_ies {
            self.stopped = true;
            return Some(Err(DecodeError::new(
                DecodeErrorCode::IeCountExceeded,
                self.offset,
            )
            .with_spec_ref(spec_ref())));
        }

        match decode_raw_ie(self.remaining, self.ctx, self.offset) {
            Ok((tail, ie)) => {
                let consumed = self.remaining.len().checked_sub(tail.len()).ok_or_else(|| {
                    DecodeError::new(DecodeErrorCode::LengthOverflow, self.offset)
                        .with_spec_ref(spec_ref())
                });
                self.offset =
                    match consumed.and_then(|consumed| checked_offset(self.offset, consumed)) {
                        Ok(offset) => offset,
                        Err(error) => {
                            self.stopped = true;
                            return Some(Err(error));
                        }
                    };
                self.remaining = tail;
                Some(Ok(ie))
            }
            Err(error) => {
                self.stopped = true;
                Some(Err(error))
            }
        }
    }
}

/// Validate that `region` is a well-formed sequence of raw GTPv2-C IEs.
///
/// This function does not allocate or type-dispatch. It only enforces TLIV
/// boundaries, spare-bit strictness, and the configured IE count limit.
///
/// @spec 3GPP TS29274 R18 8.2
/// @req REQ-3GPP-TS29274-R18-8.2-005
/// @conformance s2b-subset
pub fn validate_ie_region(region: &[u8], ctx: DecodeContext) -> Result<(), DecodeError> {
    for item in RawIeIterator::new(region, ctx) {
        item?;
    }
    Ok(())
}

fn decode_raw_ie<'a>(
    input: &'a [u8],
    ctx: DecodeContext,
    base_offset: usize,
) -> DecodeResult<'a, RawIe<'a>> {
    let spec = spec_ref();
    if input.len() < IE_HEADER_LEN {
        return Err(DecodeError::new(DecodeErrorCode::Truncated, base_offset).with_spec_ref(spec));
    }

    let ie_type = input[0];
    let length = u16::from_be_bytes([input[1], input[2]]);
    let spare = (input[3] >> 4) & 0x0f;
    let instance = input[3] & 0x0f;
    if crate::is_strict(ctx.validation_level) && spare != 0 {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "IE spare bits must be zero",
            },
            checked_offset(base_offset, 3)?,
        )
        .with_spec_ref(spec));
    }

    let total_len = IE_HEADER_LEN
        .checked_add(length as usize)
        .ok_or_else(|| DecodeError::new(DecodeErrorCode::LengthOverflow, base_offset))
        .map_err(|error| error.with_spec_ref(spec.clone()))?;
    if input.len() < total_len {
        // Report truncation at the start of the IE so both header-truncated and
        // value-truncated cases use a consistent offset convention.
        return Err(DecodeError::new(DecodeErrorCode::Truncated, base_offset).with_spec_ref(spec));
    }

    let value = &input[IE_HEADER_LEN..total_len];
    Ok((
        &input[total_len..],
        RawIe {
            ie_type,
            instance,
            spare,
            value,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_raw_ie_region() {
        let region = [0xff, 0x00, 0x01, 0x00, 0xaa];
        let result = validate_ie_region(&region, DecodeContext::default());
        assert!(result.is_ok());
    }

    #[test]
    fn enforces_ie_count_limit() {
        let region = [0xff, 0x00, 0x00, 0x00];
        let ctx = DecodeContext {
            max_ies: 0,
            ..DecodeContext::default()
        };
        let result = validate_ie_region(&region, ctx);
        assert!(matches!(
            result,
            Err(error) if matches!(error.code(), DecodeErrorCode::IeCountExceeded)
        ));
    }
}
