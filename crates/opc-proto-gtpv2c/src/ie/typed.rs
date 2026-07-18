//! Typed GTPv2-C Information Elements used by the S2b procedure views.
//!
//! This module intentionally implements a narrow Release 18 subset that is
//! needed by the S2b Echo/session and dedicated-bearer message views.
//! Unsupported IEs remain available as raw-preserving [`RawIe`] fallbacks.
//!
//! @spec 3GPP TS29274 R18 8.2
//! @req REQ-3GPP-TS29274-R18-S2B-IE-001

use core::fmt;

use bytes::{BufMut, BytesMut};
use opc_proto_tft::{TftError, TftErrorKind, TrafficFlowTemplate};
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, DuplicateIePolicy, EncodeContext, EncodeError,
    EncodeErrorCode, SpecRef, UnknownIePolicy,
};

use crate::ie::{RawIe, RawIeIterator, IE_HEADER_LEN};

/// Maximum number of distinct duplicate-IE keys retained in receive diagnostics.
///
/// Further duplicate keys are counted by the enclosing S2b diagnostic summary
/// without retaining peer-controlled values or allocating an unbounded list.
pub const MAX_DUPLICATE_IE_EVIDENCE: usize = 64;

/// Redaction-safe evidence that a singleton IE key was repeated in one scope.
///
/// Offsets are relative to the start of the decoded top-level IE region. A
/// grouped IE has its own scope, identified by both `depth` and `scope_offset`.
/// No IE value bytes are retained.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DuplicateIeEvidence {
    ie_type: u8,
    instance: u8,
    depth: usize,
    scope_offset: usize,
    first_offset: usize,
    duplicate_count: u16,
}

impl DuplicateIeEvidence {
    /// Return the repeated IE type.
    pub const fn ie_type(self) -> u8 {
        self.ie_type
    }

    /// Return the repeated IE instance.
    pub const fn instance(self) -> u8 {
        self.instance
    }

    /// Return the grouped-IE nesting depth of this key.
    pub const fn depth(self) -> usize {
        self.depth
    }

    /// Return the offset at which this IE scope begins.
    pub const fn scope_offset(self) -> usize {
        self.scope_offset
    }

    /// Return the offset of the first retained occurrence.
    pub const fn first_offset(self) -> usize {
        self.first_offset
    }

    /// Return the saturated number of ignored later occurrences.
    pub const fn duplicate_count(self) -> u16 {
        self.duplicate_count
    }
}

impl fmt::Debug for DuplicateIeEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DuplicateIeEvidence")
            .field("ie_type", &self.ie_type)
            .field("instance", &self.instance)
            .field("depth", &self.depth)
            .field("scope_offset", &self.scope_offset)
            .field("first_offset", &self.first_offset)
            .field("duplicate_count", &self.duplicate_count)
            .finish()
    }
}

#[derive(Default)]
pub(crate) struct DuplicateIeCollector {
    entries: Vec<DuplicateIeEvidence>,
    omitted_count: u32,
}

impl DuplicateIeCollector {
    fn record(
        &mut self,
        ie_type: u8,
        instance: u8,
        depth: usize,
        scope_offset: usize,
        first_offset: usize,
    ) {
        if let Some(entry) = self.entries.iter_mut().find(|entry| {
            entry.ie_type == ie_type
                && entry.instance == instance
                && entry.depth == depth
                && entry.scope_offset == scope_offset
        }) {
            entry.duplicate_count = entry.duplicate_count.saturating_add(1);
            return;
        }
        if self.entries.len() < MAX_DUPLICATE_IE_EVIDENCE {
            self.entries.push(DuplicateIeEvidence {
                ie_type,
                instance,
                depth,
                scope_offset,
                first_offset,
                duplicate_count: 1,
            });
        } else {
            self.omitted_count = self.omitted_count.saturating_add(1);
        }
    }

    pub(crate) fn into_parts(self) -> (Vec<DuplicateIeEvidence>, u32) {
        (self.entries, self.omitted_count)
    }
}

pub(crate) struct DecodedIeSequence<'a> {
    pub(crate) ies: Vec<TypedIe<'a>>,
    pub(crate) duplicate_evidence: Vec<DuplicateIeEvidence>,
    pub(crate) omitted_duplicate_count: u32,
}

type IeDecodeFilter<'f> = &'f dyn Fn(u8, u8, usize, Option<(u8, u8)>) -> bool;
type IeRepeatableLimit<'f> = &'f dyn Fn(u8, u8, usize, Option<(u8, u8)>) -> Option<usize>;

#[derive(Clone, Copy)]
struct IeDecodePolicy<'p> {
    legacy_pgw_triggered_request: bool,
    filter: Option<IeDecodeFilter<'p>>,
    scoped_repeatable_limit: Option<IeRepeatableLimit<'p>>,
}

impl<'p> IeDecodePolicy<'p> {
    const fn legacy(pgw_triggered_request: bool) -> Self {
        Self {
            legacy_pgw_triggered_request: pgw_triggered_request,
            filter: None,
            scoped_repeatable_limit: None,
        }
    }

    const fn scoped(filter: IeDecodeFilter<'p>, repeatable_limit: IeRepeatableLimit<'p>) -> Self {
        Self {
            legacy_pgw_triggered_request: false,
            filter: Some(filter),
            scoped_repeatable_limit: Some(repeatable_limit),
        }
    }
}

#[derive(Clone, Copy)]
struct IeSequencePosition {
    depth: usize,
    base_offset: usize,
    parent_ie: Option<(u8, u8)>,
}

impl IeSequencePosition {
    const fn root(depth: usize) -> Self {
        Self {
            depth,
            base_offset: 0,
            parent_ie: None,
        }
    }
}

/// GTPv2-C IMSI IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_IMSI: u8 = 1;
/// GTPv2-C Cause IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_CAUSE: u8 = 2;
/// GTPv2-C Recovery IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_RECOVERY: u8 = 3;
/// GTPv2-C APN IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_APN: u8 = 71;
/// GTPv2-C Aggregate Maximum Bit Rate IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_AMBR: u8 = 72;
/// GTPv2-C EPS Bearer ID IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_EBI: u8 = 73;
/// GTPv2-C MEI IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_MEI: u8 = 75;
/// GTPv2-C MSISDN IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_MSISDN: u8 = 76;
/// GTPv2-C Indication IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_INDICATION: u8 = 77;
/// GTPv2-C Protocol Configuration Options IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_PCO: u8 = 78;
/// GTPv2-C PDN Address Allocation IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_PAA: u8 = 79;
/// GTPv2-C Bearer QoS IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_BEARER_QOS: u8 = 80;
/// GTPv2-C RAT Type IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_RAT_TYPE: u8 = 82;
/// GTPv2-C Serving Network IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_SERVING_NETWORK: u8 = 83;
/// GTPv2-C Bearer TFT IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_BEARER_TFT: u8 = 84;
/// GTPv2-C Fully Qualified TEID IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_F_TEID: u8 = 87;
/// GTPv2-C Bearer Context grouped IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_BEARER_CONTEXT: u8 = 93;
/// GTPv2-C Charging ID IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_CHARGING_ID: u8 = 94;
/// GTPv2-C PDN Type IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_PDN_TYPE: u8 = 99;
/// GTPv2-C APN Restriction IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_APN_RESTRICTION: u8 = 127;
/// GTPv2-C Selection Mode IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_SELECTION_MODE: u8 = 128;
/// GTPv2-C Additional Protocol Configuration Options IE type.
pub const IE_TYPE_APCO: u8 = 163;
/// GTPv2-C Overload Control Information IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_OVERLOAD_CONTROL_INFORMATION: u8 = 180;
/// GTPv2-C Load Control Information IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_LOAD_CONTROL_INFORMATION: u8 = 181;
/// GTPv2-C PGW Change Info IE type (TS 29.274 Table 8.1-1).
pub const IE_TYPE_PGW_CHANGE_INFO: u8 = 214;

/// Largest integer-kbps rate representable by a Bearer QoS u40 field.
pub const MAX_BEARER_QOS_BITRATE_KBPS: u64 = 0x00ff_ffff_ffff;

fn spec_ref() -> SpecRef {
    SpecRef::new("3gpp", "TS29274", "8.2")
}

fn checked_add_offset(base: usize, delta: usize) -> Result<usize, DecodeError> {
    base.checked_add(delta).ok_or_else(|| {
        DecodeError::new(DecodeErrorCode::LengthOverflow, base).with_spec_ref(spec_ref())
    })
}

pub(crate) const TFT_OPERATION_SYNTAX_ERROR_REASON: &str =
    "Bearer TFT IE has a syntactically invalid TFT operation";
pub(crate) const PACKET_FILTER_SYNTAX_ERROR_REASON: &str =
    "Bearer TFT IE has syntactically invalid packet filters";
pub(crate) const PACKET_FILTER_SEMANTIC_ERROR_REASON: &str =
    "Bearer TFT IE has semantically invalid packet filters";

fn bearer_tft_decode_error(error: TftError, value_offset: usize) -> DecodeError {
    let error_offset = error
        .offset()
        .and_then(|relative| value_offset.checked_add(relative))
        .unwrap_or(value_offset);
    let reason = match error.kind() {
        TftErrorKind::ConflictingComponents { .. } => PACKET_FILTER_SEMANTIC_ERROR_REASON,
        TftErrorKind::Truncated { field } if field.starts_with("packet filter") => {
            PACKET_FILTER_SYNTAX_ERROR_REASON
        }
        TftErrorKind::InvalidPacketFilterIdentifier { .. }
        | TftErrorKind::DuplicatePacketFilterIdentifier { .. }
        | TftErrorKind::DuplicateEvaluationPrecedence { .. }
        | TftErrorKind::EmptyPacketFilterContents
        | TftErrorKind::PacketFilterContentsTooLong { .. }
        | TftErrorKind::ReservedComponentType { .. }
        | TftErrorKind::InvalidComponentLength { .. }
        | TftErrorKind::DuplicateComponent { .. }
        | TftErrorKind::InvalidIpv6PrefixLength { .. }
        | TftErrorKind::InvalidPortRange
        | TftErrorKind::InvalidFlowLabel { .. }
        | TftErrorKind::InvalidVlanIdentifier { .. }
        | TftErrorKind::InvalidVlanPriority { .. } => PACKET_FILTER_SYNTAX_ERROR_REASON,
        TftErrorKind::NonZeroSpareBits {
            field: "packet-filter-identifier parameter",
        } => TFT_OPERATION_SYNTAX_ERROR_REASON,
        TftErrorKind::NonZeroSpareBits { .. } => PACKET_FILTER_SYNTAX_ERROR_REASON,
        _ => TFT_OPERATION_SYNTAX_ERROR_REASON,
    };
    DecodeError::new(DecodeErrorCode::Structural { reason }, error_offset).with_spec_ref(spec_ref())
}

fn require_exact_len(
    value: &[u8],
    expected: usize,
    offset: usize,
    reason: &'static str,
) -> Result<(), DecodeError> {
    if value.len() != expected {
        return Err(
            DecodeError::new(DecodeErrorCode::InvalidLength { reason }, offset)
                .with_spec_ref(spec_ref()),
        );
    }
    Ok(())
}

fn require_min_len(
    value: &[u8],
    minimum: usize,
    offset: usize,
    _reason: &'static str,
) -> Result<(), DecodeError> {
    if value.len() < minimum {
        return Err(DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref()));
    }
    Ok(())
}

fn encode_structural_error(reason: &'static str) -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural { reason }).with_spec_ref(spec_ref())
}

fn decode_u40(value: &[u8]) -> u64 {
    ((value[0] as u64) << 32)
        | ((value[1] as u64) << 24)
        | ((value[2] as u64) << 16)
        | ((value[3] as u64) << 8)
        | (value[4] as u64)
}

fn encode_u40(value: u64, dst: &mut BytesMut) -> Result<(), EncodeError> {
    if value > MAX_BEARER_QOS_BITRATE_KBPS {
        return Err(encode_structural_error(
            "Bearer QoS bitrate exceeds 40 bits",
        ));
    }
    dst.put_u8((value >> 32) as u8);
    dst.put_u8((value >> 24) as u8);
    dst.put_u8((value >> 16) as u8);
    dst.put_u8((value >> 8) as u8);
    dst.put_u8(value as u8);
    Ok(())
}

fn validate_decimal_digits(digits: &str, reason: &'static str) -> Result<(), EncodeError> {
    if digits.is_empty() {
        return Err(encode_structural_error(reason));
    }
    if digits.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(encode_structural_error("TBCD digits must be decimal"));
    }
    Ok(())
}

fn push_tbcd_digit(out: &mut String, digit: u8, offset: usize) -> Result<(), DecodeError> {
    if digit > 9 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidEnumValue {
                field: "tbcd_digit",
                value: digit as u64,
            },
            offset,
        )
        .with_spec_ref(spec_ref()));
    }
    out.push(char::from(b'0' + digit));
    Ok(())
}

/// Telephony Binary Coded Decimal digits used by IMSI, MSISDN, and MEI IEs.
///
/// GTPv2-C encodes the first decimal digit in the low nibble and the second in
/// the high nibble of each octet; odd-length values use `0xf` as the final high
/// nibble filler.
///
/// @spec 3GPP TS29274 R18 8.3.2, 8.15, 8.16
/// @req REQ-3GPP-TS29274-R18-S2B-IE-TBCD-001
#[derive(Clone, PartialEq, Eq)]
pub struct TbcdDigits {
    /// Decimal digits decoded from the TBCD value.
    pub digits: String,
}

impl TbcdDigits {
    /// Construct TBCD digits from a decimal string.
    pub fn new(digits: impl Into<String>) -> Self {
        Self {
            digits: digits.into(),
        }
    }

    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        if value.is_empty() {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "TBCD value must not be empty",
                },
                offset,
            )
            .with_spec_ref(spec_ref()));
        }

        let mut digits = String::with_capacity(value.len().saturating_mul(2));
        for (index, octet) in value.iter().copied().enumerate() {
            let low = octet & 0x0f;
            let high = (octet >> 4) & 0x0f;
            let digit_offset = checked_add_offset(offset, index)?;
            push_tbcd_digit(&mut digits, low, digit_offset)?;
            if high == 0x0f {
                if index + 1 != value.len() {
                    return Err(DecodeError::new(
                        DecodeErrorCode::Structural {
                            reason: "TBCD filler must appear only in the final high nibble",
                        },
                        digit_offset,
                    )
                    .with_spec_ref(spec_ref()));
                }
            } else {
                push_tbcd_digit(&mut digits, high, digit_offset)?;
            }
        }
        Ok(Self { digits })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        validate_decimal_digits(&self.digits, "TBCD value must not be empty")?;
        let bytes = self.digits.as_bytes();
        let mut index = 0usize;
        while index < bytes.len() {
            let low = bytes[index] - b'0';
            let high = if index + 1 < bytes.len() {
                bytes[index + 1] - b'0'
            } else {
                0x0f
            };
            dst.put_u8((high << 4) | low);
            index = index.saturating_add(2);
        }
        Ok(())
    }
}

impl fmt::Debug for TbcdDigits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TbcdDigits")
            .field("digits", &"<redacted>")
            .field("digit_len", &self.digits.len())
            .finish()
    }
}

/// GTPv2-C Cause values used by the S2b protocol surface.
///
/// Unknown cause codes are preserved as [`CauseValue::Unknown`].
///
/// @spec 3GPP TS29274 R18 8.4
/// @req REQ-3GPP-TS29274-R18-S2B-IE-CAUSE-001
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CauseValue {
    /// Local detach (2).
    LocalDetach,
    /// RAT changed from 3GPP to non-3GPP (4).
    RatChangedFrom3gppToNon3gpp,
    /// ISR deactivation (5).
    IsrDeactivation,
    /// Reactivation requested (8).
    ReactivationRequested,
    /// PDN reconnection to this APN disallowed (9).
    PdnReconnectionDisallowed,
    /// Access changed from non-3GPP to 3GPP (10).
    AccessChangedFromNon3gppTo3gpp,
    /// PDN connection inactivity timer expires (11).
    PdnConnectionInactivityTimerExpires,
    /// EPS to 5GS mobility (15).
    EpsTo5gsMobility,
    /// Request accepted (16).
    RequestAccepted,
    /// Request accepted partially (17).
    RequestAcceptedPartially,
    /// Context not found (64).
    ContextNotFound,
    /// Invalid message format (65).
    InvalidMessageFormat,
    /// Invalid length (67).
    InvalidLength,
    /// Service not supported (68).
    ServiceNotSupported,
    /// Mandatory IE incorrect (69).
    MandatoryIeIncorrect,
    /// Mandatory IE missing (70).
    MandatoryIeMissing,
    /// System failure (72).
    SystemFailure,
    /// No resources available (73).
    NoResourcesAvailable,
    /// Semantic error in the TFT operation (74).
    SemanticErrorInTftOperation,
    /// Syntactic error in the TFT operation (75).
    SyntacticErrorInTftOperation,
    /// Semantic errors in packet filter(s) (76).
    SemanticErrorsInPacketFilters,
    /// Syntactic errors in packet filter(s) (77).
    SyntacticErrorsInPacketFilters,
    /// Denied in RAT (82).
    DeniedInRat,
    /// UE context without TFT already activated (85).
    UeContextWithoutTftAlreadyActivated,
    /// UE not responding (87).
    UeNotResponding,
    /// UE refuses (88).
    UeRefuses,
    /// Unable to page UE (90).
    UnableToPageUe,
    /// Request rejected without a more specific reason (94).
    RequestRejected,
    /// Collision with network initiated request (101).
    CollisionWithNetworkInitiatedRequest,
    /// Unable to page UE due to suspension (102).
    UnableToPageUeDueToSuspension,
    /// Conditional IE missing (103).
    ConditionalIeMissing,
    /// Temporarily rejected because handover, TAU, or RAU is in progress (110).
    TemporarilyRejectedForMobilityProcedure,
    /// Bearer handling not supported (114).
    BearerHandlingNotSupported,
    /// MME or SGSN refuses due to VPLMN policy (119).
    RefusedDueToVplmnPolicy,
    /// Late overlapping request (121).
    LateOverlappingRequest,
    /// Timed out request (122).
    TimedOutRequest,
    /// UE is temporarily unreachable due to power saving (123).
    UeTemporarilyUnreachableDueToPowerSaving,
    /// Request rejected due to UE capability (127).
    RequestRejectedDueToUeCapability,
    /// Multiple accesses to one PDN connection are not allowed (126).
    MultipleAccessesToPdnConnectionNotAllowed,
    /// Unmodelled cause value.
    Unknown(u8),
}

impl CauseValue {
    /// Return the normative numeric Cause value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::LocalDetach => 2,
            Self::RatChangedFrom3gppToNon3gpp => 4,
            Self::IsrDeactivation => 5,
            Self::ReactivationRequested => 8,
            Self::PdnReconnectionDisallowed => 9,
            Self::AccessChangedFromNon3gppTo3gpp => 10,
            Self::PdnConnectionInactivityTimerExpires => 11,
            Self::EpsTo5gsMobility => 15,
            Self::RequestAccepted => 16,
            Self::RequestAcceptedPartially => 17,
            Self::ContextNotFound => 64,
            Self::InvalidMessageFormat => 65,
            Self::InvalidLength => 67,
            Self::ServiceNotSupported => 68,
            Self::MandatoryIeIncorrect => 69,
            Self::MandatoryIeMissing => 70,
            Self::SystemFailure => 72,
            Self::NoResourcesAvailable => 73,
            Self::SemanticErrorInTftOperation => 74,
            Self::SyntacticErrorInTftOperation => 75,
            Self::SemanticErrorsInPacketFilters => 76,
            Self::SyntacticErrorsInPacketFilters => 77,
            Self::DeniedInRat => 82,
            Self::UeContextWithoutTftAlreadyActivated => 85,
            Self::UeNotResponding => 87,
            Self::UeRefuses => 88,
            Self::UnableToPageUe => 90,
            Self::RequestRejected => 94,
            Self::CollisionWithNetworkInitiatedRequest => 101,
            Self::UnableToPageUeDueToSuspension => 102,
            Self::ConditionalIeMissing => 103,
            Self::TemporarilyRejectedForMobilityProcedure => 110,
            Self::BearerHandlingNotSupported => 114,
            Self::RefusedDueToVplmnPolicy => 119,
            Self::LateOverlappingRequest => 121,
            Self::TimedOutRequest => 122,
            Self::UeTemporarilyUnreachableDueToPowerSaving => 123,
            Self::MultipleAccessesToPdnConnectionNotAllowed => 126,
            Self::RequestRejectedDueToUeCapability => 127,
            Self::Unknown(value) => value,
        }
    }

    /// Return `true` for Cause values in the acceptance range used here.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::RequestAccepted | Self::RequestAcceptedPartially)
    }

    /// Return `true` when this is the partial-acceptance Cause.
    #[must_use]
    pub const fn is_partially_accepted(self) -> bool {
        matches!(self, Self::RequestAcceptedPartially)
    }

    /// Return `true` for a rejection Cause value (64 through 239).
    #[must_use]
    pub const fn is_rejection(self) -> bool {
        let value = self.as_u8();
        value >= 64 && value <= 239
    }
}

impl From<u8> for CauseValue {
    fn from(value: u8) -> Self {
        match value {
            2 => Self::LocalDetach,
            4 => Self::RatChangedFrom3gppToNon3gpp,
            5 => Self::IsrDeactivation,
            8 => Self::ReactivationRequested,
            9 => Self::PdnReconnectionDisallowed,
            10 => Self::AccessChangedFromNon3gppTo3gpp,
            11 => Self::PdnConnectionInactivityTimerExpires,
            15 => Self::EpsTo5gsMobility,
            16 => Self::RequestAccepted,
            17 => Self::RequestAcceptedPartially,
            64 => Self::ContextNotFound,
            65 => Self::InvalidMessageFormat,
            67 => Self::InvalidLength,
            68 => Self::ServiceNotSupported,
            69 => Self::MandatoryIeIncorrect,
            70 => Self::MandatoryIeMissing,
            72 => Self::SystemFailure,
            73 => Self::NoResourcesAvailable,
            74 => Self::SemanticErrorInTftOperation,
            75 => Self::SyntacticErrorInTftOperation,
            76 => Self::SemanticErrorsInPacketFilters,
            77 => Self::SyntacticErrorsInPacketFilters,
            82 => Self::DeniedInRat,
            85 => Self::UeContextWithoutTftAlreadyActivated,
            87 => Self::UeNotResponding,
            88 => Self::UeRefuses,
            90 => Self::UnableToPageUe,
            94 => Self::RequestRejected,
            101 => Self::CollisionWithNetworkInitiatedRequest,
            102 => Self::UnableToPageUeDueToSuspension,
            103 => Self::ConditionalIeMissing,
            110 => Self::TemporarilyRejectedForMobilityProcedure,
            114 => Self::BearerHandlingNotSupported,
            119 => Self::RefusedDueToVplmnPolicy,
            121 => Self::LateOverlappingRequest,
            122 => Self::TimedOutRequest,
            123 => Self::UeTemporarilyUnreachableDueToPowerSaving,
            126 => Self::MultipleAccessesToPdnConnectionNotAllowed,
            127 => Self::RequestRejectedDueToUeCapability,
            other => Self::Unknown(other),
        }
    }
}

impl From<CauseValue> for u8 {
    fn from(value: CauseValue) -> Self {
        value.as_u8()
    }
}

/// Cause IE (type 2).
///
/// @spec 3GPP TS29274 R18 8.4
/// @req REQ-3GPP-TS29274-R18-S2B-IE-CAUSE-002
#[derive(Clone, PartialEq, Eq)]
pub struct Cause {
    /// Cause code.
    pub value: CauseValue,
    /// Raw cause flags/locality octet following the cause code.
    pub flags_octet: u8,
    /// Optional offending-IE payload bytes after the flags/locality octet.
    pub offending_ie: Vec<u8>,
}

impl Cause {
    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        require_min_len(
            value,
            2,
            offset,
            "Cause IE must contain cause and flags/locality octets",
        )?;
        Ok(Self {
            value: CauseValue::from(value[0]),
            flags_octet: value[1],
            offending_ie: value[2..].to_vec(),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u8(self.value.into());
        dst.put_u8(self.flags_octet);
        dst.put_slice(&self.offending_ie);
        Ok(())
    }
}

impl fmt::Debug for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cause")
            .field("value", &self.value)
            .field("flags_octet", &self.flags_octet)
            .field("offending_ie_len", &self.offending_ie.len())
            .finish()
    }
}

/// Recovery IE (type 3), carrying the restart counter used by Echo Response.
///
/// @spec 3GPP TS29274 R18 8.5
/// @req REQ-3GPP-TS29274-R18-S2B-IE-RECOVERY-001
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovery {
    /// Recovery restart counter.
    pub restart_counter: u8,
}

impl Recovery {
    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        require_exact_len(value, 1, offset, "Recovery IE must be one octet")?;
        Ok(Self {
            restart_counter: value[0],
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u8(self.restart_counter);
        Ok(())
    }
}

/// Access Point Name IE (type 71).
///
/// The value uses DNS label encoding without the terminating root label.
///
/// @spec 3GPP TS29274 R18 8.6
/// @req REQ-3GPP-TS29274-R18-S2B-IE-APN-001
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPointName {
    /// APN labels in order, for example `internet` or `ims.mnc001.mcc001.gprs`.
    pub labels: Vec<String>,
}

impl AccessPointName {
    /// Construct an APN from labels.
    pub fn new(labels: Vec<String>) -> Self {
        Self { labels }
    }

    /// Return the APN as a dot-separated string.
    pub fn to_dotted_string(&self) -> String {
        self.labels.join(".")
    }

    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        if value.is_empty() {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "APN IE must contain at least one label",
                },
                offset,
            )
            .with_spec_ref(spec_ref()));
        }
        let mut labels = Vec::new();
        let mut position = 0usize;
        while position < value.len() {
            let label_len = value[position] as usize;
            if label_len == 0 || label_len > 63 {
                return Err(DecodeError::new(
                    DecodeErrorCode::InvalidLength {
                        reason: "APN label length must be 1..63 octets",
                    },
                    checked_add_offset(offset, position)?,
                )
                .with_spec_ref(spec_ref()));
            }
            let start = position.checked_add(1).ok_or_else(|| {
                DecodeError::new(DecodeErrorCode::LengthOverflow, position)
                    .with_spec_ref(spec_ref())
            })?;
            let end = start.checked_add(label_len).ok_or_else(|| {
                DecodeError::new(DecodeErrorCode::LengthOverflow, start).with_spec_ref(spec_ref())
            })?;
            if end > value.len() {
                return Err(DecodeError::new(
                    DecodeErrorCode::Truncated,
                    checked_add_offset(offset, start)?,
                )
                .with_spec_ref(spec_ref()));
            }
            let label_offset = checked_add_offset(offset, start)?;
            let label = core::str::from_utf8(&value[start..end]).map_err(|_| {
                DecodeError::new(
                    DecodeErrorCode::Structural {
                        reason: "APN label must be UTF-8 for typed view",
                    },
                    label_offset,
                )
                .with_spec_ref(spec_ref())
            })?;
            labels.push(label.to_string());
            position = end;
        }
        Ok(Self { labels })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        if self.labels.is_empty() {
            return Err(encode_structural_error(
                "APN must contain at least one label",
            ));
        }
        for label in &self.labels {
            let bytes = label.as_bytes();
            if bytes.is_empty() || bytes.len() > 63 {
                return Err(encode_structural_error(
                    "APN label length must be 1..63 octets",
                ));
            }
            let label_len = u8::try_from(bytes.len())
                .map_err(|_| EncodeError::length_overflow().with_spec_ref(spec_ref()))?;
            dst.put_u8(label_len);
            dst.put_slice(bytes);
        }
        Ok(())
    }
}

/// Aggregate Maximum Bit Rate IE (type 72).
///
/// @spec 3GPP TS29274 R18 8.7
/// @req REQ-3GPP-TS29274-R18-S2B-IE-AMBR-001
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregateMaximumBitRate {
    /// Uplink APN-AMBR in kilobits per second.
    pub uplink: u32,
    /// Downlink APN-AMBR in kilobits per second.
    pub downlink: u32,
}

impl AggregateMaximumBitRate {
    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        require_exact_len(value, 8, offset, "AMBR IE must be eight octets")?;
        Ok(Self {
            uplink: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
            downlink: u32::from_be_bytes([value[4], value[5], value[6], value[7]]),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u32(self.uplink);
        dst.put_u32(self.downlink);
        Ok(())
    }
}

/// EPS Bearer ID IE (type 73).
///
/// @spec 3GPP TS29274 R18 8.8
/// @req REQ-3GPP-TS29274-R18-S2B-IE-EBI-001
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EpsBearerId {
    /// Low-nibble EPS bearer identity value.
    pub value: u8,
}

impl fmt::Debug for EpsBearerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EpsBearerId")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl EpsBearerId {
    fn decode_value(value: &[u8], offset: usize, ctx: DecodeContext) -> Result<Self, DecodeError> {
        require_exact_len(value, 1, offset, "EBI IE must be one octet")?;
        let spare = value[0] >> 4;
        if crate::is_strict(ctx.validation_level) && spare != 0 {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "EBI spare bits must be zero",
                },
                offset,
            )
            .with_spec_ref(spec_ref()));
        }
        Ok(Self {
            value: value[0] & 0x0f,
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u8(self.value & 0x0f);
        Ok(())
    }
}

/// Indication IE (type 77).
///
/// The Release 18 indication bitset is extension-friendly and varies in
/// length as later octets are added. This typed view preserves the value
/// octets byte-exact while exposing the IE as part of the S2b subset.
///
/// @spec 3GPP TS29274 R18 8.12
/// @req REQ-3GPP-TS29274-R18-S2B-IE-INDICATION-001
#[derive(Clone, PartialEq, Eq)]
pub struct Indication {
    /// Raw indication flag octets.
    pub flags: Vec<u8>,
}

impl Indication {
    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        require_min_len(value, 1, offset, "Indication IE must contain flag octets")?;
        Ok(Self {
            flags: value.to_vec(),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        if self.flags.is_empty() {
            return Err(encode_structural_error(
                "Indication IE must contain flag octets",
            ));
        }
        dst.put_slice(&self.flags);
        Ok(())
    }
}

impl fmt::Debug for Indication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Indication")
            .field("flags_len", &self.flags.len())
            .finish()
    }
}

/// Protocol Configuration Options IE (type 78).
///
/// PCO carries a TS 24.008 protocol-configuration container. This S2b subset
/// keeps the container opaque so unsupported nested protocols remain
/// byte-exact on canonical encode.
///
/// @spec 3GPP TS29274 R18 8.13
/// @req REQ-3GPP-TS29274-R18-S2B-IE-PCO-001
#[derive(Clone, PartialEq, Eq)]
pub struct ProtocolConfigurationOptions {
    /// Raw TS 24.008 protocol-configuration container bytes.
    pub value: Vec<u8>,
}

impl ProtocolConfigurationOptions {
    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        require_min_len(
            value,
            1,
            offset,
            "Protocol Configuration Options IE must not be empty",
        )?;
        Ok(Self {
            value: value.to_vec(),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        if self.value.is_empty() {
            return Err(encode_structural_error(
                "Protocol Configuration Options IE must not be empty",
            ));
        }
        dst.put_slice(&self.value);
        Ok(())
    }
}

impl fmt::Debug for ProtocolConfigurationOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtocolConfigurationOptions")
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// Typed Allocation and Retention Priority carried by Bearer QoS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationRetentionPriority {
    priority_level: u8,
    preemption_capability: bool,
    preemption_vulnerability: bool,
}

impl AllocationRetentionPriority {
    /// Construct a typed ARP value.
    ///
    /// # Errors
    ///
    /// Returns [`BearerQosValidationError::InvalidPriorityLevel`] unless the
    /// priority level is in the TS 29.212 range 1 through 15.
    pub const fn new(
        priority_level: u8,
        preemption_capability: bool,
        preemption_vulnerability: bool,
    ) -> Result<Self, BearerQosValidationError> {
        if priority_level == 0 || priority_level > 15 {
            return Err(BearerQosValidationError::InvalidPriorityLevel);
        }
        Ok(Self {
            priority_level,
            preemption_capability,
            preemption_vulnerability,
        })
    }

    /// Decode the TS 29.274 ARP octet, requiring spare bits 8 and 2 to be zero.
    ///
    /// # Errors
    ///
    /// Returns a stable validation error for spare bits or priority level zero.
    pub const fn from_octet(octet: u8) -> Result<Self, BearerQosValidationError> {
        if octet & 0x82 != 0 {
            return Err(BearerQosValidationError::InvalidArpSpareBits);
        }
        Self::new((octet >> 2) & 0x0f, octet & 0x40 != 0, octet & 0x01 != 0)
    }

    /// Encode the canonical TS 29.274 ARP octet with both spare bits zero.
    pub const fn to_octet(self) -> u8 {
        ((self.preemption_capability as u8) << 6)
            | (self.priority_level << 2)
            | self.preemption_vulnerability as u8
    }

    /// Allocation and Retention Priority level (1 is highest, 15 lowest).
    pub const fn priority_level(self) -> u8 {
        self.priority_level
    }

    /// Whether the bearer may pre-empt another bearer.
    pub const fn preemption_capability(self) -> bool {
        self.preemption_capability
    }

    /// Whether the bearer may be pre-empted by another bearer.
    pub const fn preemption_vulnerability(self) -> bool {
        self.preemption_vulnerability
    }
}

/// GBR classification used to validate Bearer QoS rate fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerQosResourceType {
    /// Guaranteed-bit-rate bearer.
    Gbr,
    /// Non-guaranteed-bit-rate bearer.
    NonGbr,
}

/// Stable, redaction-safe Bearer QoS validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerQosValidationError {
    /// ARP spare bit 8 or bit 2 was non-zero.
    InvalidArpSpareBits,
    /// ARP priority level was outside 1 through 15.
    InvalidPriorityLevel,
    /// QCI is reserved or unsupported by the Release 18 classification table.
    UnsupportedQci,
    /// Operator-specific QCI 128 through 254 needs caller-supplied classification.
    OperatorResourceTypeRequired,
    /// Caller-supplied resource type conflicts with a standardized QCI.
    ResourceTypeMismatch,
    /// A bitrate exceeded the five-octet unsigned integer range.
    BitrateExceedsU40,
    /// A standardized or explicitly classified non-GBR bearer had non-zero rates.
    NonGbrRatesMustBeZero,
    /// A GBR bearer had zero maximum bitrate in both directions.
    GbrMaximumBitratesMustNotBothBeZero,
    /// A guaranteed rate exceeded its same-direction maximum rate.
    GuaranteedBitrateExceedsMaximum,
}

impl BearerQosValidationError {
    /// Stable machine-readable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArpSpareBits => "gtpv2c_bearer_qos_arp_spare_bits",
            Self::InvalidPriorityLevel => "gtpv2c_bearer_qos_priority_level",
            Self::UnsupportedQci => "gtpv2c_bearer_qos_qci_unsupported",
            Self::OperatorResourceTypeRequired => "gtpv2c_bearer_qos_resource_type_required",
            Self::ResourceTypeMismatch => "gtpv2c_bearer_qos_resource_type_mismatch",
            Self::BitrateExceedsU40 => "gtpv2c_bearer_qos_bitrate_u40",
            Self::NonGbrRatesMustBeZero => "gtpv2c_bearer_qos_non_gbr_rates_nonzero",
            Self::GbrMaximumBitratesMustNotBothBeZero => {
                "gtpv2c_bearer_qos_gbr_maximum_bitrates_zero"
            }
            Self::GuaranteedBitrateExceedsMaximum => "gtpv2c_bearer_qos_guaranteed_exceeds_maximum",
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::InvalidArpSpareBits => "Bearer QoS ARP spare bits must be zero",
            Self::InvalidPriorityLevel => "Bearer QoS ARP priority level must be 1 through 15",
            Self::UnsupportedQci => "Bearer QoS QCI is reserved or unsupported",
            Self::OperatorResourceTypeRequired => {
                "operator-specific Bearer QoS QCI requires explicit resource type"
            }
            Self::ResourceTypeMismatch => {
                "Bearer QoS resource type conflicts with standardized QCI"
            }
            Self::BitrateExceedsU40 => "Bearer QoS bitrate exceeds 40 bits",
            Self::NonGbrRatesMustBeZero => "non-GBR Bearer QoS rates must all be zero",
            Self::GbrMaximumBitratesMustNotBothBeZero => {
                "GBR Bearer QoS maximum bitrates must not both be zero"
            }
            Self::GuaranteedBitrateExceedsMaximum => {
                "Bearer QoS guaranteed bitrate exceeds maximum bitrate"
            }
        }
    }
}

impl fmt::Display for BearerQosValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for BearerQosValidationError {}

/// Bearer QoS IE (type 80).
///
/// The four rate fields are unsigned 40-bit integer kilobits per second.
/// Standardized QCI semantics are checked on decode and encode. Operator-
/// specific QCIs remain wire-preservable but require an explicit resource
/// type through [`BearerQos::validate_with_resource_type`] before policy use.
///
/// @spec 3GPP TS29274 R18 8.15
/// @req REQ-3GPP-TS29274-R18-S2B-IE-BEARER-QOS-001
#[derive(Clone, PartialEq, Eq)]
pub struct BearerQos {
    /// Raw allocation/retention priority octet retained for source compatibility.
    ///
    /// Use [`Self::allocation_retention_priority`] for typed PCI/PVI/PL access.
    /// Encode rejects non-zero spare bits and an invalid priority level.
    pub priority_flags: u8,
    /// QoS Class Identifier.
    pub qci: u8,
    /// Maximum uplink bitrate as a 40-bit unsigned integer in kbps.
    pub maximum_bitrate_uplink: u64,
    /// Maximum downlink bitrate as a 40-bit unsigned integer in kbps.
    pub maximum_bitrate_downlink: u64,
    /// Guaranteed uplink bitrate as a 40-bit unsigned integer in kbps.
    pub guaranteed_bitrate_uplink: u64,
    /// Guaranteed downlink bitrate as a 40-bit unsigned integer in kbps.
    pub guaranteed_bitrate_downlink: u64,
}

impl BearerQos {
    /// Construct and validate a Bearer QoS value.
    ///
    /// The rate arguments are integer kilobits per second. For operator-
    /// specific QCIs, call [`Self::validate_with_resource_type`] before using
    /// the value for bearer policy.
    ///
    /// # Errors
    ///
    /// Returns a stable error for invalid ARP/QCI/rate relationships.
    pub fn new(
        allocation_retention_priority: AllocationRetentionPriority,
        qci: u8,
        maximum_bitrate_uplink: u64,
        maximum_bitrate_downlink: u64,
        guaranteed_bitrate_uplink: u64,
        guaranteed_bitrate_downlink: u64,
    ) -> Result<Self, BearerQosValidationError> {
        let value = Self {
            priority_flags: allocation_retention_priority.to_octet(),
            qci,
            maximum_bitrate_uplink,
            maximum_bitrate_downlink,
            guaranteed_bitrate_uplink,
            guaranteed_bitrate_downlink,
        };
        value.validate_wire()?;
        Ok(value)
    }

    /// Return typed Allocation and Retention Priority fields.
    ///
    /// # Errors
    ///
    /// Returns a stable error if a directly constructed value contains spare
    /// bits or an invalid priority level.
    pub const fn allocation_retention_priority(
        &self,
    ) -> Result<AllocationRetentionPriority, BearerQosValidationError> {
        AllocationRetentionPriority::from_octet(self.priority_flags)
    }

    /// Return the standardized QCI resource type.
    ///
    /// # Errors
    ///
    /// Operator-specific QCI 128 through 254 returns
    /// [`BearerQosValidationError::OperatorResourceTypeRequired`]. Reserved
    /// QCI values return [`BearerQosValidationError::UnsupportedQci`].
    pub fn resource_type(&self) -> Result<BearerQosResourceType, BearerQosValidationError> {
        match qci_resource_type(self.qci)? {
            Some(resource_type) => Ok(resource_type),
            None => Err(BearerQosValidationError::OperatorResourceTypeRequired),
        }
    }

    /// Validate all standardized QCI, ARP, and bitrate semantics.
    ///
    /// # Errors
    ///
    /// Operator-specific QCIs require [`Self::validate_with_resource_type`].
    pub fn validate(&self) -> Result<(), BearerQosValidationError> {
        self.validate_common()?;
        let resource_type = self.resource_type()?;
        self.validate_rates(resource_type)
    }

    /// Validate using an explicit resource type for operator-specific QCIs.
    ///
    /// Standardized QCIs must agree with the supplied type; operator-specific
    /// QCIs 128 through 254 use it without inferring product policy.
    ///
    /// # Errors
    ///
    /// Returns a stable error for a standardized mismatch or invalid rates.
    pub fn validate_with_resource_type(
        &self,
        resource_type: BearerQosResourceType,
    ) -> Result<(), BearerQosValidationError> {
        self.validate_common()?;
        if qci_resource_type(self.qci)?.is_some_and(|expected| expected != resource_type) {
            return Err(BearerQosValidationError::ResourceTypeMismatch);
        }
        self.validate_rates(resource_type)
    }

    fn validate_common(&self) -> Result<(), BearerQosValidationError> {
        let _arp = self.allocation_retention_priority()?;
        let _classification = qci_resource_type(self.qci)?;
        if [
            self.maximum_bitrate_uplink,
            self.maximum_bitrate_downlink,
            self.guaranteed_bitrate_uplink,
            self.guaranteed_bitrate_downlink,
        ]
        .into_iter()
        .any(|rate| rate > MAX_BEARER_QOS_BITRATE_KBPS)
        {
            return Err(BearerQosValidationError::BitrateExceedsU40);
        }
        Ok(())
    }

    fn validate_rates(
        &self,
        resource_type: BearerQosResourceType,
    ) -> Result<(), BearerQosValidationError> {
        match resource_type {
            BearerQosResourceType::NonGbr => {
                if self.maximum_bitrate_uplink != 0
                    || self.maximum_bitrate_downlink != 0
                    || self.guaranteed_bitrate_uplink != 0
                    || self.guaranteed_bitrate_downlink != 0
                {
                    return Err(BearerQosValidationError::NonGbrRatesMustBeZero);
                }
            }
            BearerQosResourceType::Gbr => {
                if self.maximum_bitrate_uplink == 0 && self.maximum_bitrate_downlink == 0 {
                    return Err(BearerQosValidationError::GbrMaximumBitratesMustNotBothBeZero);
                }
                if self.guaranteed_bitrate_uplink > self.maximum_bitrate_uplink
                    || self.guaranteed_bitrate_downlink > self.maximum_bitrate_downlink
                {
                    return Err(BearerQosValidationError::GuaranteedBitrateExceedsMaximum);
                }
            }
        }
        Ok(())
    }

    fn validate_wire(&self) -> Result<(), BearerQosValidationError> {
        self.validate_common()?;
        if let Some(resource_type) = qci_resource_type(self.qci)? {
            self.validate_rates(resource_type)?;
        }
        Ok(())
    }

    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        require_exact_len(value, 22, offset, "Bearer QoS IE must be twenty-two octets")?;
        let decoded = Self {
            priority_flags: value[0],
            qci: value[1],
            maximum_bitrate_uplink: decode_u40(&value[2..7]),
            maximum_bitrate_downlink: decode_u40(&value[7..12]),
            guaranteed_bitrate_uplink: decode_u40(&value[12..17]),
            guaranteed_bitrate_downlink: decode_u40(&value[17..22]),
        };
        decoded.validate_wire().map_err(|error| {
            DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: error.reason(),
                },
                offset,
            )
            .with_spec_ref(spec_ref())
        })?;
        Ok(decoded)
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        self.validate_wire()
            .map_err(|error| encode_structural_error(error.reason()))?;
        dst.put_u8(self.priority_flags);
        dst.put_u8(self.qci);
        encode_u40(self.maximum_bitrate_uplink, dst)?;
        encode_u40(self.maximum_bitrate_downlink, dst)?;
        encode_u40(self.guaranteed_bitrate_uplink, dst)?;
        encode_u40(self.guaranteed_bitrate_downlink, dst)?;
        Ok(())
    }
}

impl fmt::Debug for BearerQos {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BearerQos")
            .field("qci", &self.qci)
            .field(
                "allocation_retention_priority_valid",
                &self.allocation_retention_priority().is_ok(),
            )
            .field(
                "maximum_bitrates_present",
                &(self.maximum_bitrate_uplink != 0 || self.maximum_bitrate_downlink != 0),
            )
            .field(
                "guaranteed_bitrates_present",
                &(self.guaranteed_bitrate_uplink != 0 || self.guaranteed_bitrate_downlink != 0),
            )
            .finish()
    }
}

fn qci_resource_type(qci: u8) -> Result<Option<BearerQosResourceType>, BearerQosValidationError> {
    match qci {
        1..=4 | 65..=67 | 71..=76 | 82..=85 => Ok(Some(BearerQosResourceType::Gbr)),
        5..=10 | 69..=70 | 79..=80 => Ok(Some(BearerQosResourceType::NonGbr)),
        128..=254 => Ok(None),
        _ => Err(BearerQosValidationError::UnsupportedQci),
    }
}

/// RAT Type values used by the S2b subset.
///
/// @spec 3GPP TS29274 R18 8.17
/// @req REQ-3GPP-TS29274-R18-S2B-IE-RAT-001
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatTypeValue {
    /// UTRAN (1).
    Utran,
    /// GERAN (2).
    Geran,
    /// WLAN / non-3GPP untrusted access (3).
    Wlan,
    /// GAN (4).
    Gan,
    /// HSPA Evolution (5).
    HspaEvolution,
    /// E-UTRAN (6).
    Eutran,
    /// Virtual (7).
    Virtual,
    /// Unmodelled RAT type.
    Unknown(u8),
}

impl From<u8> for RatTypeValue {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Utran,
            2 => Self::Geran,
            3 => Self::Wlan,
            4 => Self::Gan,
            5 => Self::HspaEvolution,
            6 => Self::Eutran,
            7 => Self::Virtual,
            other => Self::Unknown(other),
        }
    }
}

impl From<RatTypeValue> for u8 {
    fn from(value: RatTypeValue) -> Self {
        match value {
            RatTypeValue::Utran => 1,
            RatTypeValue::Geran => 2,
            RatTypeValue::Wlan => 3,
            RatTypeValue::Gan => 4,
            RatTypeValue::HspaEvolution => 5,
            RatTypeValue::Eutran => 6,
            RatTypeValue::Virtual => 7,
            RatTypeValue::Unknown(other) => other,
        }
    }
}

/// RAT Type IE (type 82).
///
/// @spec 3GPP TS29274 R18 8.17
/// @req REQ-3GPP-TS29274-R18-S2B-IE-RAT-002
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatType {
    /// RAT type value.
    pub value: RatTypeValue,
}

impl RatType {
    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        require_exact_len(value, 1, offset, "RAT Type IE must be one octet")?;
        Ok(Self {
            value: RatTypeValue::from(value[0]),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u8(self.value.into());
        Ok(())
    }
}

/// Public Land Mobile Network identifier used by Serving Network.
///
/// @spec 3GPP TS29274 R18 8.18
/// @req REQ-3GPP-TS29274-R18-S2B-IE-PLMN-001
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlmnId {
    /// Three-decimal-digit Mobile Country Code.
    pub mcc: String,
    /// Two- or three-decimal-digit Mobile Network Code.
    pub mnc: String,
}

impl PlmnId {
    /// Construct a PLMN identifier from MCC and MNC strings.
    pub fn new(mcc: impl Into<String>, mnc: impl Into<String>) -> Self {
        Self {
            mcc: mcc.into(),
            mnc: mnc.into(),
        }
    }

    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        require_exact_len(value, 3, offset, "PLMN ID must be three octets")?;
        let mcc1 = value[0] & 0x0f;
        let mcc2 = (value[0] >> 4) & 0x0f;
        let mcc3 = value[1] & 0x0f;
        let mnc3 = (value[1] >> 4) & 0x0f;
        let mnc1 = value[2] & 0x0f;
        let mnc2 = (value[2] >> 4) & 0x0f;

        let mut mcc = String::with_capacity(3);
        push_tbcd_digit(&mut mcc, mcc1, offset)?;
        push_tbcd_digit(&mut mcc, mcc2, offset)?;
        push_tbcd_digit(&mut mcc, mcc3, checked_add_offset(offset, 1)?)?;

        let mut mnc = String::with_capacity(3);
        push_tbcd_digit(&mut mnc, mnc1, checked_add_offset(offset, 2)?)?;
        push_tbcd_digit(&mut mnc, mnc2, checked_add_offset(offset, 2)?)?;
        if mnc3 != 0x0f {
            push_tbcd_digit(&mut mnc, mnc3, checked_add_offset(offset, 1)?)?;
        }

        Ok(Self { mcc, mnc })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        validate_decimal_digits(&self.mcc, "MCC must contain three digits")?;
        validate_decimal_digits(&self.mnc, "MNC must contain two or three digits")?;
        if self.mcc.len() != 3 || !(self.mnc.len() == 2 || self.mnc.len() == 3) {
            return Err(encode_structural_error(
                "PLMN MCC must be 3 digits and MNC must be 2 or 3 digits",
            ));
        }
        let mcc = self.mcc.as_bytes();
        let mnc = self.mnc.as_bytes();
        let d = |byte: u8| byte - b'0';
        let mnc3 = if mnc.len() == 3 { d(mnc[2]) } else { 0x0f };
        dst.put_u8((d(mcc[1]) << 4) | d(mcc[0]));
        dst.put_u8((mnc3 << 4) | d(mcc[2]));
        dst.put_u8((d(mnc[1]) << 4) | d(mnc[0]));
        Ok(())
    }
}

/// Serving Network IE (type 83).
///
/// @spec 3GPP TS29274 R18 8.18
/// @req REQ-3GPP-TS29274-R18-S2B-IE-SERVING-NETWORK-001
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServingNetwork {
    /// Serving PLMN identity.
    pub plmn: PlmnId,
}

impl ServingNetwork {
    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        Ok(Self {
            plmn: PlmnId::decode_value(value, offset)?,
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        self.plmn.encode_value(dst)
    }
}

/// Fully Qualified Tunnel Endpoint Identifier IE (type 87).
///
/// @spec 3GPP TS29274 R18 8.22
/// @req REQ-3GPP-TS29274-R18-S2B-IE-FTEID-001
#[derive(Clone, PartialEq, Eq)]
pub struct FullyQualifiedTeid {
    /// Six-bit GTPv2-C interface type.
    pub interface_type: u8,
    /// Tunnel Endpoint Identifier / GRE key.
    pub teid: u32,
    /// IPv4 endpoint address if the V4 flag is set.
    pub ipv4: Option<[u8; 4]>,
    /// IPv6 endpoint address if the V6 flag is set.
    pub ipv6: Option<[u8; 16]>,
}

impl fmt::Debug for FullyQualifiedTeid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FullyQualifiedTeid")
            .field("interface_type", &self.interface_type)
            .field("teid", &"<redacted>")
            .field("ipv4_present", &self.ipv4.is_some())
            .field("ipv6_present", &self.ipv6.is_some())
            .finish()
    }
}

impl FullyQualifiedTeid {
    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        require_min_len(value, 5, offset, "F-TEID IE must include flags and TEID")?;
        let flags = value[0];
        let has_ipv4 = (flags & 0x80) != 0;
        let has_ipv6 = (flags & 0x40) != 0;
        if !has_ipv4 && !has_ipv6 {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "F-TEID IE must set V4, V6, or both",
                },
                offset,
            )
            .with_spec_ref(spec_ref()));
        }
        let interface_type = flags & 0x3f;
        let teid = u32::from_be_bytes([value[1], value[2], value[3], value[4]]);
        let mut position = 5usize;
        let mut ipv4 = None;
        let mut ipv6 = None;
        if has_ipv4 {
            let end = position.checked_add(4).ok_or_else(|| {
                DecodeError::new(DecodeErrorCode::LengthOverflow, position)
                    .with_spec_ref(spec_ref())
            })?;
            if value.len() < end {
                return Err(DecodeError::new(
                    DecodeErrorCode::Truncated,
                    checked_add_offset(offset, position)?,
                )
                .with_spec_ref(spec_ref()));
            }
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&value[position..end]);
            ipv4 = Some(addr);
            position = end;
        }
        if has_ipv6 {
            let end = position.checked_add(16).ok_or_else(|| {
                DecodeError::new(DecodeErrorCode::LengthOverflow, position)
                    .with_spec_ref(spec_ref())
            })?;
            if value.len() < end {
                return Err(DecodeError::new(
                    DecodeErrorCode::Truncated,
                    checked_add_offset(offset, position)?,
                )
                .with_spec_ref(spec_ref()));
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&value[position..end]);
            ipv6 = Some(addr);
            position = end;
        }
        if position != value.len() {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "F-TEID IE contains trailing bytes after address fields",
                },
                checked_add_offset(offset, position)?,
            )
            .with_spec_ref(spec_ref()));
        }
        Ok(Self {
            interface_type,
            teid,
            ipv4,
            ipv6,
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        if self.ipv4.is_none() && self.ipv6.is_none() {
            return Err(encode_structural_error(
                "F-TEID IE must set V4, V6, or both",
            ));
        }
        if self.interface_type > 0x3f {
            return Err(encode_structural_error(
                "F-TEID interface type must be a six-bit value",
            ));
        }
        let mut flags = self.interface_type;
        if self.ipv4.is_some() {
            flags |= 0x80;
        }
        if self.ipv6.is_some() {
            flags |= 0x40;
        }
        dst.put_u8(flags);
        dst.put_u32(self.teid);
        if let Some(ipv4) = self.ipv4 {
            dst.put_slice(&ipv4);
        }
        if let Some(ipv6) = self.ipv6 {
            dst.put_slice(&ipv6);
        }
        Ok(())
    }
}

/// PDN type values shared by PDN Type and PAA IEs.
///
/// @spec 3GPP TS29274 R18 8.34, 8.14
/// @req REQ-3GPP-TS29274-R18-S2B-IE-PDN-TYPE-001
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdnTypeValue {
    /// IPv4 PDN type (1).
    Ipv4,
    /// IPv6 PDN type (2).
    Ipv6,
    /// IPv4v6 PDN type (3).
    Ipv4v6,
    /// Non-IP PDN type (4).
    NonIp,
    /// Ethernet PDN type (5).
    Ethernet,
    /// Unmodelled PDN type value.
    Unknown(u8),
}

impl From<u8> for PdnTypeValue {
    fn from(value: u8) -> Self {
        match value & 0x07 {
            1 => Self::Ipv4,
            2 => Self::Ipv6,
            3 => Self::Ipv4v6,
            4 => Self::NonIp,
            5 => Self::Ethernet,
            other => Self::Unknown(other),
        }
    }
}

impl From<PdnTypeValue> for u8 {
    fn from(value: PdnTypeValue) -> Self {
        match value {
            PdnTypeValue::Ipv4 => 1,
            PdnTypeValue::Ipv6 => 2,
            PdnTypeValue::Ipv4v6 => 3,
            PdnTypeValue::NonIp => 4,
            PdnTypeValue::Ethernet => 5,
            PdnTypeValue::Unknown(other) => other & 0x07,
        }
    }
}

/// PDN Type IE (type 99).
///
/// @spec 3GPP TS29274 R18 8.34
/// @req REQ-3GPP-TS29274-R18-S2B-IE-PDN-TYPE-002
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdnType {
    /// PDN type value.
    pub value: PdnTypeValue,
}

impl PdnType {
    fn decode_value(value: &[u8], offset: usize, ctx: DecodeContext) -> Result<Self, DecodeError> {
        require_exact_len(value, 1, offset, "PDN Type IE must be one octet")?;
        if crate::is_strict(ctx.validation_level) && (value[0] & 0xf8) != 0 {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "PDN Type spare bits must be zero",
                },
                offset,
            )
            .with_spec_ref(spec_ref()));
        }
        Ok(Self {
            value: PdnTypeValue::from(value[0]),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u8(u8::from(self.value) & 0x07);
        Ok(())
    }
}

/// PDN Address Allocation IE (type 79).
///
/// @spec 3GPP TS29274 R18 8.14
/// @req REQ-3GPP-TS29274-R18-S2B-IE-PAA-001
///
/// Use the explicit dynamic/static constructors when building S2b Create
/// Session Requests. They distinguish the all-zero dynamic-allocation wire
/// form from an AAA-provided static allocation and keep the PDN family and
/// address fields consistent.
#[derive(Clone, PartialEq, Eq)]
pub struct PdnAddressAllocation {
    /// PDN type encoded in the low three bits of the first value octet.
    pub pdn_type: PdnTypeValue,
    /// IPv6 prefix length, present for IPv6 and IPv4v6 PAA values.
    pub ipv6_prefix_length: Option<u8>,
    /// IPv6 prefix/address bytes, present for IPv6 and IPv4v6 PAA values.
    pub ipv6_prefix: Option<[u8; 16]>,
    /// IPv4 address, present for IPv4 and IPv4v6 PAA values.
    pub ipv4: Option<[u8; 4]>,
}

/// Fixed IPv6 prefix length used by an assigned PAA value.
///
/// TS 29.274 clause 8.14 fixes an assigned IPv6 PAA prefix at /64. A dynamic
/// Create Session Request instead carries a zero prefix length and all-zero
/// prefix/address fields.
pub const PAA_ASSIGNED_IPV6_PREFIX_LENGTH: u8 = 64;

/// Validation error for a typed [`PdnAddressAllocation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdnAddressAllocationError {
    /// The PDN type uses a reserved value.
    ReservedPdnType,
    /// The selected PDN type requires an IPv4 address field.
    MissingIpv4Address,
    /// The selected PDN type prohibits an IPv4 address field.
    UnexpectedIpv4Address,
    /// The selected PDN type requires an IPv6 prefix-length field.
    MissingIpv6PrefixLength,
    /// The selected PDN type prohibits an IPv6 prefix-length field.
    UnexpectedIpv6PrefixLength,
    /// The IPv6 prefix length is neither the dynamic value 0 nor assigned value 64.
    InvalidIpv6PrefixLength,
    /// The selected PDN type requires an IPv6 prefix/address field.
    MissingIpv6Prefix,
    /// The selected PDN type prohibits an IPv6 prefix/address field.
    UnexpectedIpv6Prefix,
    /// A static IPv4 allocation used the all-zero dynamic-allocation value.
    StaticIpv4AddressUnspecified,
    /// A static IPv6 allocation used an all-zero prefix/address value.
    StaticIpv6PrefixUnspecified,
    /// A static IPv4v6 allocation did not provide either address family.
    StaticIpv4v6AddressMissing,
}

impl PdnAddressAllocationError {
    /// Stable machine-readable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReservedPdnType => "gtpv2c_paa_reserved_pdn_type",
            Self::MissingIpv4Address => "gtpv2c_paa_ipv4_missing",
            Self::UnexpectedIpv4Address => "gtpv2c_paa_ipv4_unexpected",
            Self::MissingIpv6PrefixLength => "gtpv2c_paa_ipv6_prefix_length_missing",
            Self::UnexpectedIpv6PrefixLength => "gtpv2c_paa_ipv6_prefix_length_unexpected",
            Self::InvalidIpv6PrefixLength => "gtpv2c_paa_ipv6_prefix_length_invalid",
            Self::MissingIpv6Prefix => "gtpv2c_paa_ipv6_prefix_missing",
            Self::UnexpectedIpv6Prefix => "gtpv2c_paa_ipv6_prefix_unexpected",
            Self::StaticIpv4AddressUnspecified => "gtpv2c_paa_static_ipv4_unspecified",
            Self::StaticIpv6PrefixUnspecified => "gtpv2c_paa_static_ipv6_unspecified",
            Self::StaticIpv4v6AddressMissing => "gtpv2c_paa_static_ipv4v6_missing",
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::ReservedPdnType => "PAA PDN type is reserved",
            Self::MissingIpv4Address => "PAA PDN type requires an IPv4 address",
            Self::UnexpectedIpv4Address => "PAA PDN type prohibits an IPv4 address",
            Self::MissingIpv6PrefixLength => "PAA PDN type requires an IPv6 prefix length",
            Self::UnexpectedIpv6PrefixLength => {
                "PAA PDN type prohibits an IPv6 prefix length"
            }
            Self::InvalidIpv6PrefixLength => {
                "PAA IPv6 prefix length must be zero for dynamic allocation or 64 for assigned allocation"
            }
            Self::MissingIpv6Prefix => "PAA PDN type requires an IPv6 prefix",
            Self::UnexpectedIpv6Prefix => "PAA PDN type prohibits an IPv6 prefix",
            Self::StaticIpv4AddressUnspecified => {
                "static PAA IPv4 address must not be the dynamic all-zero value"
            }
            Self::StaticIpv6PrefixUnspecified => {
                "static PAA IPv6 prefix must not be the dynamic all-zero value"
            }
            Self::StaticIpv4v6AddressMissing => {
                "static IPv4v6 PAA requires at least one assigned address family"
            }
        }
    }
}

impl fmt::Display for PdnAddressAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for PdnAddressAllocationError {}

impl fmt::Debug for PdnAddressAllocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PdnAddressAllocation")
            .field("pdn_type", &self.pdn_type)
            .field("ipv6_prefix_length", &self.ipv6_prefix_length)
            .field("ipv6_present", &self.ipv6_prefix.is_some())
            .field("ipv4_present", &self.ipv4.is_some())
            .finish()
    }
}

impl PdnAddressAllocation {
    /// Build the all-zero dynamic IPv4 allocation request.
    #[must_use]
    pub const fn dynamic_ipv4() -> Self {
        Self {
            pdn_type: PdnTypeValue::Ipv4,
            ipv6_prefix_length: None,
            ipv6_prefix: None,
            ipv4: Some([0; 4]),
        }
    }

    /// Build the all-zero dynamic IPv6 allocation request.
    #[must_use]
    pub const fn dynamic_ipv6() -> Self {
        Self {
            pdn_type: PdnTypeValue::Ipv6,
            ipv6_prefix_length: Some(0),
            ipv6_prefix: Some([0; 16]),
            ipv4: None,
        }
    }

    /// Build the all-zero dynamic dual-stack allocation request.
    #[must_use]
    pub const fn dynamic_ipv4v6() -> Self {
        Self {
            pdn_type: PdnTypeValue::Ipv4v6,
            ipv6_prefix_length: Some(0),
            ipv6_prefix: Some([0; 16]),
            ipv4: Some([0; 4]),
        }
    }

    /// Build an AAA-provided static IPv4 allocation.
    ///
    /// # Errors
    ///
    /// Returns [`PdnAddressAllocationError::StaticIpv4AddressUnspecified`]
    /// when `ipv4` is the all-zero dynamic-allocation value.
    pub fn static_ipv4(ipv4: [u8; 4]) -> Result<Self, PdnAddressAllocationError> {
        if ipv4 == [0; 4] {
            return Err(PdnAddressAllocationError::StaticIpv4AddressUnspecified);
        }
        Ok(Self {
            pdn_type: PdnTypeValue::Ipv4,
            ipv6_prefix_length: None,
            ipv6_prefix: None,
            ipv4: Some(ipv4),
        })
    }

    /// Build an AAA-provided static IPv6 allocation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the assigned prefix length is 64 and the
    /// supplied prefix/address is non-zero.
    pub fn static_ipv6(
        ipv6_prefix_length: u8,
        ipv6_prefix: [u8; 16],
    ) -> Result<Self, PdnAddressAllocationError> {
        validate_static_ipv6(ipv6_prefix_length, ipv6_prefix)?;
        Ok(Self {
            pdn_type: PdnTypeValue::Ipv6,
            ipv6_prefix_length: Some(ipv6_prefix_length),
            ipv6_prefix: Some(ipv6_prefix),
            ipv4: None,
        })
    }

    /// Build an AAA-provided static dual-stack allocation.
    ///
    /// A subscription may provide either family or both. A missing family is
    /// encoded with the all-zero values required by TS 29.274 Table 7.2.1-1.
    ///
    /// # Errors
    ///
    /// Returns an error if neither family is supplied, if a supplied family
    /// uses its all-zero dynamic value, or if an IPv6 allocation is not /64.
    pub fn static_ipv4v6(
        ipv4: Option<[u8; 4]>,
        ipv6: Option<(u8, [u8; 16])>,
    ) -> Result<Self, PdnAddressAllocationError> {
        if ipv4.is_none() && ipv6.is_none() {
            return Err(PdnAddressAllocationError::StaticIpv4v6AddressMissing);
        }
        if ipv4.is_some_and(|address| address == [0; 4]) {
            return Err(PdnAddressAllocationError::StaticIpv4AddressUnspecified);
        }
        if let Some((prefix_length, prefix)) = ipv6 {
            validate_static_ipv6(prefix_length, prefix)?;
        }
        let (ipv6_prefix_length, ipv6_prefix) = ipv6
            .map_or((Some(0), Some([0; 16])), |(prefix_length, prefix)| {
                (Some(prefix_length), Some(prefix))
            });
        Ok(Self {
            pdn_type: PdnTypeValue::Ipv4v6,
            ipv6_prefix_length,
            ipv6_prefix,
            ipv4: Some(ipv4.unwrap_or([0; 4])),
        })
    }

    /// Build a Non-IP PAA value with no address octets.
    #[must_use]
    pub const fn non_ip() -> Self {
        Self {
            pdn_type: PdnTypeValue::NonIp,
            ipv6_prefix_length: None,
            ipv6_prefix: None,
            ipv4: None,
        }
    }

    /// Build an Ethernet PAA value with no address octets.
    #[must_use]
    pub const fn ethernet() -> Self {
        Self {
            pdn_type: PdnTypeValue::Ethernet,
            ipv6_prefix_length: None,
            ipv6_prefix: None,
            ipv4: None,
        }
    }

    /// Validate the PDN type and address-field shape.
    ///
    /// Dynamic IP requests use zero values, while assigned IPv6 values use the
    /// fixed /64 prefix length from TS 29.274 clause 8.14.
    pub fn validate(&self) -> Result<(), PdnAddressAllocationError> {
        match self.pdn_type {
            PdnTypeValue::Ipv4 => {
                if self.ipv4.is_none() {
                    return Err(PdnAddressAllocationError::MissingIpv4Address);
                }
                if self.ipv6_prefix_length.is_some() {
                    return Err(PdnAddressAllocationError::UnexpectedIpv6PrefixLength);
                }
                if self.ipv6_prefix.is_some() {
                    return Err(PdnAddressAllocationError::UnexpectedIpv6Prefix);
                }
            }
            PdnTypeValue::Ipv6 => {
                if self.ipv4.is_some() {
                    return Err(PdnAddressAllocationError::UnexpectedIpv4Address);
                }
                validate_ipv6_shape(self.ipv6_prefix_length, self.ipv6_prefix)?;
            }
            PdnTypeValue::Ipv4v6 => {
                if self.ipv4.is_none() {
                    return Err(PdnAddressAllocationError::MissingIpv4Address);
                }
                validate_ipv6_shape(self.ipv6_prefix_length, self.ipv6_prefix)?;
            }
            PdnTypeValue::NonIp | PdnTypeValue::Ethernet => {
                if self.ipv4.is_some() {
                    return Err(PdnAddressAllocationError::UnexpectedIpv4Address);
                }
                if self.ipv6_prefix_length.is_some() {
                    return Err(PdnAddressAllocationError::UnexpectedIpv6PrefixLength);
                }
                if self.ipv6_prefix.is_some() {
                    return Err(PdnAddressAllocationError::UnexpectedIpv6Prefix);
                }
            }
            PdnTypeValue::Unknown(_) => {
                return Err(PdnAddressAllocationError::ReservedPdnType);
            }
        }
        Ok(())
    }

    fn decode_value(value: &[u8], offset: usize, ctx: DecodeContext) -> Result<Self, DecodeError> {
        require_min_len(value, 1, offset, "PAA IE must contain the PDN type octet")?;
        if crate::is_strict(ctx.validation_level) && (value[0] & 0xf8) != 0 {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "PAA spare bits must be zero",
                },
                offset,
            )
            .with_spec_ref(spec_ref()));
        }
        let pdn_type = PdnTypeValue::from(value[0]);
        let decoded = match pdn_type {
            PdnTypeValue::Ipv4 => {
                require_exact_len(value, 5, offset, "IPv4 PAA must be five octets")?;
                let mut ipv4 = [0u8; 4];
                ipv4.copy_from_slice(&value[1..5]);
                Self {
                    pdn_type,
                    ipv6_prefix_length: None,
                    ipv6_prefix: None,
                    ipv4: Some(ipv4),
                }
            }
            PdnTypeValue::Ipv6 => {
                require_exact_len(value, 18, offset, "IPv6 PAA must be eighteen octets")?;
                let mut ipv6 = [0u8; 16];
                ipv6.copy_from_slice(&value[2..18]);
                Self {
                    pdn_type,
                    ipv6_prefix_length: Some(value[1]),
                    ipv6_prefix: Some(ipv6),
                    ipv4: None,
                }
            }
            PdnTypeValue::Ipv4v6 => {
                require_exact_len(value, 22, offset, "IPv4v6 PAA must be twenty-two octets")?;
                let mut ipv6 = [0u8; 16];
                ipv6.copy_from_slice(&value[2..18]);
                let mut ipv4 = [0u8; 4];
                ipv4.copy_from_slice(&value[18..22]);
                Self {
                    pdn_type,
                    ipv6_prefix_length: Some(value[1]),
                    ipv6_prefix: Some(ipv6),
                    ipv4: Some(ipv4),
                }
            }
            PdnTypeValue::NonIp | PdnTypeValue::Ethernet | PdnTypeValue::Unknown(_) => {
                require_exact_len(
                    value,
                    1,
                    offset,
                    "Non-IP, Ethernet, and unknown PAA values must be one octet",
                )?;
                Self {
                    pdn_type,
                    ipv6_prefix_length: None,
                    ipv6_prefix: None,
                    ipv4: None,
                }
            }
        };
        if crate::is_strict(ctx.validation_level) {
            decoded.validate().map_err(|error| {
                DecodeError::new(
                    DecodeErrorCode::Structural {
                        reason: error.reason(),
                    },
                    offset,
                )
                .with_spec_ref(spec_ref())
            })?;
        }
        Ok(decoded)
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        self.validate()
            .map_err(|error| encode_structural_error(error.reason()))?;
        dst.put_u8(u8::from(self.pdn_type) & 0x07);
        match self.pdn_type {
            PdnTypeValue::Ipv4 => {
                let ipv4 = self
                    .ipv4
                    .ok_or_else(|| encode_structural_error("IPv4 PAA requires an IPv4 address"))?;
                dst.put_slice(&ipv4);
            }
            PdnTypeValue::Ipv6 => {
                let prefix_len = self.ipv6_prefix_length.ok_or_else(|| {
                    encode_structural_error("IPv6 PAA requires an IPv6 prefix length")
                })?;
                let prefix = self
                    .ipv6_prefix
                    .ok_or_else(|| encode_structural_error("IPv6 PAA requires an IPv6 prefix"))?;
                dst.put_u8(prefix_len);
                dst.put_slice(&prefix);
            }
            PdnTypeValue::Ipv4v6 => {
                let prefix_len = self.ipv6_prefix_length.ok_or_else(|| {
                    encode_structural_error("IPv4v6 PAA requires an IPv6 prefix length")
                })?;
                let prefix = self
                    .ipv6_prefix
                    .ok_or_else(|| encode_structural_error("IPv4v6 PAA requires an IPv6 prefix"))?;
                let ipv4 = self.ipv4.ok_or_else(|| {
                    encode_structural_error("IPv4v6 PAA requires an IPv4 address")
                })?;
                dst.put_u8(prefix_len);
                dst.put_slice(&prefix);
                dst.put_slice(&ipv4);
            }
            PdnTypeValue::NonIp | PdnTypeValue::Ethernet | PdnTypeValue::Unknown(_) => {}
        }
        Ok(())
    }
}

fn validate_ipv6_shape(
    prefix_length: Option<u8>,
    prefix: Option<[u8; 16]>,
) -> Result<(), PdnAddressAllocationError> {
    let Some(prefix_length) = prefix_length else {
        return Err(PdnAddressAllocationError::MissingIpv6PrefixLength);
    };
    if prefix_length != 0 && prefix_length != PAA_ASSIGNED_IPV6_PREFIX_LENGTH {
        return Err(PdnAddressAllocationError::InvalidIpv6PrefixLength);
    }
    if prefix.is_none() {
        return Err(PdnAddressAllocationError::MissingIpv6Prefix);
    }
    Ok(())
}

fn validate_static_ipv6(
    prefix_length: u8,
    prefix: [u8; 16],
) -> Result<(), PdnAddressAllocationError> {
    if prefix_length != PAA_ASSIGNED_IPV6_PREFIX_LENGTH {
        return Err(PdnAddressAllocationError::InvalidIpv6PrefixLength);
    }
    if prefix == [0; 16] {
        return Err(PdnAddressAllocationError::StaticIpv6PrefixUnspecified);
    }
    Ok(())
}

/// APN Restriction IE (type 127).
///
/// @spec 3GPP TS29274 R18 8.57
/// @req REQ-3GPP-TS29274-R18-S2B-IE-APN-RESTRICTION-001
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApnRestriction {
    /// APN restriction value.
    pub value: u8,
}

impl ApnRestriction {
    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        require_exact_len(value, 1, offset, "APN Restriction IE must be one octet")?;
        Ok(Self { value: value[0] })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u8(self.value);
        Ok(())
    }
}

/// Selection Mode values used by S2b Create Session Request.
///
/// @spec 3GPP TS29274 R18 8.58
/// @req REQ-3GPP-TS29274-R18-S2B-IE-SELECTION-MODE-001
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionModeValue {
    /// MS or network provided APN, subscription verified (0).
    MsOrNetworkProvidedSubscriptionVerified,
    /// MS provided APN, subscription not verified (1).
    MsProvidedSubscriptionNotVerified,
    /// Network provided APN, subscription not verified (2).
    NetworkProvidedSubscriptionNotVerified,
    /// Unmodelled selection mode.
    Unknown(u8),
}

impl From<u8> for SelectionModeValue {
    fn from(value: u8) -> Self {
        match value & 0x03 {
            0 => Self::MsOrNetworkProvidedSubscriptionVerified,
            1 => Self::MsProvidedSubscriptionNotVerified,
            2 => Self::NetworkProvidedSubscriptionNotVerified,
            other => Self::Unknown(other),
        }
    }
}

impl From<SelectionModeValue> for u8 {
    fn from(value: SelectionModeValue) -> Self {
        match value {
            SelectionModeValue::MsOrNetworkProvidedSubscriptionVerified => 0,
            SelectionModeValue::MsProvidedSubscriptionNotVerified => 1,
            SelectionModeValue::NetworkProvidedSubscriptionNotVerified => 2,
            SelectionModeValue::Unknown(other) => other & 0x03,
        }
    }
}

/// Selection Mode IE (type 128).
///
/// @spec 3GPP TS29274 R18 8.58
/// @req REQ-3GPP-TS29274-R18-S2B-IE-SELECTION-MODE-002
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionMode {
    /// Selection mode value.
    pub value: SelectionModeValue,
}

impl SelectionMode {
    fn decode_value(value: &[u8], offset: usize, ctx: DecodeContext) -> Result<Self, DecodeError> {
        require_exact_len(value, 1, offset, "Selection Mode IE must be one octet")?;
        if crate::is_strict(ctx.validation_level) && (value[0] & 0xfc) != 0 {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "Selection Mode spare bits must be zero",
                },
                offset,
            )
            .with_spec_ref(spec_ref()));
        }
        Ok(Self {
            value: SelectionModeValue::from(value[0]),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u8(u8::from(self.value) & 0x03);
        Ok(())
    }
}

/// Bearer Context grouped IE (type 93).
///
/// The grouped value is decoded as a sequence of typed GTPv2-C IEs, with raw
/// fallback for unsupported bearer members.
///
/// @spec 3GPP TS29274 R18 8.28
/// @req REQ-3GPP-TS29274-R18-S2B-IE-BEARER-CONTEXT-001
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerContext<'a> {
    /// Grouped bearer member IEs.
    pub members: Vec<TypedIe<'a>>,
}

impl<'a> BearerContext<'a> {
    /// Decode the grouped bearer value.
    ///
    /// `base_offset` is the absolute byte position of the first value octet
    /// of this Bearer Context IE within the containing input (i.e. just after
    /// the four-octet TLIV header). It is passed through to nested decoders so
    /// that errors inside grouped members report offsets relative to the
    /// message rather than to the grouped value.
    fn decode_value(
        value: &'a [u8],
        ctx: DecodeContext,
        depth: usize,
        base_offset: usize,
        instance: u8,
        policy: IeDecodePolicy<'_>,
        duplicate_evidence: &mut DuplicateIeCollector,
    ) -> Result<Self, DecodeError> {
        if depth.saturating_add(1) > ctx.max_depth {
            return Err(
                DecodeError::new(DecodeErrorCode::DepthExceeded, base_offset)
                    .with_spec_ref(spec_ref()),
            );
        }
        Ok(Self {
            members: decode_typed_ie_sequence_at(
                value,
                ctx,
                IeSequencePosition {
                    depth: depth.saturating_add(1),
                    base_offset,
                    parent_ie: Some((IE_TYPE_BEARER_CONTEXT, instance)),
                },
                policy,
                duplicate_evidence,
            )?,
        })
    }

    fn encode_value(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        for member in &self.members {
            member.encode(dst, ctx)?;
        }
        Ok(())
    }
}

/// Charging ID IE (type 94).
///
/// @spec 3GPP TS29274 R18 8.29
/// @req REQ-3GPP-TS29274-R18-S2B-IE-CHARGING-ID-001
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChargingId {
    /// Charging identifier value.
    pub value: u32,
}

impl fmt::Debug for ChargingId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChargingId")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl ChargingId {
    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        require_exact_len(value, 4, offset, "Charging ID IE must be four octets")?;
        Ok(Self {
            value: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u32(self.value);
        Ok(())
    }
}

/// Additional Protocol Configuration Options IE (type 163).
///
/// APCO carries an additional TS 24.008 protocol-configuration container. Like
/// PCO, this typed view keeps nested protocol identifiers opaque and
/// byte-exact.
///
/// @spec 3GPP TS29274 R18 8.104
/// @req REQ-3GPP-TS29274-R18-S2B-IE-APCO-001
#[derive(Clone, PartialEq, Eq)]
pub struct AdditionalProtocolConfigurationOptions {
    /// Raw additional protocol-configuration container bytes.
    pub value: Vec<u8>,
}

impl AdditionalProtocolConfigurationOptions {
    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        require_min_len(
            value,
            1,
            offset,
            "Additional Protocol Configuration Options IE must not be empty",
        )?;
        Ok(Self {
            value: value.to_vec(),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        if self.value.is_empty() {
            return Err(encode_structural_error(
                "Additional Protocol Configuration Options IE must not be empty",
            ));
        }
        dst.put_slice(&self.value);
        Ok(())
    }
}

impl fmt::Debug for AdditionalProtocolConfigurationOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdditionalProtocolConfigurationOptions")
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// Typed GTPv2-C IE value subset for S2b message views.
///
/// @spec 3GPP TS29274 R18 8.2
/// @req REQ-3GPP-TS29274-R18-S2B-IE-002
#[derive(Clone, PartialEq, Eq)]
pub enum TypedIeValue<'a> {
    /// IMSI IE (type 1).
    Imsi(TbcdDigits),
    /// Cause IE (type 2).
    Cause(Cause),
    /// Recovery IE (type 3).
    Recovery(Recovery),
    /// APN IE (type 71).
    AccessPointName(AccessPointName),
    /// Aggregate Maximum Bit Rate IE (type 72).
    AggregateMaximumBitRate(AggregateMaximumBitRate),
    /// EPS Bearer ID IE (type 73).
    EpsBearerId(EpsBearerId),
    /// MEI IE (type 75).
    Mei(TbcdDigits),
    /// MSISDN IE (type 76).
    Msisdn(TbcdDigits),
    /// Indication IE (type 77).
    Indication(Indication),
    /// Protocol Configuration Options IE (type 78).
    ProtocolConfigurationOptions(ProtocolConfigurationOptions),
    /// PDN Address Allocation IE (type 79).
    PdnAddressAllocation(PdnAddressAllocation),
    /// Bearer QoS IE (type 80).
    BearerQos(BearerQos),
    /// RAT Type IE (type 82).
    RatType(RatType),
    /// Serving Network IE (type 83).
    ServingNetwork(ServingNetwork),
    /// EPS Bearer Level Traffic Flow Template IE (type 84).
    BearerTft(TrafficFlowTemplate),
    /// Fully Qualified TEID IE (type 87).
    FullyQualifiedTeid(FullyQualifiedTeid),
    /// Bearer Context IE (type 93).
    BearerContext(BearerContext<'a>),
    /// Charging ID IE (type 94).
    ChargingId(ChargingId),
    /// PDN Type IE (type 99).
    PdnType(PdnType),
    /// APN Restriction IE (type 127).
    ApnRestriction(ApnRestriction),
    /// Selection Mode IE (type 128).
    SelectionMode(SelectionMode),
    /// Additional Protocol Configuration Options IE (type 163).
    AdditionalProtocolConfigurationOptions(AdditionalProtocolConfigurationOptions),
    /// Unsupported, unknown, private, or future IE preserved byte-exact.
    Raw(RawIe<'a>),
}

/// A typed GTPv2-C IE with its four-bit instance preserved.
///
/// @spec 3GPP TS29274 R18 8.2
/// @req REQ-3GPP-TS29274-R18-S2B-IE-003
#[derive(Clone, PartialEq, Eq)]
pub struct TypedIe<'a> {
    /// IE instance from the low four bits of the TLIV instance octet.
    pub instance: u8,
    /// Decoded typed value or raw fallback.
    pub value: TypedIeValue<'a>,
}

impl<'a> TypedIe<'a> {
    /// Decode a sequence of GTPv2-C IEs into typed values with raw fallback.
    pub fn decode_sequence(input: &'a [u8], ctx: DecodeContext) -> Result<Vec<Self>, DecodeError> {
        decode_typed_ie_sequence(input, ctx, 0)
    }

    /// Decode one typed IE from an already-decoded raw IE.
    ///
    /// `base_offset` is the absolute byte position of the start of the raw IE
    /// header within the containing input. It is used so that value-level decode
    /// errors report offsets relative to the message rather than to the IE value.
    pub fn decode_from_raw(
        raw: RawIe<'a>,
        ctx: DecodeContext,
        depth: usize,
        base_offset: usize,
    ) -> Result<Self, DecodeError> {
        let mut duplicate_evidence = DuplicateIeCollector::default();
        Self::decode_from_raw_with_evidence(
            raw,
            ctx,
            depth,
            base_offset,
            IeDecodePolicy::legacy(false),
            &mut duplicate_evidence,
        )
    }

    fn decode_from_raw_with_evidence(
        raw: RawIe<'a>,
        ctx: DecodeContext,
        depth: usize,
        base_offset: usize,
        policy: IeDecodePolicy<'_>,
        duplicate_evidence: &mut DuplicateIeCollector,
    ) -> Result<Self, DecodeError> {
        let value_offset = checked_add_offset(base_offset, IE_HEADER_LEN)?;
        let value = match raw.ie_type {
            IE_TYPE_IMSI => TypedIeValue::Imsi(TbcdDigits::decode_value(raw.value, value_offset)?),
            IE_TYPE_CAUSE => TypedIeValue::Cause(Cause::decode_value(raw.value, value_offset)?),
            IE_TYPE_RECOVERY => {
                TypedIeValue::Recovery(Recovery::decode_value(raw.value, value_offset)?)
            }
            IE_TYPE_APN => TypedIeValue::AccessPointName(AccessPointName::decode_value(
                raw.value,
                value_offset,
            )?),
            IE_TYPE_AMBR => TypedIeValue::AggregateMaximumBitRate(
                AggregateMaximumBitRate::decode_value(raw.value, value_offset)?,
            ),
            IE_TYPE_EBI => {
                TypedIeValue::EpsBearerId(EpsBearerId::decode_value(raw.value, value_offset, ctx)?)
            }
            IE_TYPE_MEI => TypedIeValue::Mei(TbcdDigits::decode_value(raw.value, value_offset)?),
            IE_TYPE_MSISDN => {
                TypedIeValue::Msisdn(TbcdDigits::decode_value(raw.value, value_offset)?)
            }
            IE_TYPE_INDICATION => {
                TypedIeValue::Indication(Indication::decode_value(raw.value, value_offset)?)
            }
            IE_TYPE_PCO => TypedIeValue::ProtocolConfigurationOptions(
                ProtocolConfigurationOptions::decode_value(raw.value, value_offset)?,
            ),
            IE_TYPE_PAA => TypedIeValue::PdnAddressAllocation(PdnAddressAllocation::decode_value(
                raw.value,
                value_offset,
                ctx,
            )?),
            IE_TYPE_BEARER_QOS => {
                TypedIeValue::BearerQos(BearerQos::decode_value(raw.value, value_offset)?)
            }
            IE_TYPE_RAT_TYPE => {
                TypedIeValue::RatType(RatType::decode_value(raw.value, value_offset)?)
            }
            IE_TYPE_SERVING_NETWORK => {
                TypedIeValue::ServingNetwork(ServingNetwork::decode_value(raw.value, value_offset)?)
            }
            IE_TYPE_BEARER_TFT => TypedIeValue::BearerTft(
                TrafficFlowTemplate::decode_value_with_context(raw.value, ctx)
                    .map_err(|error| bearer_tft_decode_error(error, value_offset))?,
            ),
            IE_TYPE_F_TEID => TypedIeValue::FullyQualifiedTeid(FullyQualifiedTeid::decode_value(
                raw.value,
                value_offset,
            )?),
            IE_TYPE_BEARER_CONTEXT => TypedIeValue::BearerContext(BearerContext::decode_value(
                raw.value,
                ctx,
                depth,
                value_offset,
                raw.instance,
                policy,
                duplicate_evidence,
            )?),
            IE_TYPE_CHARGING_ID => {
                TypedIeValue::ChargingId(ChargingId::decode_value(raw.value, value_offset)?)
            }
            IE_TYPE_PDN_TYPE => {
                TypedIeValue::PdnType(PdnType::decode_value(raw.value, value_offset, ctx)?)
            }
            IE_TYPE_APN_RESTRICTION => {
                TypedIeValue::ApnRestriction(ApnRestriction::decode_value(raw.value, value_offset)?)
            }
            IE_TYPE_SELECTION_MODE => TypedIeValue::SelectionMode(SelectionMode::decode_value(
                raw.value,
                value_offset,
                ctx,
            )?),
            IE_TYPE_APCO => TypedIeValue::AdditionalProtocolConfigurationOptions(
                AdditionalProtocolConfigurationOptions::decode_value(raw.value, value_offset)?,
            ),
            _ if matches!(ctx.unknown_ie_policy, UnknownIePolicy::Reject) => {
                return Err(
                    DecodeError::new(DecodeErrorCode::UnknownCriticalIe, base_offset)
                        .with_spec_ref(spec_ref()),
                );
            }
            _ => TypedIeValue::Raw(raw.clone()),
        };
        Ok(Self {
            instance: raw.instance,
            value,
        })
    }

    /// Return the IE type code for this typed value.
    pub fn ie_type(&self) -> u8 {
        match &self.value {
            TypedIeValue::Imsi(_) => IE_TYPE_IMSI,
            TypedIeValue::Cause(_) => IE_TYPE_CAUSE,
            TypedIeValue::Recovery(_) => IE_TYPE_RECOVERY,
            TypedIeValue::AccessPointName(_) => IE_TYPE_APN,
            TypedIeValue::AggregateMaximumBitRate(_) => IE_TYPE_AMBR,
            TypedIeValue::EpsBearerId(_) => IE_TYPE_EBI,
            TypedIeValue::Mei(_) => IE_TYPE_MEI,
            TypedIeValue::Msisdn(_) => IE_TYPE_MSISDN,
            TypedIeValue::Indication(_) => IE_TYPE_INDICATION,
            TypedIeValue::ProtocolConfigurationOptions(_) => IE_TYPE_PCO,
            TypedIeValue::PdnAddressAllocation(_) => IE_TYPE_PAA,
            TypedIeValue::BearerQos(_) => IE_TYPE_BEARER_QOS,
            TypedIeValue::RatType(_) => IE_TYPE_RAT_TYPE,
            TypedIeValue::ServingNetwork(_) => IE_TYPE_SERVING_NETWORK,
            TypedIeValue::BearerTft(_) => IE_TYPE_BEARER_TFT,
            TypedIeValue::FullyQualifiedTeid(_) => IE_TYPE_F_TEID,
            TypedIeValue::BearerContext(_) => IE_TYPE_BEARER_CONTEXT,
            TypedIeValue::ChargingId(_) => IE_TYPE_CHARGING_ID,
            TypedIeValue::PdnType(_) => IE_TYPE_PDN_TYPE,
            TypedIeValue::ApnRestriction(_) => IE_TYPE_APN_RESTRICTION,
            TypedIeValue::SelectionMode(_) => IE_TYPE_SELECTION_MODE,
            TypedIeValue::AdditionalProtocolConfigurationOptions(_) => IE_TYPE_APCO,
            TypedIeValue::Raw(raw) => raw.ie_type,
        }
    }

    /// Encode this IE into `dst`.
    pub fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        if let TypedIeValue::Raw(raw) = &self.value {
            return raw.encode(dst);
        }

        let mut value = BytesMut::new();
        self.encode_value(&mut value, ctx)?;
        let value_len = u16::try_from(value.len())
            .map_err(|_| EncodeError::length_overflow().with_spec_ref(spec_ref()))?;
        dst.put_u8(self.ie_type());
        dst.put_u16(value_len);
        dst.put_u8(self.instance & 0x0f);
        dst.put_slice(&value);
        Ok(())
    }

    /// Return this IE's encoded wire length.
    pub fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        if let TypedIeValue::Raw(raw) = &self.value {
            return raw.wire_len();
        }
        let mut value = BytesMut::new();
        self.encode_value(&mut value, ctx)?;
        IE_HEADER_LEN
            .checked_add(value.len())
            .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec_ref()))
    }

    fn encode_value(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        match &self.value {
            TypedIeValue::Imsi(value) | TypedIeValue::Mei(value) | TypedIeValue::Msisdn(value) => {
                value.encode_value(dst)
            }
            TypedIeValue::Cause(value) => value.encode_value(dst),
            TypedIeValue::Recovery(value) => value.encode_value(dst),
            TypedIeValue::AccessPointName(value) => value.encode_value(dst),
            TypedIeValue::AggregateMaximumBitRate(value) => value.encode_value(dst),
            TypedIeValue::EpsBearerId(value) => value.encode_value(dst),
            TypedIeValue::Indication(value) => value.encode_value(dst),
            TypedIeValue::ProtocolConfigurationOptions(value) => value.encode_value(dst),
            TypedIeValue::PdnAddressAllocation(value) => value.encode_value(dst),
            TypedIeValue::BearerQos(value) => value.encode_value(dst),
            TypedIeValue::RatType(value) => value.encode_value(dst),
            TypedIeValue::ServingNetwork(value) => value.encode_value(dst),
            TypedIeValue::BearerTft(value) => value
                .encode_value(dst)
                .map_err(|_| encode_structural_error("Bearer TFT IE failed TS 24.008 validation")),
            TypedIeValue::FullyQualifiedTeid(value) => value.encode_value(dst),
            TypedIeValue::BearerContext(value) => value.encode_value(dst, ctx),
            TypedIeValue::ChargingId(value) => value.encode_value(dst),
            TypedIeValue::PdnType(value) => value.encode_value(dst),
            TypedIeValue::ApnRestriction(value) => value.encode_value(dst),
            TypedIeValue::SelectionMode(value) => value.encode_value(dst),
            TypedIeValue::AdditionalProtocolConfigurationOptions(value) => value.encode_value(dst),
            TypedIeValue::Raw(_) => Err(encode_structural_error(
                "raw IE value must use the raw-preserving encoder",
            )),
        }
    }
}

impl fmt::Debug for TypedIeValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Imsi(value) => f.debug_tuple("Imsi").field(value).finish(),
            Self::Cause(value) => f.debug_tuple("Cause").field(value).finish(),
            Self::Recovery(value) => f.debug_tuple("Recovery").field(value).finish(),
            Self::AccessPointName(value) => f.debug_tuple("AccessPointName").field(value).finish(),
            Self::AggregateMaximumBitRate(value) => f
                .debug_tuple("AggregateMaximumBitRate")
                .field(value)
                .finish(),
            Self::EpsBearerId(value) => f.debug_tuple("EpsBearerId").field(value).finish(),
            Self::Mei(value) => f.debug_tuple("Mei").field(value).finish(),
            Self::Msisdn(value) => f.debug_tuple("Msisdn").field(value).finish(),
            Self::Indication(value) => f.debug_tuple("Indication").field(value).finish(),
            Self::ProtocolConfigurationOptions(value) => f
                .debug_tuple("ProtocolConfigurationOptions")
                .field(value)
                .finish(),
            Self::PdnAddressAllocation(value) => {
                f.debug_tuple("PdnAddressAllocation").field(value).finish()
            }
            Self::BearerQos(value) => f.debug_tuple("BearerQos").field(value).finish(),
            Self::RatType(value) => f.debug_tuple("RatType").field(value).finish(),
            Self::ServingNetwork(value) => f.debug_tuple("ServingNetwork").field(value).finish(),
            Self::BearerTft(value) => f.debug_tuple("BearerTft").field(value).finish(),
            Self::FullyQualifiedTeid(value) => {
                f.debug_tuple("FullyQualifiedTeid").field(value).finish()
            }
            Self::BearerContext(value) => f.debug_tuple("BearerContext").field(value).finish(),
            Self::ChargingId(value) => f.debug_tuple("ChargingId").field(value).finish(),
            Self::PdnType(value) => f.debug_tuple("PdnType").field(value).finish(),
            Self::ApnRestriction(value) => f.debug_tuple("ApnRestriction").field(value).finish(),
            Self::SelectionMode(value) => f.debug_tuple("SelectionMode").field(value).finish(),
            Self::AdditionalProtocolConfigurationOptions(value) => f
                .debug_tuple("AdditionalProtocolConfigurationOptions")
                .field(value)
                .finish(),
            Self::Raw(raw) => f
                .debug_struct("Raw")
                .field("ie_type", &raw.ie_type)
                .field("instance", &raw.instance)
                .field("value_len", &raw.value.len())
                .finish(),
        }
    }
}

impl fmt::Debug for TypedIe<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedIe")
            .field("ie_type", &self.ie_type())
            .field("instance", &self.instance)
            .field("value", &self.value)
            .finish()
    }
}

/// Encode a sequence of typed GTPv2-C IEs into a raw IE region.
///
/// # Errors
///
/// Returns [`EncodeError`] when any member IE cannot be represented in its
/// canonical wire format.
///
/// @spec 3GPP TS29274 R18 8.2
/// @req REQ-3GPP-TS29274-R18-S2B-IE-005
pub fn encode_typed_ie_sequence(
    ies: &[TypedIe<'_>],
    dst: &mut BytesMut,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    for ie in ies {
        ie.encode(dst, ctx)?;
    }
    Ok(())
}

/// Decode a sequence of GTPv2-C IEs into typed values with raw fallback.
///
/// @spec 3GPP TS29274 R18 8.2
/// @req REQ-3GPP-TS29274-R18-S2B-IE-004
pub fn decode_typed_ie_sequence<'a>(
    input: &'a [u8],
    ctx: DecodeContext,
    depth: usize,
) -> Result<Vec<TypedIe<'a>>, DecodeError> {
    let mut duplicate_evidence = DuplicateIeCollector::default();
    decode_typed_ie_sequence_at(
        input,
        ctx,
        IeSequencePosition::root(depth),
        IeDecodePolicy::legacy(false),
        &mut duplicate_evidence,
    )
}

pub(crate) fn decode_typed_ie_sequence_with_evidence<'a>(
    input: &'a [u8],
    ctx: DecodeContext,
    depth: usize,
) -> Result<DecodedIeSequence<'a>, DecodeError> {
    let mut collector = DuplicateIeCollector::default();
    let ies = decode_typed_ie_sequence_at(
        input,
        ctx,
        IeSequencePosition::root(depth),
        IeDecodePolicy::legacy(false),
        &mut collector,
    )?;
    let (duplicate_evidence, omitted_duplicate_count) = collector.into_parts();
    Ok(DecodedIeSequence {
        ies,
        duplicate_evidence,
        omitted_duplicate_count,
    })
}

/// Decode the top-level IE sequence of a PGW-triggered bearer request.
///
/// TS 29.274 tables 7.2.3-1, 7.2.15-1, and 7.2.9.2-1 declare three
/// additional repeated type/instance pairs for requests 95, 97, and 99.
/// Keeping this profile request-specific prevents the same duplicates from
/// being silently accepted in responses 96, 98, and 100.
pub(crate) fn decode_pgw_triggered_request_ie_sequence_with_evidence<'a>(
    input: &'a [u8],
    ctx: DecodeContext,
) -> Result<DecodedIeSequence<'a>, DecodeError> {
    let mut collector = DuplicateIeCollector::default();
    let ies = decode_typed_ie_sequence_at(
        input,
        ctx,
        IeSequencePosition::root(0),
        IeDecodePolicy::legacy(true),
        &mut collector,
    )?;
    let (duplicate_evidence, omitted_duplicate_count) = collector.into_parts();
    Ok(DecodedIeSequence {
        ies,
        duplicate_evidence,
        omitted_duplicate_count,
    })
}

/// Decode an S2b receive sequence while discarding table-known unexpected keys
/// before their values are interpreted.
pub(crate) fn decode_s2b_receive_ie_sequence_with_evidence<'a>(
    input: &'a [u8],
    ctx: DecodeContext,
    filter: IeDecodeFilter<'_>,
    scoped_repeatable_limit: IeRepeatableLimit<'_>,
) -> Result<DecodedIeSequence<'a>, DecodeError> {
    let mut collector = DuplicateIeCollector::default();
    let ies = decode_typed_ie_sequence_at(
        input,
        ctx,
        IeSequencePosition::root(0),
        IeDecodePolicy::scoped(filter, scoped_repeatable_limit),
        &mut collector,
    )?;
    let (duplicate_evidence, omitted_duplicate_count) = collector.into_parts();
    Ok(DecodedIeSequence {
        ies,
        duplicate_evidence,
        omitted_duplicate_count,
    })
}

/// Decode a sequence of GTPv2-C IEs into typed values with raw fallback,
/// anchored at `base_offset`.
///
/// `base_offset` is the absolute byte position of the first octet of `input`
/// within the containing message. The iterator returned by
/// [`RawIeIterator::new_at_offset`] is the single source of truth for offsets;
/// each decoded IE uses the iterator's current offset before it is advanced,
/// and the iterator's absolute offsets are propagated to value decoders and
/// duplicate-IE diagnostics.
fn decode_typed_ie_sequence_at<'a>(
    input: &'a [u8],
    ctx: DecodeContext,
    position: IeSequencePosition,
    policy: IeDecodePolicy<'_>,
    duplicate_evidence: &mut DuplicateIeCollector,
) -> Result<Vec<TypedIe<'a>>, DecodeError> {
    if position.depth > ctx.max_depth {
        return Err(
            DecodeError::new(DecodeErrorCode::DepthExceeded, position.base_offset)
                .with_spec_ref(spec_ref()),
        );
    }
    let mut ies: Vec<TypedIe<'a>> = Vec::new();
    let mut seen = Vec::new();
    let mut iter = RawIeIterator::new_at_offset(input, ctx, position.base_offset);
    loop {
        let offset = iter.offset();
        match iter.next() {
            Some(Ok(raw)) => {
                if policy.filter.is_some_and(|filter| {
                    !filter(
                        raw.ie_type,
                        raw.instance,
                        position.depth,
                        position.parent_ie,
                    )
                }) {
                    continue;
                }
                let key = (raw.ie_type, raw.instance);
                let first_offset = seen.iter().find_map(|(seen_key, first_offset)| {
                    (*seen_key == key).then_some(*first_offset)
                });
                let repeatable_limit = match policy.scoped_repeatable_limit {
                    Some(resolve) => resolve(
                        raw.ie_type,
                        raw.instance,
                        position.depth,
                        position.parent_ie,
                    ),
                    None => legacy_repeatable_limit(
                        position.depth,
                        raw.ie_type,
                        raw.instance,
                        policy.legacy_pgw_triggered_request,
                    ),
                };
                if let Some(first_offset) = first_offset {
                    if repeatable_limit.is_none() {
                        match ctx.duplicate_ie_policy {
                            DuplicateIePolicy::Reject => {
                                return Err(DecodeError::new(DecodeErrorCode::DuplicateIe, offset)
                                    .with_spec_ref(spec_ref()));
                            }
                            DuplicateIePolicy::First => {
                                duplicate_evidence.record(
                                    raw.ie_type,
                                    raw.instance,
                                    position.depth,
                                    position.base_offset,
                                    first_offset,
                                );
                                continue;
                            }
                            DuplicateIePolicy::Last => {}
                        }
                    } else if matches!(ctx.duplicate_ie_policy, DuplicateIePolicy::First)
                        && repeatable_limit.is_some_and(|limit| {
                            ies.iter()
                                .filter(|ie| {
                                    ie.ie_type() == raw.ie_type && ie.instance == raw.instance
                                })
                                .count()
                                >= limit
                        })
                    {
                        duplicate_evidence.record(
                            raw.ie_type,
                            raw.instance,
                            position.depth,
                            position.base_offset,
                            first_offset,
                        );
                        continue;
                    }
                } else {
                    seen.push((key, offset));
                }

                let typed = TypedIe::decode_from_raw_with_evidence(
                    raw,
                    ctx,
                    position.depth,
                    offset,
                    policy,
                    duplicate_evidence,
                )?;
                apply_duplicate_policy(
                    &mut ies,
                    typed,
                    ctx.duplicate_ie_policy,
                    repeatable_limit.is_some(),
                );
            }
            Some(Err(error)) => return Err(error),
            None => break,
        }
    }
    Ok(ies)
}

fn apply_duplicate_policy<'a>(
    ies: &mut Vec<TypedIe<'a>>,
    typed: TypedIe<'a>,
    policy: DuplicateIePolicy,
    repeatable: bool,
) {
    // TS 29.274 procedure tables explicitly use these type/instance pairs as
    // lists. Treating them as singleton duplicates would either discard
    // dedicated bearers under First/Last or reject conforming multi-bearer
    // messages under Reject. Nested typed EBI IEs remain singleton members.
    // Unknown IEs still follow the caller's duplicate policy: without a
    // dictionary entry, treating every unknown type as repeatable would
    // silently weaken `DuplicateIePolicy::Reject` for the whole crate.
    if repeatable {
        ies.push(typed);
        return;
    }

    let duplicate = ies.iter().position(|existing| {
        existing.ie_type() == typed.ie_type() && existing.instance == typed.instance
    });

    match duplicate {
        Some(_) if matches!(policy, DuplicateIePolicy::Reject | DuplicateIePolicy::First) => {}
        Some(index) => {
            ies.remove(index);
            ies.push(typed);
        }
        None => {
            ies.push(typed);
        }
    }
}

fn legacy_repeatable_limit(
    depth: usize,
    ie_type: u8,
    instance: u8,
    pgw_triggered_request: bool,
) -> Option<usize> {
    if depth != 0 {
        return None;
    }
    match (ie_type, instance) {
        (IE_TYPE_BEARER_CONTEXT, 0) => Some(usize::MAX),
        (IE_TYPE_EBI, 1) => Some(15),
        (IE_TYPE_LOAD_CONTROL_INFORMATION, 1) if pgw_triggered_request => Some(10),
        (IE_TYPE_OVERLOAD_CONTROL_INFORMATION, 0) if pgw_triggered_request => Some(11),
        // Create, Update, and Delete Bearer Request each explicitly allow
        // several outer PGW Change Info IEs. Session responses do not use this
        // legacy request-only decoder and remain singleton in the scoped path.
        (IE_TYPE_PGW_CHANGE_INFO, 0) if pgw_triggered_request => Some(usize::MAX),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arp() -> AllocationRetentionPriority {
        let Ok(value) = AllocationRetentionPriority::new(3, true, true) else {
            panic!("test ARP must be valid");
        };
        value
    }

    #[test]
    fn bearer_qos_validates_typed_arp_and_standardized_resource_semantics() {
        assert_eq!(arp().to_octet(), 0x4d);
        assert_eq!(AllocationRetentionPriority::from_octet(0x4d), Ok(arp()));
        assert_eq!(
            AllocationRetentionPriority::from_octet(0x4f),
            Err(BearerQosValidationError::InvalidArpSpareBits)
        );
        assert_eq!(
            AllocationRetentionPriority::new(0, false, false),
            Err(BearerQosValidationError::InvalidPriorityLevel)
        );

        let Ok(voice) = BearerQos::new(arp(), 1, 128, 128, 64, 64) else {
            panic!("standardized GBR voice QoS must validate");
        };
        assert_eq!(voice.resource_type(), Ok(BearerQosResourceType::Gbr));
        assert_eq!(voice.validate(), Ok(()));

        let Ok(downlink_only_gbr) = BearerQos::new(arp(), 1, 0, 128, 0, 64) else {
            panic!("a zero-rate uplink direction must remain valid");
        };
        assert_eq!(downlink_only_gbr.validate(), Ok(()));
        assert_eq!(
            BearerQos::new(arp(), 1, 0, 0, 0, 0),
            Err(BearerQosValidationError::GbrMaximumBitratesMustNotBothBeZero)
        );

        let Ok(non_gbr) = BearerQos::new(arp(), 9, 0, 0, 0, 0) else {
            panic!("standardized non-GBR QoS must use zero rates");
        };
        assert_eq!(non_gbr.resource_type(), Ok(BearerQosResourceType::NonGbr));
        assert_eq!(
            BearerQos::new(arp(), 9, 1, 0, 0, 0),
            Err(BearerQosValidationError::NonGbrRatesMustBeZero)
        );
        assert_eq!(
            BearerQos::new(arp(), 1, 64, 64, 65, 64),
            Err(BearerQosValidationError::GuaranteedBitrateExceedsMaximum)
        );
        assert_eq!(
            BearerQos::new(arp(), 11, 0, 0, 0, 0),
            Err(BearerQosValidationError::UnsupportedQci)
        );
    }

    #[test]
    fn operator_specific_bearer_qos_requires_explicit_resource_type() {
        let Ok(operator_qos) = BearerQos::new(arp(), 200, 128, 128, 64, 64) else {
            panic!("operator-specific QCI remains wire representable");
        };
        assert_eq!(
            operator_qos.validate(),
            Err(BearerQosValidationError::OperatorResourceTypeRequired)
        );
        assert_eq!(
            operator_qos.validate_with_resource_type(BearerQosResourceType::Gbr),
            Ok(())
        );
        assert_eq!(
            operator_qos.validate_with_resource_type(BearerQosResourceType::NonGbr),
            Err(BearerQosValidationError::NonGbrRatesMustBeZero)
        );
    }

    #[test]
    fn bearer_qos_decode_rejects_arp_spare_bits() {
        let mut value = [0u8; 22];
        value[0] = 0x4f;
        value[1] = 9;
        let Err(error) = BearerQos::decode_value(&value, 7) else {
            panic!("ARP spare bit 2 must fail at the untrusted boundary");
        };
        assert!(matches!(
            error.code(),
            DecodeErrorCode::Structural {
                reason: "Bearer QoS ARP spare bits must be zero"
            }
        ));
        assert_eq!(error.offset(), 7);
    }

    #[test]
    fn paa_constructors_distinguish_dynamic_and_static_allocations() {
        let dynamic_cases = [
            (PdnAddressAllocation::dynamic_ipv4(), vec![1, 0, 0, 0, 0]),
            (
                PdnAddressAllocation::dynamic_ipv6(),
                [vec![2, 0], vec![0; 16]].concat(),
            ),
            (
                PdnAddressAllocation::dynamic_ipv4v6(),
                [vec![3, 0], vec![0; 16], vec![0; 4]].concat(),
            ),
            (PdnAddressAllocation::non_ip(), vec![4]),
            (PdnAddressAllocation::ethernet(), vec![5]),
        ];
        for (paa, expected) in dynamic_cases {
            assert_eq!(paa.validate(), Ok(()));
            let mut encoded = BytesMut::new();
            assert_eq!(paa.encode_value(&mut encoded), Ok(()));
            assert_eq!(encoded.as_ref(), expected.as_slice());
        }

        let static_ipv4 = PdnAddressAllocation::static_ipv4([198, 51, 100, 7]);
        assert_eq!(
            static_ipv4.as_ref().map(|paa| paa.ipv4),
            Ok(Some([198, 51, 100, 7]))
        );
        let mut encoded_static_ipv4 = BytesMut::new();
        let static_ipv4_encode = match &static_ipv4 {
            Ok(paa) => paa.encode_value(&mut encoded_static_ipv4),
            Err(error) => panic!("static IPv4 construction failed: {error}"),
        };
        assert_eq!(static_ipv4_encode, Ok(()));
        assert_eq!(encoded_static_ipv4.as_ref(), &[1, 198, 51, 100, 7]);
        let ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
        let static_ipv6 = PdnAddressAllocation::static_ipv6(64, ipv6);
        assert_eq!(
            static_ipv6.as_ref().map(|paa| paa.ipv6_prefix),
            Ok(Some(ipv6))
        );
        let mut encoded_static_ipv6 = BytesMut::new();
        let static_ipv6_encode = match &static_ipv6 {
            Ok(paa) => paa.encode_value(&mut encoded_static_ipv6),
            Err(error) => panic!("static IPv6 construction failed: {error}"),
        };
        assert_eq!(static_ipv6_encode, Ok(()));
        assert_eq!(
            encoded_static_ipv6.as_ref(),
            [vec![2, 64], ipv6.to_vec()].concat()
        );
        let static_dual = PdnAddressAllocation::static_ipv4v6(None, Some((64, ipv6)));
        assert_eq!(static_dual.as_ref().map(|paa| paa.ipv4), Ok(Some([0; 4])));
        assert_eq!(
            static_dual.as_ref().map(|paa| paa.ipv6_prefix),
            Ok(Some(ipv6))
        );
        let mut encoded_static_dual = BytesMut::new();
        let static_dual_encode = match &static_dual {
            Ok(paa) => paa.encode_value(&mut encoded_static_dual),
            Err(error) => panic!("static IPv4v6 construction failed: {error}"),
        };
        assert_eq!(static_dual_encode, Ok(()));
        assert_eq!(
            encoded_static_dual.as_ref(),
            [vec![3, 64], ipv6.to_vec(), vec![0; 4]].concat()
        );
    }

    #[test]
    fn paa_constructors_and_encode_reject_ambiguous_or_mismatched_shapes() {
        assert_eq!(
            PdnAddressAllocation::static_ipv4([0; 4]),
            Err(PdnAddressAllocationError::StaticIpv4AddressUnspecified)
        );
        assert_eq!(
            PdnAddressAllocation::static_ipv6(0, [1; 16]),
            Err(PdnAddressAllocationError::InvalidIpv6PrefixLength)
        );
        assert_eq!(
            PdnAddressAllocation::static_ipv6(64, [0; 16]),
            Err(PdnAddressAllocationError::StaticIpv6PrefixUnspecified)
        );
        assert_eq!(
            PdnAddressAllocation::static_ipv4v6(None, None),
            Err(PdnAddressAllocationError::StaticIpv4v6AddressMissing)
        );

        let mismatched = PdnAddressAllocation {
            pdn_type: PdnTypeValue::NonIp,
            ipv6_prefix_length: None,
            ipv6_prefix: None,
            ipv4: Some([198, 51, 100, 7]),
        };
        assert_eq!(
            mismatched.validate(),
            Err(PdnAddressAllocationError::UnexpectedIpv4Address)
        );
        let mut encoded = BytesMut::new();
        let error = match mismatched.encode_value(&mut encoded) {
            Ok(()) => panic!("family-mismatched PAA unexpectedly encoded"),
            Err(error) => error,
        };
        assert!(encoded.is_empty());
        assert!(matches!(
            error.code(),
            EncodeErrorCode::Structural {
                reason: "PAA PDN type prohibits an IPv4 address"
            }
        ));
        assert_eq!(
            PdnAddressAllocationError::UnexpectedIpv4Address.as_str(),
            "gtpv2c_paa_ipv4_unexpected"
        );
    }

    #[test]
    fn strict_paa_decode_rejects_reserved_type_and_invalid_prefix_length() {
        let strict = DecodeContext {
            validation_level: opc_protocol::ValidationLevel::Strict,
            ..DecodeContext::default()
        };
        let reserved = PdnAddressAllocation::decode_value(&[6], 9, strict);
        assert!(matches!(
            reserved.as_ref().map_err(DecodeError::code),
            Err(DecodeErrorCode::Structural {
                reason: "PAA PDN type is reserved"
            })
        ));

        let mut invalid_ipv6 = vec![2, 63];
        invalid_ipv6.extend_from_slice(&[0; 16]);
        let invalid_prefix = PdnAddressAllocation::decode_value(&invalid_ipv6, 11, strict);
        assert!(matches!(
            invalid_prefix.as_ref().map_err(DecodeError::code),
            Err(DecodeErrorCode::Structural {
                reason: "PAA IPv6 prefix length must be zero for dynamic allocation or 64 for assigned allocation"
            })
        ));
    }

    #[test]
    fn internal_raw_value_encode_fails_structurally_without_panicking() {
        let ie = TypedIe {
            instance: 0,
            value: TypedIeValue::Raw(RawIe {
                ie_type: 254,
                instance: 0,
                spare: 0,
                value: &[0xaa],
            }),
        };
        let mut encoded = BytesMut::new();
        let error = match ie.encode_value(&mut encoded, EncodeContext::default()) {
            Ok(()) => panic!("internal raw value encoding unexpectedly succeeded"),
            Err(error) => error,
        };

        assert!(encoded.is_empty());
        assert!(matches!(
            error.code(),
            EncodeErrorCode::Structural {
                reason: "raw IE value must use the raw-preserving encoder"
            }
        ));
        let spec = match error.spec_ref() {
            Some(spec) => spec,
            None => panic!("raw value encode error omitted its specification reference"),
        };
        assert_eq!(spec.doc(), "TS29274");
        assert_eq!(spec.section(), "8.2");
    }
}
