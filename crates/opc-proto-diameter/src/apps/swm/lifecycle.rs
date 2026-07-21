//! Typed SWm Abort-Session and Session-Termination lifecycle boundary.
//!
//! The codec owns command grammar, request/answer correlation, and safe wire
//! projection. Active-session lookup, teardown ordering, retries, and
//! compensation remain product policy.

use bytes::{Bytes, BytesMut};
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, EncodeContext, EncodeError, EncodeErrorCode,
    SpecRef, UnknownIePolicy,
};
use std::{collections::HashSet, error::Error, fmt, num::NonZeroU64};

use super::{builder_helpers, Redacted, APPLICATION_ID};
use crate::avp::dictionary::Sensitive;
use crate::base;
use crate::dictionary::{
    AvpCardinality, AvpDataType, AvpDefinition, AvpFlagRules, AvpKey, CommandAvpRule,
    CommandDefinition, CommandKind, FlagRequirement,
};
use crate::parser_error::DiameterParserError;
use crate::{
    AvpCode, AvpFlags, AvpHeader, CommandCode, CommandFlags, Message, OwnedMessage, RawAvp,
    VendorId, DIAMETER_HEADER_LEN,
};

/// Abort-Session command code (RFC 6733 section 8.5).
pub const COMMAND_ABORT_SESSION: CommandCode = CommandCode::new(274);
/// Session-Termination command code (RFC 6733 section 8.4).
pub const COMMAND_SESSION_TERMINATION: CommandCode = CommandCode::new(275);

/// Diameter Routing Message Priority AVP code (RFC 7944 section 9.1).
pub const AVP_DRMP: AvpCode = AvpCode::new(301);
/// OC-Supported-Features AVP code (RFC 7683 section 7.1).
pub const AVP_OC_SUPPORTED_FEATURES: AvpCode = AvpCode::new(621);
/// OC-Feature-Vector AVP code (RFC 7683 section 7.2).
pub const AVP_OC_FEATURE_VECTOR: AvpCode = AvpCode::new(622);
/// OC-OLR AVP code (RFC 7683 section 7.3).
pub const AVP_OC_OLR: AvpCode = AvpCode::new(623);
/// OC-Sequence-Number AVP code (RFC 7683 section 7.4).
pub const AVP_OC_SEQUENCE_NUMBER: AvpCode = AvpCode::new(624);
/// OC-Validity-Duration AVP code (RFC 7683 section 7.5).
pub const AVP_OC_VALIDITY_DURATION: AvpCode = AvpCode::new(625);
/// OC-Report-Type AVP code (RFC 7683 section 7.6).
pub const AVP_OC_REPORT_TYPE: AvpCode = AvpCode::new(626);
/// OC-Reduction-Percentage AVP code (RFC 7683 section 7.7).
pub const AVP_OC_REDUCTION_PERCENTAGE: AvpCode = AvpCode::new(627);
/// SourceID AVP code (RFC 8581 section 7.3).
pub const AVP_SOURCE_ID: AvpCode = AvpCode::new(649);
/// Load AVP code (RFC 8583 section 7.1).
pub const AVP_LOAD: AvpCode = AvpCode::new(650);
/// Load-Type AVP code (RFC 8583 section 7.2).
pub const AVP_LOAD_TYPE: AvpCode = AvpCode::new(651);
/// Load-Value AVP code (RFC 8583 section 7.3).
pub const AVP_LOAD_VALUE: AvpCode = AvpCode::new(652);

const OC_DEFAULT_ALGORITHM: u64 = 1;
const LOAD_VALUE_MAX: u64 = 65_535;
const RESULT_CODE_DIAMETER_REDIRECT_INDICATION: u32 = 3006;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OcSupportedFeatures {
    feature_vector: Option<u64>,
}

impl OcSupportedFeatures {
    const fn effective_vector(self) -> u64 {
        match self.feature_vector {
            Some(value) => value,
            None => OC_DEFAULT_ALGORITHM,
        }
    }

    const fn selects_default_algorithm(self) -> bool {
        self.effective_vector() & OC_DEFAULT_ALGORITHM != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OcOlrFacts {
    validity_duration: Option<u32>,
    reduction_percentage: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ValueValidationPurpose {
    Decode,
    Encode,
}

const MAX_ROUTE_RECORDS: usize = 128;
const MAX_ADDITIONAL_AVPS: usize = 128;
const MAX_PROXY_INFOS: usize = 128;

static ABORT_SESSION_REQUEST_AVP_RULES: [CommandAvpRule; 27] = [
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_SESSION_ID),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_DRMP), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ORIGIN_HOST),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ORIGIN_REALM),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_DESTINATION_REALM),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_DESTINATION_HOST),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(base::AVP_USER_NAME), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(AvpKey::ietf(base::AVP_CLASS), AvpCardinality::ZeroOrMore),
    CommandAvpRule::new(AvpKey::ietf(super::AVP_STATE), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::ietf(super::AVP_REPLY_MESSAGE),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_AUTH_SESSION_STATE),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ORIGIN_STATE_ID),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_SUPPORTED_FEATURES),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_PROXY_INFO),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ROUTE_RECORD),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_RESULT_CODE),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_OC_OLR), AvpCardinality::Forbidden),
    CommandAvpRule::new(AvpKey::ietf(AVP_LOAD), AvpCardinality::Forbidden),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_TERMINATION_CAUSE),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ERROR_MESSAGE),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ERROR_REPORTING_HOST),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_FAILED_AVP),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_REDIRECT_HOST),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_REDIRECT_HOST_USAGE),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_REDIRECT_MAX_CACHE_TIME),
        AvpCardinality::Forbidden,
    ),
];

static ABORT_SESSION_ANSWER_AVP_RULES: [CommandAvpRule; 25] = [
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_SESSION_ID),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_DRMP), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_RESULT_CODE),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ORIGIN_HOST),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ORIGIN_REALM),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(base::AVP_USER_NAME), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(AvpKey::ietf(super::AVP_STATE), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ORIGIN_STATE_ID),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ERROR_MESSAGE),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ERROR_REPORTING_HOST),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_FAILED_AVP),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_REDIRECT_HOST),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_REDIRECT_HOST_USAGE),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_REDIRECT_MAX_CACHE_TIME),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_SUPPORTED_FEATURES),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_OC_OLR), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(AvpKey::ietf(AVP_LOAD), AvpCardinality::ZeroOrMore),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_PROXY_INFO),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_DESTINATION_REALM),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_DESTINATION_HOST),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_AUTH_SESSION_STATE),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ROUTE_RECORD),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_TERMINATION_CAUSE),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT),
        AvpCardinality::ZeroOrOne,
    ),
];

static SESSION_TERMINATION_REQUEST_AVP_RULES: [CommandAvpRule; 17] = [
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_SESSION_ID),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ORIGIN_HOST),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ORIGIN_REALM),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_DESTINATION_REALM),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_DESTINATION_HOST),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_TERMINATION_CAUSE),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(base::AVP_USER_NAME), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(AvpKey::ietf(base::AVP_CLASS), AvpCardinality::ZeroOrMore),
    CommandAvpRule::new(AvpKey::ietf(AVP_DRMP), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_SUPPORTED_FEATURES),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_PROXY_INFO),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ROUTE_RECORD),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_RESULT_CODE),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_OC_OLR), AvpCardinality::Forbidden),
    CommandAvpRule::new(AvpKey::ietf(AVP_LOAD), AvpCardinality::Forbidden),
];

static SESSION_TERMINATION_ANSWER_AVP_RULES: [CommandAvpRule; 16] = [
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_SESSION_ID),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_RESULT_CODE),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ORIGIN_HOST),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ORIGIN_REALM),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(base::AVP_CLASS), AvpCardinality::ZeroOrMore),
    CommandAvpRule::new(AvpKey::ietf(AVP_DRMP), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_SUPPORTED_FEATURES),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_OC_OLR), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(AvpKey::ietf(AVP_LOAD), AvpCardinality::ZeroOrMore),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_PROXY_INFO),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_DESTINATION_REALM),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_DESTINATION_HOST),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_TERMINATION_CAUSE),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ROUTE_RECORD),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT),
        AvpCardinality::ZeroOrOne,
    ),
];

/// SWm Abort-Session-Request command definition.
pub const COMMAND_ABORT_SESSION_REQUEST: CommandDefinition = CommandDefinition::new(
    COMMAND_ABORT_SESSION,
    "Abort-Session-Request",
    CommandKind::Request,
    APPLICATION_ID,
    true,
    SpecRef::new("3gpp", "TS29273", "7.2.2.3.1"),
)
.with_avp_rules(&ABORT_SESSION_REQUEST_AVP_RULES);

/// SWm Abort-Session-Answer command definition.
pub const COMMAND_ABORT_SESSION_ANSWER: CommandDefinition = CommandDefinition::new(
    COMMAND_ABORT_SESSION,
    "Abort-Session-Answer",
    CommandKind::Answer,
    APPLICATION_ID,
    true,
    SpecRef::new("3gpp", "TS29273", "7.2.2.3.2"),
)
.with_avp_rules(&ABORT_SESSION_ANSWER_AVP_RULES);

/// SWm Session-Termination-Request command definition.
pub const COMMAND_SESSION_TERMINATION_REQUEST: CommandDefinition = CommandDefinition::new(
    COMMAND_SESSION_TERMINATION,
    "Session-Termination-Request",
    CommandKind::Request,
    APPLICATION_ID,
    true,
    SpecRef::new("3gpp", "TS29273", "7.2.2.2.1"),
)
.with_avp_rules(&SESSION_TERMINATION_REQUEST_AVP_RULES);

/// SWm Session-Termination-Answer command definition.
pub const COMMAND_SESSION_TERMINATION_ANSWER: CommandDefinition = CommandDefinition::new(
    COMMAND_SESSION_TERMINATION,
    "Session-Termination-Answer",
    CommandKind::Answer,
    APPLICATION_ID,
    true,
    SpecRef::new("3gpp", "TS29273", "7.2.2.2.2"),
)
.with_avp_rules(&SESSION_TERMINATION_ANSWER_AVP_RULES);

/// IANA-assigned Diameter Termination-Cause value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmTerminationCause {
    /// DIAMETER_LOGOUT (1).
    Logout,
    /// DIAMETER_SERVICE_NOT_PROVIDED (2).
    ServiceNotProvided,
    /// DIAMETER_BAD_ANSWER (3).
    BadAnswer,
    /// DIAMETER_ADMINISTRATIVE (4).
    Administrative,
    /// DIAMETER_LINK_BROKEN (5).
    LinkBroken,
    /// DIAMETER_AUTH_EXPIRED (6).
    AuthExpired,
    /// DIAMETER_USER_MOVED (7).
    UserMoved,
    /// DIAMETER_SESSION_TIMEOUT (8).
    SessionTimeout,
    /// A nonzero value assigned by a newer registry revision or application.
    Other(u32),
}

impl SwmTerminationCause {
    /// Convert an IANA registry value into the typed representation.
    #[must_use]
    pub const fn from_value(value: u32) -> Option<Self> {
        match value {
            0 => None,
            1 => Some(Self::Logout),
            2 => Some(Self::ServiceNotProvided),
            3 => Some(Self::BadAnswer),
            4 => Some(Self::Administrative),
            5 => Some(Self::LinkBroken),
            6 => Some(Self::AuthExpired),
            7 => Some(Self::UserMoved),
            8 => Some(Self::SessionTimeout),
            other => Some(Self::Other(other)),
        }
    }

    /// Return the IANA registry wire value.
    #[must_use]
    pub const fn value(self) -> u32 {
        match self {
            Self::Logout => 1,
            Self::ServiceNotProvided => 2,
            Self::BadAnswer => 3,
            Self::Administrative => 4,
            Self::LinkBroken => 5,
            Self::AuthExpired => 6,
            Self::UserMoved => 7,
            Self::SessionTimeout => 8,
            Self::Other(value) => value,
        }
    }
}

/// Diameter routing priority in the RFC 7944 range 0 (highest) through 15.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmRoutingMessagePriority(u8);

impl SwmRoutingMessagePriority {
    /// Construct a priority when `value` is in the assigned 0..=15 range.
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        if value <= 15 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Parse a 32-bit Enumerated wire value.
    #[must_use]
    pub const fn from_value(value: u32) -> Option<Self> {
        if value <= 15 {
            Some(Self(value as u8))
        } else {
            None
        }
    }

    /// Return the 0..=15 wire value.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

/// Typed Result-Code projection for one SWm STA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmSessionTerminationResult {
    /// DIAMETER_SUCCESS (2001).
    Success,
    /// DIAMETER_UNKNOWN_SESSION_ID (5002).
    UnknownSession,
    /// DIAMETER_UNABLE_TO_COMPLY (5012).
    UnableToComply,
    /// Another received base Diameter result code.
    ///
    /// This receive-side projection preserves forward-compatible result codes.
    /// The typed STA builder deliberately rejects this variant because it does
    /// not model the result-specific AVPs required by arbitrary Diameter
    /// failures and redirects.
    Other(u32),
}

impl SwmSessionTerminationResult {
    /// Project a base Diameter Result-Code.
    #[must_use]
    pub const fn from_result_code(result_code: u32) -> Self {
        match result_code {
            base::RESULT_CODE_DIAMETER_SUCCESS => Self::Success,
            base::RESULT_CODE_DIAMETER_UNKNOWN_SESSION_ID => Self::UnknownSession,
            base::RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY => Self::UnableToComply,
            other => Self::Other(other),
        }
    }

    /// Return the base Diameter Result-Code.
    #[must_use]
    pub const fn result_code(self) -> u32 {
        match self {
            Self::Success => base::RESULT_CODE_DIAMETER_SUCCESS,
            Self::UnknownSession => base::RESULT_CODE_DIAMETER_UNKNOWN_SESSION_ID,
            Self::UnableToComply => base::RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY,
            Self::Other(result_code) => result_code,
        }
    }

    /// Return whether this is exact `DIAMETER_UNKNOWN_SESSION_ID`.
    #[must_use]
    pub const fn is_unknown_session(self) -> bool {
        matches!(self, Self::UnknownSession)
    }
}

/// One explicitly sensitive additional AVP retained by the typed lifecycle codec.
///
/// The raw value is intentionally inaccessible and absent from `Debug` and
/// `Display`. [`Self::new`] is the explicit raw-value intake boundary; the
/// STR/STA builders still reject command-core duplicates, wrong-role AVPs,
/// invalid flag combinations, and untrusted repeatability.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmAdditionalAvp {
    header: AvpHeader,
    value: Bytes,
}

impl SwmAdditionalAvp {
    /// Retain one raw AVP value for a typed lifecycle message.
    ///
    /// # Logging safety
    ///
    /// `value` can contain subscriber, topology, proxy, or policy data. Do not
    /// log it before moving it into this redaction-safe wrapper.
    pub fn new(header: AvpHeader, value: Vec<u8>, ctx: EncodeContext) -> Result<Self, EncodeError> {
        let retained = Self {
            header,
            value: Bytes::from(value),
        };
        let mut proof = BytesMut::new();
        retained.append_to(&mut proof, ctx)?;
        Ok(retained)
    }

    pub(super) fn from_raw(avp: &RawAvp<'_>) -> Self {
        let mut header = avp.header.clone();
        if header.key() == AvpKey::ietf(AVP_LOAD) {
            // TS 29.273 requires known received Load M-bit mismatches to be
            // ignored. Retain the value but canonicalize the receive-only
            // mismatch here so it can never be re-originated.
            header.flags = AvpFlags::from_bits(header.flags.bits() & !AvpFlags::MANDATORY);
        }
        Self {
            header,
            value: Bytes::copy_from_slice(avp.value),
        }
    }

    pub(super) fn append_to(
        &self,
        dst: &mut BytesMut,
        ctx: EncodeContext,
    ) -> Result<(), EncodeError> {
        builder_helpers::append_avp(dst, self.header.clone(), &self.value, ctx)
    }

    pub(super) const fn header(&self) -> &AvpHeader {
        &self.header
    }

    pub(super) fn value(&self) -> &[u8] {
        &self.value
    }

    /// Return the AVP code without exposing its value.
    #[must_use]
    pub const fn code(&self) -> AvpCode {
        self.header.code
    }

    /// Return the Vendor-Id without exposing the AVP value.
    #[must_use]
    pub const fn vendor_id(&self) -> Option<VendorId> {
        self.header.vendor_id
    }

    /// Return the retained value length without exposing its bytes.
    #[must_use]
    pub fn value_len(&self) -> usize {
        self.value.len()
    }

    fn has_same_replay_value(&self, other: &Self) -> bool {
        self.header.code == other.header.code
            && self.header.flags == other.header.flags
            && self.header.vendor_id == other.header.vendor_id
            && self.value == other.value
    }
}

pub(super) fn additional_avp_sequences_match(
    left: &[SwmAdditionalAvp],
    right: &[SwmAdditionalAvp],
) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.has_same_replay_value(right))
}

impl fmt::Debug for SwmAdditionalAvp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmAdditionalAvp")
            .field("code", &self.header.code)
            .field("vendor_id", &self.header.vendor_id)
            .field("flags", &self.header.flags)
            .field("value_len", &self.value.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for SwmAdditionalAvp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "swm_additional_avp(code={},vendor={},value=<redacted>)",
            self.header.code.get(),
            self.header.vendor_id.map_or(0, VendorId::get)
        )
    }
}

/// Opaque generation for one authenticated Diameter transport connection.
///
/// The transport allocates a process-unique nonzero value whenever an
/// authenticated peer connection is established. Reconnect and failover must
/// allocate a new token. The value is deliberately redacted from diagnostics
/// so it cannot become a high-cardinality connection label.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmDiameterConnectionToken(NonZeroU64);

impl SwmDiameterConnectionToken {
    /// Wrap one transport-owned, process-unique connection generation.
    #[must_use]
    pub const fn new(value: NonZeroU64) -> Self {
        Self(value)
    }
}

impl fmt::Debug for SwmDiameterConnectionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmDiameterConnectionToken(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
enum SwmAnswerOriginPolicy {
    Any,
    Exact {
        origin_host: Redacted<String>,
        origin_realm: Redacted<String>,
    },
    Realm(Redacted<String>),
}

/// Expected peer and optional logical origin for request-bound answers.
///
/// Every mode binds an answer to the same authenticated connection generation
/// on which its request was sent. [`Self::routed`] permits any logical Origin
/// because RFC 6733 agents can forward an ordinary answer from a different
/// final server. [`Self::direct`] and [`Self::routed_in_realm`] add explicit
/// logical-origin constraints when trusted routing state can prove them.
/// Destination AVPs are never treated as proof of the final Origin.
///
/// Generic RFC 6733 E-bit errors skip only the logical-origin policy because
/// an intermediary can originate them; connection binding and every other
/// correlation check remain mandatory.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmExpectedAnswerPeer {
    connection: SwmDiameterConnectionToken,
    origin_policy: SwmAnswerOriginPolicy,
}

impl SwmExpectedAnswerPeer {
    /// Bind a routed request to its authenticated connection only.
    #[must_use]
    pub const fn routed(connection: SwmDiameterConnectionToken) -> Self {
        Self {
            connection,
            origin_policy: SwmAnswerOriginPolicy::Any,
        }
    }

    /// Bind a direct request to one final Origin-Host and Origin-Realm.
    ///
    /// DiameterIdentity FQDN and realm comparison is ASCII case-insensitive.
    #[must_use]
    pub fn direct(
        connection: SwmDiameterConnectionToken,
        origin_host: impl Into<Redacted<String>>,
        origin_realm: impl Into<Redacted<String>>,
    ) -> Self {
        Self {
            connection,
            origin_policy: SwmAnswerOriginPolicy::Exact {
                origin_host: origin_host.into(),
                origin_realm: origin_realm.into(),
            },
        }
    }

    /// Bind a routed request to any final server in one Origin-Realm.
    ///
    /// DiameterIdentity realm comparison is ASCII case-insensitive.
    #[must_use]
    pub fn routed_in_realm(
        connection: SwmDiameterConnectionToken,
        origin_realm: impl Into<Redacted<String>>,
    ) -> Self {
        Self {
            connection,
            origin_policy: SwmAnswerOriginPolicy::Realm(origin_realm.into()),
        }
    }

    /// Return the opaque connection generation used for transport dispatch.
    #[must_use]
    pub const fn connection(&self) -> SwmDiameterConnectionToken {
        self.connection
    }

    pub(super) fn matches_origin(&self, origin_host: &str, origin_realm: &str) -> bool {
        match &self.origin_policy {
            SwmAnswerOriginPolicy::Any => true,
            SwmAnswerOriginPolicy::Exact {
                origin_host: expected_host,
                origin_realm: expected_realm,
            } => {
                expected_host.as_ref().eq_ignore_ascii_case(origin_host)
                    && expected_realm.as_ref().eq_ignore_ascii_case(origin_realm)
            }
            SwmAnswerOriginPolicy::Realm(expected_realm) => {
                expected_realm.as_ref().eq_ignore_ascii_case(origin_realm)
            }
        }
    }

    pub(super) fn validate_for_encode(&self) -> Result<(), EncodeError> {
        match &self.origin_policy {
            SwmAnswerOriginPolicy::Any => Ok(()),
            SwmAnswerOriginPolicy::Exact {
                origin_host,
                origin_realm,
            } => {
                validate_identity_for_encode(
                    origin_host.as_ref(),
                    "expected SWm answer Origin-Host must be a nonempty ASCII DiameterIdentity",
                    "6.3",
                )?;
                validate_identity_for_encode(
                    origin_realm.as_ref(),
                    "expected SWm answer Origin-Realm must be a nonempty ASCII DiameterIdentity",
                    "6.4",
                )
            }
            SwmAnswerOriginPolicy::Realm(origin_realm) => validate_identity_for_encode(
                origin_realm.as_ref(),
                "expected SWm answer Origin-Realm must be a nonempty ASCII DiameterIdentity",
                "6.4",
            ),
        }
    }
}

impl fmt::Debug for SwmExpectedAnswerPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("SwmExpectedAnswerPeer");
        debug.field("connection", &self.connection);
        match &self.origin_policy {
            SwmAnswerOriginPolicy::Any => debug.field("origin_policy", &"routed"),
            SwmAnswerOriginPolicy::Exact {
                origin_host,
                origin_realm,
            } => debug
                .field("origin_policy", &"direct")
                .field("origin_host", origin_host)
                .field("origin_realm", origin_realm),
            SwmAnswerOriginPolicy::Realm(origin_realm) => debug
                .field("origin_policy", &"routed_in_realm")
                .field("origin_realm", origin_realm),
        };
        debug.finish()
    }
}

/// Typed ePDG-originated SWm Session-Termination-Request facts.
///
/// The retained Session-Id and permanent User-Name own zeroizing storage.
/// Cloning these facts creates independent zeroize-on-drop owners.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmSessionTerminationRequest {
    /// Session-Id; zeroized on drop and redacted in diagnostics.
    pub session_id: Sensitive<String>,
    /// Origin-Host; diagnostic formatting is redacted.
    pub origin_host: Redacted<String>,
    /// Origin-Realm; diagnostic formatting is redacted.
    pub origin_realm: Redacted<String>,
    /// Destination-Realm; diagnostic formatting is redacted.
    pub destination_realm: Redacted<String>,
    /// Optional Destination-Host; diagnostic formatting is redacted.
    pub destination_host: Option<Redacted<String>>,
    /// Required Termination-Cause.
    pub termination_cause: SwmTerminationCause,
    /// Required permanent User-Name; zeroized on drop and redacted in diagnostics.
    pub user_name: Sensitive<String>,
    /// Optional RFC 7944 routing priority.
    pub drmp: Option<SwmRoutingMessagePriority>,
    /// Ordered Route-Record values; diagnostic formatting is redacted.
    pub route_records: Vec<Redacted<String>>,
    /// Ordered, well-formed additional command AVPs.
    pub additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmSessionTerminationRequest {
    fn has_same_replay_fields(&self, other: &Self) -> bool {
        self.session_id == other.session_id
            && self.origin_host == other.origin_host
            && self.origin_realm == other.origin_realm
            && self.destination_realm == other.destination_realm
            && self.destination_host == other.destination_host
            && self.termination_cause == other.termination_cause
            && self.user_name == other.user_name
            && self.drmp == other.drmp
            && self.route_records == other.route_records
            && additional_avp_sequences_match(&self.additional_avps, &other.additional_avps)
    }
}

impl fmt::Debug for SwmSessionTerminationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmSessionTerminationRequest")
            .field("session_id", &self.session_id)
            .field("origin_host", &self.origin_host)
            .field("origin_realm", &self.origin_realm)
            .field("destination_realm", &self.destination_realm)
            .field("destination_host", &self.destination_host)
            .field("termination_cause", &self.termination_cause)
            .field("user_name", &self.user_name)
            .field("drmp", &self.drmp)
            .field("route_record_count", &self.route_records.len())
            .field("additional_avp_count", &self.additional_avps.len())
            .finish()
    }
}

impl zeroize::ZeroizeOnDrop for SwmSessionTerminationRequest {}

/// Typed SWm Session-Termination-Answer facts.
///
/// A retained Session-Id owns zeroizing storage. Cloning these facts creates
/// an independent zeroize-on-drop owner when that value is present.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmSessionTerminationAnswer {
    /// Session-Id; absent only on a received RFC 6733 generic E-bit answer,
    /// including the permitted permanent-failure fallback. Diagnostic
    /// formatting is redacted when present.
    pub session_id: Option<Sensitive<String>>,
    /// Base Diameter result projection.
    pub result: SwmSessionTerminationResult,
    /// Origin-Host; diagnostic formatting is redacted.
    pub origin_host: Redacted<String>,
    /// Origin-Realm; diagnostic formatting is redacted.
    pub origin_realm: Redacted<String>,
    /// Optional answer-specific RFC 7944 routing priority.
    pub drmp: Option<SwmRoutingMessagePriority>,
    /// Ordered, well-formed additional command AVPs.
    pub additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmSessionTerminationAnswer {
    /// Construct an answer whose Session-Id is copied from the exact request.
    #[must_use]
    pub fn for_request(
        request: &SwmSessionTerminationRequestEnvelope,
        result: SwmSessionTerminationResult,
        origin_host: impl Into<Redacted<String>>,
        origin_realm: impl Into<Redacted<String>>,
    ) -> Self {
        Self {
            session_id: Some(request.request.session_id.clone()),
            result,
            origin_host: origin_host.into(),
            origin_realm: origin_realm.into(),
            drmp: None,
            additional_avps: Vec::new(),
        }
    }
}

impl fmt::Debug for SwmSessionTerminationAnswer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmSessionTerminationAnswer")
            .field("session_id", &self.session_id)
            .field("result", &self.result)
            .field("origin_host", &self.origin_host)
            .field("origin_realm", &self.origin_realm)
            .field("drmp", &self.drmp)
            .field("additional_avp_count", &self.additional_avps.len())
            .finish()
    }
}

impl zeroize::ZeroizeOnDrop for SwmSessionTerminationAnswer {}

/// Parsed or outbound STR together with retained request-correlation facts.
///
/// An inbound request parsed for server-side STA construction has no expected
/// answer peer. Outbound requests and forwarded requests bind one explicitly;
/// attempting answer correlation without that binding fails closed.
/// Retained Session-Id and User-Name clones remain independently zeroizing.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmSessionTerminationRequestEnvelope {
    transaction: super::SwmDiameterTransaction,
    proxiable: bool,
    potentially_retransmitted: bool,
    expected_answer_peer: Option<SwmExpectedAnswerPeer>,
    request: SwmSessionTerminationRequest,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

impl SwmSessionTerminationRequestEnvelope {
    /// Bind outbound request facts to their Diameter identifiers.
    #[must_use]
    pub fn for_outbound(
        request: SwmSessionTerminationRequest,
        transaction: super::SwmDiameterTransaction,
        expected_answer_peer: SwmExpectedAnswerPeer,
    ) -> Self {
        Self {
            transaction,
            proxiable: true,
            potentially_retransmitted: false,
            expected_answer_peer: Some(expected_answer_peer),
            request,
            proxy_infos: Vec::new(),
        }
    }

    /// Replace trusted expected-answer evidence for this retained request.
    ///
    /// The supplied binding must come from trusted transport/routing state,
    /// never from the uncorrelated answer being checked. This method does not
    /// allocate a Hop-by-Hop Identifier, edit routing AVPs, or implement proxy
    /// forwarding. The caller must already own the request transaction on the
    /// selected connection. Destination AVPs are not authentication evidence.
    #[must_use]
    pub fn with_expected_answer_peer(mut self, peer: SwmExpectedAnswerPeer) -> Self {
        self.expected_answer_peer = Some(peer);
        self
    }

    /// Borrow the redaction-safe answer-path binding.
    #[must_use]
    pub const fn expected_answer_peer(&self) -> Option<&SwmExpectedAnswerPeer> {
        self.expected_answer_peer.as_ref()
    }

    /// Mark a queued, unacknowledged STR for resend after link failover.
    ///
    /// The first transmission created by [`Self::for_outbound`] always clears
    /// T. RFC 6733 sections 3 and 5.5.4 permit this one-way transition only
    /// when resending pending state after link failover or equivalent recovery;
    /// an ordinary timer retry must not call it. The transition preserves the
    /// request and End-to-End Identifier while causing subsequent builds to
    /// set T. It also atomically installs a caller-reserved Hop-by-Hop
    /// Identifier unique on the replacement connection and replaces the
    /// expected peer, so an answer from the failed connection cannot satisfy
    /// the retried request.
    pub fn mark_for_failover_retransmission(
        &mut self,
        replacement_hop_by_hop_identifier: u32,
        new_peer: SwmExpectedAnswerPeer,
    ) {
        self.transaction = super::SwmDiameterTransaction::new(
            replacement_hop_by_hop_identifier,
            self.transaction.end_to_end_identifier(),
        );
        self.potentially_retransmitted = true;
        self.expected_answer_peer = Some(new_peer);
    }

    /// Return whether a built STR will carry the RFC 6733 T bit.
    #[must_use]
    pub const fn is_potentially_retransmitted(&self) -> bool {
        self.potentially_retransmitted
    }

    /// Borrow the typed STR facts.
    #[must_use]
    pub const fn request(&self) -> &SwmSessionTerminationRequest {
        &self.request
    }

    /// Return the request's immutable Diameter identifiers.
    #[must_use]
    pub const fn transaction(&self) -> super::SwmDiameterTransaction {
        self.transaction
    }

    /// Return the number of ordered Proxy-Info AVPs retained for an answer.
    #[must_use]
    pub fn proxy_info_count(&self) -> usize {
        self.proxy_infos.len()
    }

    /// Return whether `other` carries the same immutable STR replay payload.
    ///
    /// RFC 6733 sections 3 and 5.5.4 define duplicate identity and the
    /// hop-local fields that may change during failover. This SDK operation
    /// adds a stricter typed-payload guard for duplicate caches. It includes
    /// the End-to-End Identifier, P bit, every typed request fact, ordered
    /// Route-Record and extension AVPs, and the exact ordered Proxy-Info chain.
    /// It deliberately ignores the Hop-by-Hop Identifier, T bit, and
    /// expected-answer peer binding. Derived AVP length fields are also ignored
    /// because encoding computes them from the retained value.
    ///
    /// The result is only a boolean and exposes no retained AVP value. Active
    /// session ownership, duplicate-cache lifetime, and replay disposition
    /// remain consumer policy.
    #[must_use]
    pub fn same_replay_payload(&self, other: &Self) -> bool {
        self.transaction.end_to_end_identifier() == other.transaction.end_to_end_identifier()
            && self.proxiable == other.proxiable
            && self.request.has_same_replay_fields(&other.request)
            && additional_avp_sequences_match(&self.proxy_infos, &other.proxy_infos)
    }

    /// Consume and correlate a parsed STA with this exact STR.
    pub fn correlate_answer(
        self,
        answer: SwmSessionTerminationAnswerEnvelope,
    ) -> Result<SwmCorrelatedSessionTerminationExchange, SwmSessionTerminationCorrelationError>
    {
        let expected_answer_peer = self
            .expected_answer_peer
            .as_ref()
            .ok_or(SwmSessionTerminationCorrelationError::PeerBindingMissing)?;
        if expected_answer_peer.connection != answer.received_on {
            return Err(SwmSessionTerminationCorrelationError::PeerConnectionMismatch);
        }
        if self.transaction != answer.transaction {
            return Err(SwmSessionTerminationCorrelationError::TransactionMismatch);
        }
        if self.proxiable != answer.proxiable {
            return Err(SwmSessionTerminationCorrelationError::ProxiableMismatch);
        }
        if let Some(answer_session_id) = answer.answer.session_id.as_ref() {
            if self.request.session_id.as_ref() != answer_session_id.as_ref() {
                return Err(SwmSessionTerminationCorrelationError::SessionMismatch);
            }
        }
        if self.proxy_infos != answer.proxy_infos {
            return Err(SwmSessionTerminationCorrelationError::ProxyInfoMismatch);
        }
        validate_correlated_overload_control(
            &self.request.additional_avps,
            &answer.answer.additional_avps,
        )?;
        if !answer.error
            && !expected_answer_peer.matches_origin(
                answer.answer.origin_host.as_ref(),
                answer.answer.origin_realm.as_ref(),
            )
        {
            return Err(SwmSessionTerminationCorrelationError::PeerIdentityMismatch);
        }
        Ok(SwmCorrelatedSessionTerminationExchange {
            request: self,
            answer,
        })
    }
}

impl fmt::Debug for SwmSessionTerminationRequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmSessionTerminationRequestEnvelope")
            .field("transaction", &self.transaction)
            .field("proxiable", &self.proxiable)
            .field("potentially_retransmitted", &self.potentially_retransmitted)
            .field("expected_answer_peer", &self.expected_answer_peer)
            .field("request", &self.request)
            .field("proxy_info_count", &self.proxy_infos.len())
            .finish()
    }
}

impl zeroize::ZeroizeOnDrop for SwmSessionTerminationRequestEnvelope {}

/// Parsed STA together with immutable answer-correlation facts.
///
/// Its optional retained Session-Id remains zeroizing across envelope clones.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmSessionTerminationAnswerEnvelope {
    transaction: super::SwmDiameterTransaction,
    proxiable: bool,
    received_on: SwmDiameterConnectionToken,
    error: bool,
    answer: SwmSessionTerminationAnswer,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

impl SwmSessionTerminationAnswerEnvelope {
    /// Borrow the typed STA facts.
    #[must_use]
    pub const fn answer(&self) -> &SwmSessionTerminationAnswer {
        &self.answer
    }

    /// Return the answer's immutable Diameter identifiers.
    #[must_use]
    pub const fn transaction(&self) -> super::SwmDiameterTransaction {
        self.transaction
    }

    /// Return the authenticated connection generation that carried this STA.
    #[must_use]
    pub const fn received_on(&self) -> SwmDiameterConnectionToken {
        self.received_on
    }

    /// Return whether the received STA used Diameter's generic E-bit grammar.
    ///
    /// A generic error can originate at an intermediary instead of the final
    /// STR destination, so logical-Origin correlation intentionally exempts
    /// these answers while retaining connection, transaction, P, present
    /// Session-Id, Proxy-Info, and overload-control checks.
    #[must_use]
    pub const fn is_protocol_error(&self) -> bool {
        self.error
    }

    /// Return the number of ordered Proxy-Info AVPs retained for correlation.
    #[must_use]
    pub fn proxy_info_count(&self) -> usize {
        self.proxy_infos.len()
    }
}

impl fmt::Debug for SwmSessionTerminationAnswerEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmSessionTerminationAnswerEnvelope")
            .field("transaction", &self.transaction)
            .field("proxiable", &self.proxiable)
            .field("received_on", &self.received_on)
            .field("error", &self.error)
            .field("answer", &self.answer)
            .field("proxy_info_count", &self.proxy_infos.len())
            .finish()
    }
}

impl zeroize::ZeroizeOnDrop for SwmSessionTerminationAnswerEnvelope {}

/// Fully correlated typed STR/STA exchange.
pub struct SwmCorrelatedSessionTerminationExchange {
    request: SwmSessionTerminationRequestEnvelope,
    answer: SwmSessionTerminationAnswerEnvelope,
}

impl SwmCorrelatedSessionTerminationExchange {
    /// Borrow the correlated STR facts.
    #[must_use]
    pub const fn request(&self) -> &SwmSessionTerminationRequest {
        self.request.request()
    }

    /// Borrow the correlated STA facts.
    #[must_use]
    pub const fn answer(&self) -> &SwmSessionTerminationAnswer {
        self.answer.answer()
    }

    /// Return the identifiers shared by the request and answer.
    #[must_use]
    pub const fn transaction(&self) -> super::SwmDiameterTransaction {
        self.request.transaction()
    }
}

impl fmt::Debug for SwmCorrelatedSessionTerminationExchange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmCorrelatedSessionTerminationExchange")
            .field("transaction", &self.transaction())
            .field("request", &self.request())
            .field("answer", &self.answer())
            .finish()
    }
}

impl zeroize::ZeroizeOnDrop for SwmCorrelatedSessionTerminationExchange {}

/// Redaction-safe reason a valid STR and STA could not be correlated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmSessionTerminationCorrelationError {
    /// Hop-by-Hop or End-to-End identifier mismatch.
    TransactionMismatch,
    /// Session-Id mismatch.
    SessionMismatch,
    /// The answer did not preserve the request P bit.
    ProxiableMismatch,
    /// The request was not bound to an authenticated answer connection.
    PeerBindingMissing,
    /// The answer arrived on a different authenticated connection generation.
    PeerConnectionMismatch,
    /// An ordinary STA Origin violates the explicit logical-origin policy.
    PeerIdentityMismatch,
    /// The answer did not copy the request's ordered Proxy-Info chain exactly.
    ProxyInfoMismatch,
    /// The answer enabled overload control that the request did not offer.
    UnsolicitedOverloadControl,
    /// The answer selected overload capabilities that the request did not offer.
    IncompatibleOverloadControl,
    /// Retained overload-control bytes are not valid for their command role.
    MalformedOverloadControl,
}

impl SwmSessionTerminationCorrelationError {
    /// Stable code for logs and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TransactionMismatch => "swm_str_sta_transaction_mismatch",
            Self::SessionMismatch => "swm_str_sta_session_mismatch",
            Self::ProxiableMismatch => "swm_str_sta_proxiable_mismatch",
            Self::PeerBindingMissing => "swm_str_sta_peer_binding_missing",
            Self::PeerConnectionMismatch => "swm_str_sta_peer_connection_mismatch",
            Self::PeerIdentityMismatch => "swm_str_sta_peer_identity_mismatch",
            Self::ProxyInfoMismatch => "swm_str_sta_proxy_info_mismatch",
            Self::UnsolicitedOverloadControl => "swm_str_sta_unsolicited_overload_control",
            Self::IncompatibleOverloadControl => "swm_str_sta_incompatible_overload_control",
            Self::MalformedOverloadControl => "swm_str_sta_malformed_overload_control",
        }
    }
}

impl fmt::Display for SwmSessionTerminationCorrelationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SwmSessionTerminationCorrelationError {}

/// RFC 6733 Auth-Session-State value used by the SWm abort sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmAuthSessionState {
    /// The server keeps session state and expects a post-abort STR.
    StateMaintained,
    /// The server keeps no session state and does not expect a post-abort STR.
    NoStateMaintained,
}

impl SwmAuthSessionState {
    /// Parse one assigned RFC 6733 value.
    #[must_use]
    pub const fn from_value(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::StateMaintained),
            1 => Some(Self::NoStateMaintained),
            _ => None,
        }
    }

    /// Return the RFC 6733 wire value.
    #[must_use]
    pub const fn value(self) -> u32 {
        match self {
            Self::StateMaintained => 0,
            Self::NoStateMaintained => 1,
        }
    }

    /// Return whether a successful abort requires a subsequent STR.
    #[must_use]
    pub const fn requires_session_termination(self) -> bool {
        matches!(self, Self::StateMaintained)
    }
}

/// Typed Result-Code projection for one SWm ASA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmAbortSessionResult {
    /// DIAMETER_SUCCESS (2001).
    Success,
    /// DIAMETER_UNKNOWN_SESSION_ID (5002).
    UnknownSession,
    /// DIAMETER_UNABLE_TO_COMPLY (5012).
    UnableToComply,
    /// Another received base Diameter result code.
    ///
    /// This is receive-only because arbitrary results can require AVP context
    /// that the typed ASA builder does not model.
    Other(u32),
}

impl SwmAbortSessionResult {
    /// Project a base Diameter Result-Code.
    #[must_use]
    pub const fn from_result_code(result_code: u32) -> Self {
        match result_code {
            base::RESULT_CODE_DIAMETER_SUCCESS => Self::Success,
            base::RESULT_CODE_DIAMETER_UNKNOWN_SESSION_ID => Self::UnknownSession,
            base::RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY => Self::UnableToComply,
            other => Self::Other(other),
        }
    }

    /// Return the base Diameter Result-Code.
    #[must_use]
    pub const fn result_code(self) -> u32 {
        match self {
            Self::Success => base::RESULT_CODE_DIAMETER_SUCCESS,
            Self::UnknownSession => base::RESULT_CODE_DIAMETER_UNKNOWN_SESSION_ID,
            Self::UnableToComply => base::RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY,
            Self::Other(result_code) => result_code,
        }
    }
}

/// Typed AAA-originated SWm Abort-Session-Request facts.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmAbortSessionRequest {
    /// Session-Id; diagnostic formatting is redacted.
    pub session_id: Redacted<String>,
    /// Origin-Host; diagnostic formatting is redacted.
    pub origin_host: Redacted<String>,
    /// Origin-Realm; diagnostic formatting is redacted.
    pub origin_realm: Redacted<String>,
    /// Destination-Realm; diagnostic formatting is redacted.
    pub destination_realm: Redacted<String>,
    /// Required Destination-Host; diagnostic formatting is redacted.
    pub destination_host: Redacted<String>,
    /// Required permanent identity; diagnostic formatting is redacted.
    ///
    /// TS 29.273 section 7.1.2.4.1 marks this information element mandatory
    /// even though the section 7.2.2.3.1 command-format display uses optional
    /// brackets. The typed SWm profile follows the procedure's mandatory
    /// identity/session ownership check.
    pub user_name: Redacted<String>,
    /// Optional explicit session-state directive. Absence means state maintained.
    pub auth_session_state: Option<SwmAuthSessionState>,
    /// Optional Origin-State-Id.
    pub origin_state_id: Option<u32>,
    /// Optional RFC 7944 routing priority.
    pub drmp: Option<SwmRoutingMessagePriority>,
    /// Ordered Route-Record values; diagnostic formatting is redacted.
    pub route_records: Vec<Redacted<String>>,
    /// Ordered, well-formed additional command AVPs.
    pub additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmAbortSessionRequest {
    /// Return the effective RFC 6733 state directive.
    ///
    /// Omission has the RFC-defined `STATE_MAINTAINED` default.
    #[must_use]
    pub const fn effective_auth_session_state(&self) -> SwmAuthSessionState {
        match self.auth_session_state {
            Some(value) => value,
            None => SwmAuthSessionState::StateMaintained,
        }
    }

    fn has_same_replay_fields(&self, other: &Self) -> bool {
        self.session_id == other.session_id
            && self.origin_host == other.origin_host
            && self.origin_realm == other.origin_realm
            && self.destination_realm == other.destination_realm
            && self.destination_host == other.destination_host
            && self.user_name == other.user_name
            && self.auth_session_state == other.auth_session_state
            && self.origin_state_id == other.origin_state_id
            && self.drmp == other.drmp
            && self.route_records == other.route_records
            && additional_avp_sequences_match(&self.additional_avps, &other.additional_avps)
    }
}

impl fmt::Debug for SwmAbortSessionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmAbortSessionRequest")
            .field("session_id", &self.session_id)
            .field("origin_host", &self.origin_host)
            .field("origin_realm", &self.origin_realm)
            .field("destination_realm", &self.destination_realm)
            .field("destination_host", &self.destination_host)
            .field("user_name", &self.user_name)
            .field("auth_session_state", &self.auth_session_state)
            .field("origin_state_id", &self.origin_state_id)
            .field("drmp", &self.drmp)
            .field("route_record_count", &self.route_records.len())
            .field("additional_avp_count", &self.additional_avps.len())
            .finish()
    }
}

/// Typed ePDG-originated SWm Abort-Session-Answer facts.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmAbortSessionAnswer {
    /// Session-Id; diagnostic formatting is redacted.
    ///
    /// It is required for ordinary application answers and may be absent only
    /// from a received RFC 6733 generic E-bit answer, including the permitted
    /// permanent-failure fallback.
    pub session_id: Option<Redacted<String>>,
    /// Base Diameter result projection.
    pub result: SwmAbortSessionResult,
    /// Origin-Host; diagnostic formatting is redacted.
    pub origin_host: Redacted<String>,
    /// Origin-Realm; diagnostic formatting is redacted.
    pub origin_realm: Redacted<String>,
    /// Optional echoed User-Name; diagnostic formatting is redacted.
    pub user_name: Option<Redacted<String>>,
    /// Optional Origin-State-Id.
    pub origin_state_id: Option<u32>,
    /// Optional Error-Message; diagnostic formatting is redacted.
    pub error_message: Option<Redacted<String>>,
    /// Optional Error-Reporting-Host; diagnostic formatting is redacted.
    pub error_reporting_host: Option<Redacted<String>>,
    /// Optional RFC 7944 routing priority.
    pub drmp: Option<SwmRoutingMessagePriority>,
    /// Ordered, well-formed additional command AVPs.
    pub additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmAbortSessionAnswer {
    /// Construct an ASA whose Session-Id is copied from the exact ASR.
    ///
    /// The caller supplies its authenticated local Origin explicitly.
    /// Destination AVPs in the received request are routing data and are not
    /// used to infer or validate that local identity.
    #[must_use]
    pub fn for_request(
        request: &SwmAbortSessionRequestEnvelope,
        result: SwmAbortSessionResult,
        origin_host: impl Into<Redacted<String>>,
        origin_realm: impl Into<Redacted<String>>,
    ) -> Self {
        Self {
            session_id: Some(request.request.session_id.clone()),
            result,
            origin_host: origin_host.into(),
            origin_realm: origin_realm.into(),
            user_name: None,
            origin_state_id: None,
            error_message: None,
            error_reporting_host: None,
            drmp: None,
            additional_avps: Vec::new(),
        }
    }
}

impl fmt::Debug for SwmAbortSessionAnswer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmAbortSessionAnswer")
            .field("session_id", &self.session_id)
            .field("result", &self.result)
            .field("origin_host", &self.origin_host)
            .field("origin_realm", &self.origin_realm)
            .field("user_name", &self.user_name)
            .field("origin_state_id", &self.origin_state_id)
            .field("error_message", &self.error_message)
            .field("error_reporting_host", &self.error_reporting_host)
            .field("drmp", &self.drmp)
            .field("additional_avp_count", &self.additional_avps.len())
            .finish()
    }
}

/// Parsed or outbound ASR together with retained request-correlation facts.
///
/// An inbound request parsed for server-side ASA construction has no expected
/// answer peer. Outbound requests and forwarded requests bind one explicitly;
/// attempting answer correlation without that binding fails closed.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmAbortSessionRequestEnvelope {
    transaction: super::SwmDiameterTransaction,
    proxiable: bool,
    potentially_retransmitted: bool,
    expected_answer_peer: Option<SwmExpectedAnswerPeer>,
    request: SwmAbortSessionRequest,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

impl SwmAbortSessionRequestEnvelope {
    /// Bind outbound request facts to their Diameter identifiers.
    #[must_use]
    pub fn for_outbound(
        request: SwmAbortSessionRequest,
        transaction: super::SwmDiameterTransaction,
        expected_answer_peer: SwmExpectedAnswerPeer,
    ) -> Self {
        Self {
            transaction,
            proxiable: true,
            potentially_retransmitted: false,
            expected_answer_peer: Some(expected_answer_peer),
            request,
            proxy_infos: Vec::new(),
        }
    }

    /// Replace trusted expected-answer evidence for this retained request.
    ///
    /// The supplied binding must come from trusted transport/routing state,
    /// never from the uncorrelated answer being checked. This method does not
    /// allocate a Hop-by-Hop Identifier, edit routing AVPs, or implement proxy
    /// forwarding. The caller must already own the request transaction on the
    /// selected connection. Destination AVPs are not authentication evidence.
    #[must_use]
    pub fn with_expected_answer_peer(mut self, peer: SwmExpectedAnswerPeer) -> Self {
        self.expected_answer_peer = Some(peer);
        self
    }

    /// Borrow the redaction-safe answer-path binding.
    #[must_use]
    pub const fn expected_answer_peer(&self) -> Option<&SwmExpectedAnswerPeer> {
        self.expected_answer_peer.as_ref()
    }

    /// Mark a queued, unacknowledged ASR for resend after link failover.
    ///
    /// The first transmission created by [`Self::for_outbound`] always clears
    /// T. RFC 6733 sections 3 and 5.5.4 permit this one-way transition only
    /// when resending pending state after link failover or equivalent recovery;
    /// an ordinary timer retry must not call it. The transition preserves the
    /// request and End-to-End Identifier while causing subsequent builds to
    /// set T. It also atomically installs a caller-reserved Hop-by-Hop
    /// Identifier unique on the replacement connection and replaces the
    /// expected peer, so an answer from the failed connection cannot satisfy
    /// the retried request.
    pub fn mark_for_failover_retransmission(
        &mut self,
        replacement_hop_by_hop_identifier: u32,
        new_peer: SwmExpectedAnswerPeer,
    ) {
        self.transaction = super::SwmDiameterTransaction::new(
            replacement_hop_by_hop_identifier,
            self.transaction.end_to_end_identifier(),
        );
        self.potentially_retransmitted = true;
        self.expected_answer_peer = Some(new_peer);
    }

    /// Borrow the typed ASR facts.
    #[must_use]
    pub const fn request(&self) -> &SwmAbortSessionRequest {
        &self.request
    }

    /// Return the request's immutable Diameter identifiers.
    #[must_use]
    pub const fn transaction(&self) -> super::SwmDiameterTransaction {
        self.transaction
    }

    /// Return whether the request has Diameter's T bit set.
    #[must_use]
    pub const fn is_potentially_retransmitted(&self) -> bool {
        self.potentially_retransmitted
    }

    /// Return the number of ordered Proxy-Info AVPs retained for an answer.
    #[must_use]
    pub fn proxy_info_count(&self) -> usize {
        self.proxy_infos.len()
    }

    /// Return whether `other` carries the same immutable ASR replay payload.
    ///
    /// RFC 6733 sections 3 and 5.5.4 define duplicate identity and the
    /// hop-local fields that may change during failover. This SDK operation
    /// adds a stricter typed-payload guard for duplicate caches. It includes
    /// the End-to-End Identifier, P bit, every typed request fact, ordered
    /// Route-Record and extension AVPs, and the exact ordered Proxy-Info chain.
    /// It deliberately ignores the Hop-by-Hop Identifier, T bit, and
    /// expected-answer peer binding. Derived AVP length fields are also ignored
    /// because encoding computes them from the retained value.
    ///
    /// The result is only a boolean and exposes no retained AVP value. Active
    /// session ownership, duplicate-cache lifetime, and replay disposition
    /// remain consumer policy.
    #[must_use]
    pub fn same_replay_payload(&self, other: &Self) -> bool {
        self.transaction.end_to_end_identifier() == other.transaction.end_to_end_identifier()
            && self.proxiable == other.proxiable
            && self.request.has_same_replay_fields(&other.request)
            && additional_avp_sequences_match(&self.proxy_infos, &other.proxy_infos)
    }

    /// Derive the required follow-on STR after committing an ASA.
    ///
    /// TS 29.273 requires the ePDG that received the ASR to originate an
    /// administrative STR after a successful ASA when Diameter session state
    /// is maintained. This method is therefore available on the inbound
    /// request envelope, not on the AAA-side correlated ASR/ASA exchange. It
    /// validates the same request-bound answer facts as the ASA builder before
    /// deriving the STR.
    ///
    /// The SDK cannot prove that `committed_answer` was durably committed or
    /// sent. The consumer must call this only after committing the exact ASA
    /// bytes, allocate a fresh STR transaction and expected peer, and own
    /// teardown/STR ordering, retry, and compensation state.
    pub fn post_abort_session_termination(
        &self,
        committed_answer: &SwmAbortSessionAnswer,
        ctx: EncodeContext,
    ) -> Result<SwmPostAbortSessionTermination, EncodeError> {
        validate_abort_request_for_encode(&self.request, ctx)?;
        validate_abort_answer_for_encode(self, committed_answer, ctx)?;
        if committed_answer.result != SwmAbortSessionResult::Success {
            return Ok(SwmPostAbortSessionTermination::NotRequiredAbortUnsuccessful);
        }
        if !self
            .request
            .effective_auth_session_state()
            .requires_session_termination()
        {
            return Ok(SwmPostAbortSessionTermination::NotRequiredNoState);
        }
        Ok(SwmPostAbortSessionTermination::Required(Box::new(
            SwmSessionTerminationRequest {
                session_id: Sensitive::from(self.request.session_id.as_ref().to_owned()),
                origin_host: committed_answer.origin_host.clone(),
                origin_realm: committed_answer.origin_realm.clone(),
                destination_realm: self.request.origin_realm.clone(),
                destination_host: Some(self.request.origin_host.clone()),
                termination_cause: SwmTerminationCause::Administrative,
                user_name: Sensitive::from(self.request.user_name.as_ref().to_owned()),
                drmp: self.request.drmp,
                route_records: Vec::new(),
                additional_avps: Vec::new(),
            },
        )))
    }

    /// Consume and correlate a parsed ASA with this exact ASR.
    pub fn correlate_answer(
        self,
        answer: SwmAbortSessionAnswerEnvelope,
    ) -> Result<SwmCorrelatedAbortSessionExchange, SwmAbortSessionCorrelationError> {
        let expected_answer_peer = self
            .expected_answer_peer
            .as_ref()
            .ok_or(SwmAbortSessionCorrelationError::PeerBindingMissing)?;
        if expected_answer_peer.connection != answer.received_on {
            return Err(SwmAbortSessionCorrelationError::PeerConnectionMismatch);
        }
        if self.transaction != answer.transaction {
            return Err(SwmAbortSessionCorrelationError::TransactionMismatch);
        }
        if self.proxiable != answer.proxiable {
            return Err(SwmAbortSessionCorrelationError::ProxiableMismatch);
        }
        if let Some(answer_session_id) = answer.answer.session_id.as_ref() {
            if self.request.session_id.as_ref() != answer_session_id.as_ref() {
                return Err(SwmAbortSessionCorrelationError::SessionMismatch);
            }
        }
        if !answer.error
            && !expected_answer_peer.matches_origin(
                answer.answer.origin_host.as_ref(),
                answer.answer.origin_realm.as_ref(),
            )
        {
            return Err(SwmAbortSessionCorrelationError::PeerIdentityMismatch);
        }
        if let Some(answer_user_name) = answer.answer.user_name.as_ref() {
            if self.request.user_name.as_ref() != answer_user_name.as_ref() {
                return Err(SwmAbortSessionCorrelationError::UserNameMismatch);
            }
        }
        if self.proxy_infos != answer.proxy_infos {
            return Err(SwmAbortSessionCorrelationError::ProxyInfoMismatch);
        }
        validate_abort_correlated_overload_control(
            &self.request.additional_avps,
            &answer.answer.additional_avps,
        )?;
        Ok(SwmCorrelatedAbortSessionExchange {
            request: self,
            answer,
        })
    }
}

impl fmt::Debug for SwmAbortSessionRequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmAbortSessionRequestEnvelope")
            .field("transaction", &self.transaction)
            .field("proxiable", &self.proxiable)
            .field("potentially_retransmitted", &self.potentially_retransmitted)
            .field("expected_answer_peer", &self.expected_answer_peer)
            .field("request", &self.request)
            .field("proxy_info_count", &self.proxy_infos.len())
            .finish()
    }
}

/// Parsed ASA together with immutable answer-correlation facts.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmAbortSessionAnswerEnvelope {
    transaction: super::SwmDiameterTransaction,
    proxiable: bool,
    received_on: SwmDiameterConnectionToken,
    error: bool,
    answer: SwmAbortSessionAnswer,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

impl SwmAbortSessionAnswerEnvelope {
    /// Borrow the typed ASA facts.
    #[must_use]
    pub const fn answer(&self) -> &SwmAbortSessionAnswer {
        &self.answer
    }

    /// Return the answer's immutable Diameter identifiers.
    #[must_use]
    pub const fn transaction(&self) -> super::SwmDiameterTransaction {
        self.transaction
    }

    /// Return the authenticated connection generation that carried this ASA.
    #[must_use]
    pub const fn received_on(&self) -> SwmDiameterConnectionToken {
        self.received_on
    }

    /// Return whether the received ASA used Diameter's generic E-bit grammar.
    ///
    /// Protocol-error answers can originate at an intermediary rather than
    /// the final logical server and can omit Session-Id under RFC 6733.
    #[must_use]
    pub const fn is_protocol_error(&self) -> bool {
        self.error
    }
}

impl fmt::Debug for SwmAbortSessionAnswerEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmAbortSessionAnswerEnvelope")
            .field("transaction", &self.transaction)
            .field("proxiable", &self.proxiable)
            .field("received_on", &self.received_on)
            .field("error", &self.error)
            .field("answer", &self.answer)
            .field("proxy_info_count", &self.proxy_infos.len())
            .finish()
    }
}

/// Fully correlated typed ASR/ASA exchange at the ASR originator.
///
/// Under TS 29.273, the AAA-side consumer releases its local resources after a
/// successful ASA. The ePDG-side follow-on STR disposition is instead derived
/// from the inbound [`SwmAbortSessionRequestEnvelope`] and committed ASA.
pub struct SwmCorrelatedAbortSessionExchange {
    request: SwmAbortSessionRequestEnvelope,
    answer: SwmAbortSessionAnswerEnvelope,
}

impl SwmCorrelatedAbortSessionExchange {
    /// Borrow the correlated ASR facts.
    #[must_use]
    pub const fn request(&self) -> &SwmAbortSessionRequest {
        self.request.request()
    }

    /// Borrow the correlated ASA facts.
    #[must_use]
    pub const fn answer(&self) -> &SwmAbortSessionAnswer {
        self.answer.answer()
    }

    /// Return the identifiers shared by the request and answer.
    #[must_use]
    pub const fn transaction(&self) -> super::SwmDiameterTransaction {
        self.request.transaction()
    }
}

impl fmt::Debug for SwmCorrelatedAbortSessionExchange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmCorrelatedAbortSessionExchange")
            .field("transaction", &self.transaction())
            .field("request", &self.request())
            .field("answer", &self.answer())
            .finish()
    }
}

/// Deterministic ePDG protocol disposition following a committed request-bound ASA.
#[derive(Clone, PartialEq, Eq)]
pub enum SwmPostAbortSessionTermination {
    /// The successful abort requires an administrative STR.
    Required(Box<SwmSessionTerminationRequest>),
    /// `NO_STATE_MAINTAINED` suppresses the post-abort STR.
    NotRequiredNoState,
    /// An unsuccessful ASA does not trigger the successful-abort STR path.
    NotRequiredAbortUnsuccessful,
}

impl fmt::Debug for SwmPostAbortSessionTermination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Required(request) => formatter.debug_tuple("Required").field(request).finish(),
            Self::NotRequiredNoState => formatter.write_str("NotRequiredNoState"),
            Self::NotRequiredAbortUnsuccessful => {
                formatter.write_str("NotRequiredAbortUnsuccessful")
            }
        }
    }
}

/// Redaction-safe reason a valid ASR and ASA could not be correlated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmAbortSessionCorrelationError {
    /// The retained request has no trusted expected-answer binding.
    PeerBindingMissing,
    /// The ASA arrived on a different authenticated connection generation.
    PeerConnectionMismatch,
    /// Hop-by-Hop or End-to-End identifier mismatch.
    TransactionMismatch,
    /// Session-Id mismatch.
    SessionMismatch,
    /// The answer did not preserve the request P bit.
    ProxiableMismatch,
    /// The ASA logical Origin violates the request's explicit routing policy.
    PeerIdentityMismatch,
    /// An optional ASA User-Name does not match the ASR identity.
    UserNameMismatch,
    /// The answer did not preserve the ordered Proxy-Info chain.
    ProxyInfoMismatch,
    /// The answer enabled overload control that the request did not offer.
    UnsolicitedOverloadControl,
    /// The answer selected overload capabilities that the request did not offer.
    IncompatibleOverloadControl,
    /// Retained overload-control bytes are not valid for their command role.
    MalformedOverloadControl,
}

impl SwmAbortSessionCorrelationError {
    /// Stable code for logs and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PeerBindingMissing => "swm_asr_asa_peer_binding_missing",
            Self::PeerConnectionMismatch => "swm_asr_asa_peer_connection_mismatch",
            Self::TransactionMismatch => "swm_asr_asa_transaction_mismatch",
            Self::SessionMismatch => "swm_asr_asa_session_mismatch",
            Self::ProxiableMismatch => "swm_asr_asa_proxiable_mismatch",
            Self::PeerIdentityMismatch => "swm_asr_asa_peer_identity_mismatch",
            Self::UserNameMismatch => "swm_asr_asa_user_name_mismatch",
            Self::ProxyInfoMismatch => "swm_asr_asa_proxy_info_mismatch",
            Self::UnsolicitedOverloadControl => "swm_asr_asa_unsolicited_overload_control",
            Self::IncompatibleOverloadControl => "swm_asr_asa_incompatible_overload_control",
            Self::MalformedOverloadControl => "swm_asr_asa_malformed_overload_control",
        }
    }
}

impl fmt::Display for SwmAbortSessionCorrelationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SwmAbortSessionCorrelationError {}

/// Build one outbound SWm ASR from its request-bound envelope.
pub fn build_swm_abort_session_request(
    envelope: &SwmAbortSessionRequestEnvelope,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    validate_abort_request_for_encode(&envelope.request, ctx)?;
    let expected_answer_peer = envelope.expected_answer_peer.as_ref().ok_or_else(|| {
        encode_error(
            "outbound SWm ASR requires an authenticated answer-peer binding",
            "6.2.1",
        )
    })?;
    expected_answer_peer.validate_for_encode()?;
    if !envelope.proxiable {
        return Err(encode_error("SWm ASR must set the P bit", "7.2.2.3.1"));
    }
    if envelope.proxy_infos.len() > MAX_PROXY_INFOS {
        return Err(encode_error(
            "SWm ASR Proxy-Info count exceeds the typed boundary",
            "7.2.2.3.1",
        ));
    }

    let request = &envelope.request;
    let mut raw_avps = BytesMut::new();
    append_string(
        &mut raw_avps,
        base::AVP_SESSION_ID,
        request.session_id.as_ref(),
        ctx,
    )?;
    if let Some(drmp) = request.drmp {
        append_drmp(&mut raw_avps, drmp, ctx)?;
    }
    append_string(
        &mut raw_avps,
        base::AVP_ORIGIN_HOST,
        request.origin_host.as_ref(),
        ctx,
    )?;
    append_string(
        &mut raw_avps,
        base::AVP_ORIGIN_REALM,
        request.origin_realm.as_ref(),
        ctx,
    )?;
    append_string(
        &mut raw_avps,
        base::AVP_DESTINATION_REALM,
        request.destination_realm.as_ref(),
        ctx,
    )?;
    append_string(
        &mut raw_avps,
        base::AVP_DESTINATION_HOST,
        request.destination_host.as_ref(),
        ctx,
    )?;
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        base::AVP_AUTH_APPLICATION_ID,
        APPLICATION_ID.get(),
        true,
        ctx,
    )?;
    append_string(
        &mut raw_avps,
        base::AVP_USER_NAME,
        request.user_name.as_ref(),
        ctx,
    )?;
    if let Some(auth_session_state) = request.auth_session_state {
        builder_helpers::append_u32_avp(
            &mut raw_avps,
            base::AVP_AUTH_SESSION_STATE,
            auth_session_state.value(),
            true,
            ctx,
        )?;
    }
    if let Some(origin_state_id) = request.origin_state_id {
        builder_helpers::append_u32_avp(
            &mut raw_avps,
            base::AVP_ORIGIN_STATE_ID,
            origin_state_id,
            true,
            ctx,
        )?;
    }
    for proxy_info in &envelope.proxy_infos {
        proxy_info.append_to(&mut raw_avps, ctx)?;
    }
    for route_record in &request.route_records {
        append_string(
            &mut raw_avps,
            base::AVP_ROUTE_RECORD,
            route_record.as_ref(),
            ctx,
        )?;
    }
    for avp in &request.additional_avps {
        avp.append_to(&mut raw_avps, ctx)?;
    }

    let mut flags = builder_helpers::app_request_flags();
    if envelope.potentially_retransmitted {
        flags = CommandFlags::from_bits(flags.bits() | CommandFlags::POTENTIALLY_RETRANSMITTED);
    }
    builder_helpers::build_message(
        flags,
        COMMAND_ABORT_SESSION,
        APPLICATION_ID,
        raw_avps,
        envelope.transaction.hop_by_hop_identifier(),
        envelope.transaction.end_to_end_identifier(),
        ctx,
        "7.2.2.3.1",
    )
}

/// Build one ASA bound to the exact ASR identifiers, Session-Id, P bit, and
/// ordered Proxy-Info chain.
pub fn build_swm_abort_session_answer(
    request: &SwmAbortSessionRequestEnvelope,
    answer: &SwmAbortSessionAnswer,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    validate_abort_answer_for_encode(request, answer, ctx)?;
    let mut raw_avps = BytesMut::new();
    let Some(session_id) = answer.session_id.as_ref() else {
        return Err(encode_error(
            "originated SWm ASA requires Session-Id",
            "7.2.2.3.2",
        ));
    };
    append_string(
        &mut raw_avps,
        base::AVP_SESSION_ID,
        session_id.as_ref(),
        ctx,
    )?;
    if let Some(drmp) = answer.drmp {
        append_drmp(&mut raw_avps, drmp, ctx)?;
    }
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        base::AVP_RESULT_CODE,
        answer.result.result_code(),
        true,
        ctx,
    )?;
    append_string(
        &mut raw_avps,
        base::AVP_ORIGIN_HOST,
        answer.origin_host.as_ref(),
        ctx,
    )?;
    append_string(
        &mut raw_avps,
        base::AVP_ORIGIN_REALM,
        answer.origin_realm.as_ref(),
        ctx,
    )?;
    if let Some(user_name) = answer.user_name.as_ref() {
        append_string(&mut raw_avps, base::AVP_USER_NAME, user_name.as_ref(), ctx)?;
    }
    if let Some(origin_state_id) = answer.origin_state_id {
        builder_helpers::append_u32_avp(
            &mut raw_avps,
            base::AVP_ORIGIN_STATE_ID,
            origin_state_id,
            true,
            ctx,
        )?;
    }
    if let Some(error_message) = answer.error_message.as_ref() {
        builder_helpers::append_utf8_avp(
            &mut raw_avps,
            base::AVP_ERROR_MESSAGE,
            error_message.as_ref(),
            false,
            ctx,
        )?;
    }
    if let Some(error_reporting_host) = answer.error_reporting_host.as_ref() {
        builder_helpers::append_utf8_avp(
            &mut raw_avps,
            base::AVP_ERROR_REPORTING_HOST,
            error_reporting_host.as_ref(),
            false,
            ctx,
        )?;
    }
    for avp in &answer.additional_avps {
        avp.append_to(&mut raw_avps, ctx)?;
    }
    for proxy_info in &request.proxy_infos {
        proxy_info.append_to(&mut raw_avps, ctx)?;
    }

    builder_helpers::build_message(
        builder_helpers::app_answer_flags(builder_helpers::result_code_requires_error_bit(
            answer.result.result_code(),
        )),
        COMMAND_ABORT_SESSION,
        APPLICATION_ID,
        raw_avps,
        request.transaction.hop_by_hop_identifier(),
        request.transaction.end_to_end_identifier(),
        ctx,
        "7.2.2.3.2",
    )
}

/// Parse one SWm ASR, returning the legacy structured decode error surface.
pub fn parse_swm_abort_session_request(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmAbortSessionRequest, DecodeError> {
    parse_swm_abort_session_request_with_provenance(message, ctx)
        .map_err(DiameterParserError::into_decode_error)
}

/// Parse one SWm ASR with sealed missing-AVP provenance for the generic
/// request-bound RFC 6733 error-answer mapper.
pub fn parse_swm_abort_session_request_with_provenance(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmAbortSessionRequest, DiameterParserError> {
    parse_abort_request_parts(message, ctx).map(|parts| parts.request)
}

/// Parse one inbound SWm ASR while retaining identifiers, T, P, Session-Id,
/// and ordered Proxy-Info required for response construction.
///
/// The returned server-side envelope is deliberately not bound to an expected
/// answer peer. It is suitable for local processing and ASA construction. A
/// caller inspecting a previously originated outbound wire request can attach
/// its retained authenticated routing evidence with
/// [`SwmAbortSessionRequestEnvelope::with_expected_answer_peer`]; doing so does
/// not make an inbound request safe to proxy or relay.
pub fn parse_swm_abort_session_request_envelope(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmAbortSessionRequestEnvelope, DecodeError> {
    parse_swm_abort_session_request_envelope_with_provenance(message, ctx)
        .map_err(DiameterParserError::into_decode_error)
}

/// Provenance-aware form of [`parse_swm_abort_session_request_envelope`].
pub fn parse_swm_abort_session_request_envelope_with_provenance(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmAbortSessionRequestEnvelope, DiameterParserError> {
    let parts = parse_abort_request_parts(message, ctx)?;
    Ok(SwmAbortSessionRequestEnvelope {
        transaction: super::SwmDiameterTransaction::from_message(message),
        proxiable: message.header.flags.is_proxiable(),
        potentially_retransmitted: message.header.flags.is_potentially_retransmitted(),
        expected_answer_peer: None,
        request: parts.request,
        proxy_infos: parts.proxy_infos,
    })
}

/// Parse one SWm ASA.
pub fn parse_swm_abort_session_answer(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmAbortSessionAnswer, DecodeError> {
    parse_abort_answer_parts(message, ctx).map(|parts| parts.answer)
}

/// Parse one SWm ASA while retaining its authenticated connection generation
/// and identifiers for exact ASR correlation.
pub fn parse_swm_abort_session_answer_envelope_from_connection(
    message: &Message<'_>,
    received_on: SwmDiameterConnectionToken,
    ctx: DecodeContext,
) -> Result<SwmAbortSessionAnswerEnvelope, DecodeError> {
    let parts = parse_abort_answer_parts(message, ctx)?;
    Ok(SwmAbortSessionAnswerEnvelope {
        transaction: super::SwmDiameterTransaction::from_message(message),
        proxiable: message.header.flags.is_proxiable(),
        received_on,
        error: message.header.flags.is_error(),
        answer: parts.answer,
        proxy_infos: parts.proxy_infos,
    })
}

struct ParsedAbortRequestParts {
    request: SwmAbortSessionRequest,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

fn parse_abort_request_parts(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<ParsedAbortRequestParts, DiameterParserError> {
    builder_helpers::ensure_app_header(
        message,
        COMMAND_ABORT_SESSION,
        APPLICATION_ID,
        CommandKind::Request,
        "7.2.2.3.1",
    )
    .and_then(|()| validate_abort_request_header(message))
    .map_err(|error| DiameterParserError::decoded(message, error))?;

    let mut session_id = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut destination_realm = None;
    let mut destination_host = None;
    let mut auth_application_id = None;
    let mut user_name = None;
    let mut auth_session_state = None;
    let mut origin_state_id = None;
    let mut drmp = None;
    let mut route_records = Vec::new();
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    let mut proxy_infos = Vec::new();

    builder_helpers::for_each_avp(
        message.raw_avps,
        ctx,
        DIAMETER_HEADER_LEN,
        0,
        |offset, avp| {
            let value_offset =
                builder_helpers::offset_add(offset, avp.header.header_len(), "7.2.2.3.1")?;
            let key = avp.header.key();
            if key.vendor_id().is_some() && abort_core_code(key.code()) {
                return Err(forbidden_error_at(
                    offset,
                    "SWm ASR core AVP uses the wrong vendor",
                    "7.2.2.3.1",
                ));
            }
            if key == AvpKey::ietf(base::AVP_SESSION_ID) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "8.8")?;
                builder_helpers::set_once(&mut session_id, Redacted::from(value), offset, "8.8")?;
            } else if key == AvpKey::ietf(AVP_DRMP) {
                validate_drmp(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "9.1")?;
                let value = SwmRoutingMessagePriority::from_value(value).ok_or_else(|| {
                    DecodeError::new(
                        DecodeErrorCode::InvalidEnumValue {
                            field: "DRMP priority",
                            value: u64::from(value),
                        },
                        value_offset,
                    )
                    .with_spec_ref(SpecRef::new("ietf", "RFC7944", "9.1"))
                })?;
                builder_helpers::set_once(&mut drmp, value, offset, "9.1")?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_HOST) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "6.3")?;
                builder_helpers::set_once(&mut origin_host, Redacted::from(value), offset, "6.3")?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_REALM) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "6.4")?;
                builder_helpers::set_once(&mut origin_realm, Redacted::from(value), offset, "6.4")?;
            } else if key == AvpKey::ietf(base::AVP_DESTINATION_REALM) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "6.6")?;
                builder_helpers::set_once(
                    &mut destination_realm,
                    Redacted::from(value),
                    offset,
                    "6.6",
                )?;
            } else if key == AvpKey::ietf(base::AVP_DESTINATION_HOST) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "6.5")?;
                builder_helpers::set_once(
                    &mut destination_host,
                    Redacted::from(value),
                    offset,
                    "6.5",
                )?;
            } else if key == AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID) {
                validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "6.8")?;
                builder_helpers::set_once(&mut auth_application_id, value, offset, "6.8")?;
            } else if key == AvpKey::ietf(base::AVP_USER_NAME) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "8.14")?;
                builder_helpers::set_once(&mut user_name, Redacted::from(value), offset, "8.14")?;
            } else if key == AvpKey::ietf(base::AVP_AUTH_SESSION_STATE) {
                validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.11")?;
                let value = SwmAuthSessionState::from_value(value).ok_or_else(|| {
                    DecodeError::new(
                        DecodeErrorCode::InvalidEnumValue {
                            field: "Auth-Session-State",
                            value: u64::from(value),
                        },
                        value_offset,
                    )
                    .with_spec_ref(SpecRef::new("ietf", "RFC6733", "8.11"))
                })?;
                builder_helpers::set_once(&mut auth_session_state, value, offset, "8.11")?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_STATE_ID) {
                validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.16")?;
                builder_helpers::set_once(&mut origin_state_id, value, offset, "8.16")?;
            } else if key == AvpKey::ietf(base::AVP_PROXY_INFO) {
                if proxy_infos.len() >= MAX_PROXY_INFOS {
                    return Err(count_error_at(
                        offset,
                        "SWm ASR Proxy-Info count exceeds its bound",
                        "7.2.2.3.1",
                    ));
                }
                validate_proxy_info(&avp, ctx, offset, value_offset)?;
                proxy_infos.push(SwmAdditionalAvp::from_raw(&avp));
            } else if key == AvpKey::ietf(base::AVP_ROUTE_RECORD) {
                if route_records.len() >= MAX_ROUTE_RECORDS {
                    return Err(count_error_at(
                        offset,
                        "SWm ASR Route-Record count exceeds its bound",
                        "7.2.2.3.1",
                    ));
                }
                let value = parse_core_string(&avp, ctx, offset, value_offset, "6.7.1")?;
                route_records.push(Redacted::from(value));
            } else if key == AvpKey::ietf(base::AVP_RESULT_CODE)
                || key == AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT)
                || key == AvpKey::ietf(base::AVP_TERMINATION_CAUSE)
                || key == AvpKey::ietf(base::AVP_ERROR_MESSAGE)
                || key == AvpKey::ietf(base::AVP_ERROR_REPORTING_HOST)
                || key == AvpKey::ietf(base::AVP_FAILED_AVP)
                || key == AvpKey::ietf(AVP_OC_OLR)
                || key == AvpKey::ietf(AVP_LOAD)
            {
                return Err(forbidden_error_at(
                    offset,
                    "SWm ASR contains an answer-only or prohibited AVP",
                    "7.2.2.3.1",
                ));
            } else if let Some(additional) =
                parse_additional_avp(&avp, ctx, offset, value_offset, LifecycleRole::AbortRequest)?
            {
                if additional_avps.len() >= MAX_ADDITIONAL_AVPS {
                    return Err(count_error_at(
                        offset,
                        "SWm ASR additional AVP count exceeds its bound",
                        "7.2.2.3.1",
                    ));
                }
                if !additional_key_is_repeatable(key, LifecycleRole::AbortRequest)
                    && !additional_keys.insert(key)
                {
                    return Err(duplicate_error_at(
                        offset,
                        "SWm ASR additional singleton AVP is duplicated",
                        "7.2.2.3.1",
                    ));
                }
                additional_avps.push(additional);
            }
            Ok(())
        },
    )
    .map_err(|error| DiameterParserError::decoded(message, error))?;

    let auth_application_id = require_abort_request_field(
        auth_application_id,
        "SWm ASR requires Auth-Application-Id",
        AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID),
        message,
    )?;
    if auth_application_id != APPLICATION_ID.get() {
        return Err(DiameterParserError::decoded(
            message,
            decode_error(
                "SWm ASR Auth-Application-Id does not match the SWm application id",
                DIAMETER_HEADER_LEN,
                "7.2.2.3.1",
            ),
        ));
    }

    Ok(ParsedAbortRequestParts {
        request: SwmAbortSessionRequest {
            session_id: require_abort_request_field(
                session_id,
                "SWm ASR requires Session-Id",
                AvpKey::ietf(base::AVP_SESSION_ID),
                message,
            )?,
            origin_host: require_abort_request_field(
                origin_host,
                "SWm ASR requires Origin-Host",
                AvpKey::ietf(base::AVP_ORIGIN_HOST),
                message,
            )?,
            origin_realm: require_abort_request_field(
                origin_realm,
                "SWm ASR requires Origin-Realm",
                AvpKey::ietf(base::AVP_ORIGIN_REALM),
                message,
            )?,
            destination_realm: require_abort_request_field(
                destination_realm,
                "SWm ASR requires Destination-Realm",
                AvpKey::ietf(base::AVP_DESTINATION_REALM),
                message,
            )?,
            destination_host: require_abort_request_field(
                destination_host,
                "SWm ASR requires Destination-Host",
                AvpKey::ietf(base::AVP_DESTINATION_HOST),
                message,
            )?,
            user_name: require_abort_request_field(
                user_name,
                "SWm ASR requires User-Name for the permanent-identity ownership check",
                AvpKey::ietf(base::AVP_USER_NAME),
                message,
            )?,
            auth_session_state,
            origin_state_id,
            drmp,
            route_records,
            additional_avps,
        },
        proxy_infos,
    })
}

struct ParsedAbortAnswerParts {
    answer: SwmAbortSessionAnswer,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

fn parse_abort_answer_parts(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<ParsedAbortAnswerParts, DecodeError> {
    builder_helpers::ensure_app_header(
        message,
        COMMAND_ABORT_SESSION,
        APPLICATION_ID,
        CommandKind::Answer,
        "7.2.2.3.2",
    )?;
    validate_abort_answer_header(message)?;

    let mut session_id = None;
    let mut result_code = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut user_name = None;
    let mut origin_state_id = None;
    let mut error_message = None;
    let mut error_reporting_host = None;
    let mut drmp = None;
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    let mut proxy_infos = Vec::new();

    builder_helpers::for_each_avp(
        message.raw_avps,
        ctx,
        DIAMETER_HEADER_LEN,
        0,
        |offset, avp| {
            let value_offset =
                builder_helpers::offset_add(offset, avp.header.header_len(), "7.2.2.3.2")?;
            let key = avp.header.key();
            if key.vendor_id().is_some() && abort_core_code(key.code()) {
                return Err(forbidden_error_at(
                    offset,
                    "SWm ASA core AVP uses the wrong vendor",
                    "7.2.2.3.2",
                ));
            }
            if key == AvpKey::ietf(base::AVP_SESSION_ID) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "8.8")?;
                builder_helpers::set_once(&mut session_id, Redacted::from(value), offset, "8.8")?;
            } else if key == AvpKey::ietf(AVP_DRMP) {
                validate_drmp(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "9.1")?;
                let value = SwmRoutingMessagePriority::from_value(value).ok_or_else(|| {
                    DecodeError::new(
                        DecodeErrorCode::InvalidEnumValue {
                            field: "DRMP priority",
                            value: u64::from(value),
                        },
                        value_offset,
                    )
                    .with_spec_ref(SpecRef::new("ietf", "RFC7944", "9.1"))
                })?;
                builder_helpers::set_once(&mut drmp, value, offset, "9.1")?;
            } else if key == AvpKey::ietf(base::AVP_RESULT_CODE) {
                validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.1")?;
                builder_helpers::set_once(&mut result_code, value, offset, "7.1")?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_HOST) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "6.3")?;
                builder_helpers::set_once(&mut origin_host, Redacted::from(value), offset, "6.3")?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_REALM) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "6.4")?;
                builder_helpers::set_once(&mut origin_realm, Redacted::from(value), offset, "6.4")?;
            } else if key == AvpKey::ietf(base::AVP_USER_NAME) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "8.14")?;
                builder_helpers::set_once(&mut user_name, Redacted::from(value), offset, "8.14")?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_STATE_ID) {
                validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.16")?;
                builder_helpers::set_once(&mut origin_state_id, value, offset, "8.16")?;
            } else if key == AvpKey::ietf(base::AVP_ERROR_MESSAGE) {
                let value = parse_core_utf8(&avp, ctx, offset, value_offset, "7.3")?;
                builder_helpers::set_once(
                    &mut error_message,
                    Redacted::from(value),
                    offset,
                    "7.3",
                )?;
            } else if key == AvpKey::ietf(base::AVP_ERROR_REPORTING_HOST) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "7.4")?;
                builder_helpers::set_once(
                    &mut error_reporting_host,
                    Redacted::from(value),
                    offset,
                    "7.4",
                )?;
            } else if key == AvpKey::ietf(base::AVP_PROXY_INFO) {
                if proxy_infos.len() >= MAX_PROXY_INFOS {
                    return Err(count_error_at(
                        offset,
                        "SWm ASA Proxy-Info count exceeds its bound",
                        "7.2.2.3.2",
                    ));
                }
                validate_proxy_info(&avp, ctx, offset, value_offset)?;
                proxy_infos.push(SwmAdditionalAvp::from_raw(&avp));
            } else if key == AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT)
                && !message.header.flags.is_error()
            {
                return Err(forbidden_error_at(
                    offset,
                    "ordinary SWm ASA cannot contain Experimental-Result with Result-Code",
                    "7.2.2.3.2",
                ));
            } else if key == AvpKey::ietf(base::AVP_DESTINATION_REALM)
                || key == AvpKey::ietf(base::AVP_DESTINATION_HOST)
                || key == AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID)
                || key == AvpKey::ietf(base::AVP_AUTH_SESSION_STATE)
                || key == AvpKey::ietf(base::AVP_TERMINATION_CAUSE)
                || key == AvpKey::ietf(base::AVP_ROUTE_RECORD)
            {
                return Err(forbidden_error_at(
                    offset,
                    "SWm ASA contains a request-only or prohibited AVP",
                    "7.2.2.3.2",
                ));
            } else if let Some(additional) =
                parse_additional_avp(&avp, ctx, offset, value_offset, LifecycleRole::AbortAnswer)?
            {
                if additional_avps.len() >= MAX_ADDITIONAL_AVPS {
                    return Err(count_error_at(
                        offset,
                        "SWm ASA additional AVP count exceeds its bound",
                        "7.2.2.3.2",
                    ));
                }
                if !additional_key_is_repeatable(key, LifecycleRole::AbortAnswer)
                    && !additional_keys.insert(key)
                {
                    return Err(duplicate_error_at(
                        offset,
                        "SWm ASA additional singleton AVP is duplicated",
                        "7.2.2.3.2",
                    ));
                }
                additional_avps.push(additional);
            }
            Ok(())
        },
    )?;

    let result_code =
        builder_helpers::require_field(result_code, "SWm ASA requires Result-Code", "7.2.2.3.2")?;
    validate_result_code(result_code, "7.2.2.3.2")?;
    validate_abort_supported_result_context_decode(
        result_code,
        &additional_avps,
        DIAMETER_HEADER_LEN,
    )?;
    validate_received_answer_error_bit(result_code, message.header.flags.is_error())?;
    validate_abort_answer_overload_control_decode(&additional_avps, ctx)?;

    let session_id = if message.header.flags.is_error() {
        session_id
    } else {
        Some(builder_helpers::require_field(
            session_id,
            "ordinary SWm ASA requires Session-Id",
            "7.2.2.3.2",
        )?)
    };

    Ok(ParsedAbortAnswerParts {
        answer: SwmAbortSessionAnswer {
            session_id,
            result: SwmAbortSessionResult::from_result_code(result_code),
            origin_host: builder_helpers::require_field(
                origin_host,
                "SWm ASA requires Origin-Host",
                "7.2.2.3.2",
            )?,
            origin_realm: builder_helpers::require_field(
                origin_realm,
                "SWm ASA requires Origin-Realm",
                "7.2.2.3.2",
            )?,
            user_name,
            origin_state_id,
            error_message,
            error_reporting_host,
            drmp,
            additional_avps,
        },
        proxy_infos,
    })
}

/// Build one outbound SWm STR from its request-bound envelope.
pub fn build_swm_session_termination_request(
    envelope: &SwmSessionTerminationRequestEnvelope,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    validate_request_for_encode(&envelope.request, ctx)?;
    let expected_answer_peer = envelope.expected_answer_peer.as_ref().ok_or_else(|| {
        encode_error(
            "outbound SWm STR requires an authenticated answer-peer binding",
            "6.2.1",
        )
    })?;
    expected_answer_peer.validate_for_encode()?;
    if !envelope.proxiable {
        return Err(encode_error("SWm STR must set the P bit", "7.2.2.2.1"));
    }
    if envelope.proxy_infos.len() > MAX_PROXY_INFOS {
        return Err(encode_error(
            "SWm STR Proxy-Info count exceeds the typed boundary",
            "7.2.2.2.1",
        ));
    }

    let request = &envelope.request;
    let mut raw_avps = BytesMut::new();
    append_string(
        &mut raw_avps,
        base::AVP_SESSION_ID,
        request.session_id.as_ref(),
        ctx,
    )?;
    if let Some(drmp) = request.drmp {
        append_drmp(&mut raw_avps, drmp, ctx)?;
    }
    append_string(
        &mut raw_avps,
        base::AVP_ORIGIN_HOST,
        request.origin_host.as_ref(),
        ctx,
    )?;
    append_string(
        &mut raw_avps,
        base::AVP_ORIGIN_REALM,
        request.origin_realm.as_ref(),
        ctx,
    )?;
    append_string(
        &mut raw_avps,
        base::AVP_DESTINATION_REALM,
        request.destination_realm.as_ref(),
        ctx,
    )?;
    if let Some(destination_host) = request.destination_host.as_ref() {
        append_string(
            &mut raw_avps,
            base::AVP_DESTINATION_HOST,
            destination_host.as_ref(),
            ctx,
        )?;
    }
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        base::AVP_AUTH_APPLICATION_ID,
        APPLICATION_ID.get(),
        true,
        ctx,
    )?;
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        base::AVP_TERMINATION_CAUSE,
        request.termination_cause.value(),
        true,
        ctx,
    )?;
    append_string(
        &mut raw_avps,
        base::AVP_USER_NAME,
        request.user_name.as_ref(),
        ctx,
    )?;
    for proxy_info in &envelope.proxy_infos {
        proxy_info.append_to(&mut raw_avps, ctx)?;
    }
    for route_record in &request.route_records {
        append_string(
            &mut raw_avps,
            base::AVP_ROUTE_RECORD,
            route_record.as_ref(),
            ctx,
        )?;
    }
    for avp in &request.additional_avps {
        avp.append_to(&mut raw_avps, ctx)?;
    }
    let mut request_flags = builder_helpers::app_request_flags().bits();
    if envelope.potentially_retransmitted {
        request_flags |= CommandFlags::POTENTIALLY_RETRANSMITTED;
    }
    builder_helpers::build_message(
        CommandFlags::from_bits(request_flags),
        COMMAND_SESSION_TERMINATION,
        APPLICATION_ID,
        raw_avps,
        envelope.transaction.hop_by_hop_identifier(),
        envelope.transaction.end_to_end_identifier(),
        ctx,
        "7.2.2.2.1",
    )
}

/// Build one STA bound to the exact STR identifiers, Session-Id, P bit, and
/// ordered Proxy-Info chain.
pub fn build_swm_session_termination_answer(
    request: &SwmSessionTerminationRequestEnvelope,
    answer: &SwmSessionTerminationAnswer,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    validate_answer_for_encode(request, answer, ctx)?;
    let session_id = answer
        .session_id
        .as_ref()
        .ok_or_else(|| encode_error("originated SWm STA requires Session-Id", "7.2.2.2.2"))?;
    let mut raw_avps = BytesMut::new();
    append_string(
        &mut raw_avps,
        base::AVP_SESSION_ID,
        session_id.as_ref(),
        ctx,
    )?;
    if let Some(drmp) = answer.drmp {
        append_drmp(&mut raw_avps, drmp, ctx)?;
    }
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        base::AVP_RESULT_CODE,
        answer.result.result_code(),
        true,
        ctx,
    )?;
    append_string(
        &mut raw_avps,
        base::AVP_ORIGIN_HOST,
        answer.origin_host.as_ref(),
        ctx,
    )?;
    append_string(
        &mut raw_avps,
        base::AVP_ORIGIN_REALM,
        answer.origin_realm.as_ref(),
        ctx,
    )?;
    for avp in &answer.additional_avps {
        avp.append_to(&mut raw_avps, ctx)?;
    }
    for proxy_info in &request.proxy_infos {
        proxy_info.append_to(&mut raw_avps, ctx)?;
    }

    builder_helpers::build_message(
        builder_helpers::app_answer_flags(builder_helpers::result_code_requires_error_bit(
            answer.result.result_code(),
        )),
        COMMAND_SESSION_TERMINATION,
        APPLICATION_ID,
        raw_avps,
        request.transaction.hop_by_hop_identifier(),
        request.transaction.end_to_end_identifier(),
        ctx,
        "7.2.2.2.2",
    )
}

/// Parse one SWm STR, returning the legacy structured decode error surface.
pub fn parse_swm_session_termination_request(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmSessionTerminationRequest, DecodeError> {
    parse_swm_session_termination_request_with_provenance(message, ctx)
        .map_err(DiameterParserError::into_decode_error)
}

/// Parse one SWm STR with sealed missing-AVP provenance for the generic
/// request-bound RFC 6733 error-answer mapper.
pub fn parse_swm_session_termination_request_with_provenance(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmSessionTerminationRequest, DiameterParserError> {
    parse_request_parts(message, ctx).map(|parts| parts.request)
}

/// Parse one inbound SWm STR while retaining identifiers, P, Session-Id, and
/// ordered Proxy-Info required for response construction.
///
/// The returned server-side envelope is deliberately not bound to an expected
/// answer peer. It is suitable for local processing and STA construction. A
/// caller inspecting a previously originated outbound wire request can attach
/// its retained authenticated routing evidence with
/// [`SwmSessionTerminationRequestEnvelope::with_expected_answer_peer`]; doing so
/// does not make an inbound request safe to proxy or relay.
pub fn parse_swm_session_termination_request_envelope(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmSessionTerminationRequestEnvelope, DecodeError> {
    parse_swm_session_termination_request_envelope_with_provenance(message, ctx)
        .map_err(DiameterParserError::into_decode_error)
}

/// Provenance-aware form of [`parse_swm_session_termination_request_envelope`].
pub fn parse_swm_session_termination_request_envelope_with_provenance(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmSessionTerminationRequestEnvelope, DiameterParserError> {
    let parts = parse_request_parts(message, ctx)?;
    Ok(SwmSessionTerminationRequestEnvelope {
        transaction: super::SwmDiameterTransaction::from_message(message),
        proxiable: message.header.flags.is_proxiable(),
        potentially_retransmitted: message.header.flags.is_potentially_retransmitted(),
        expected_answer_peer: None,
        request: parts.request,
        proxy_infos: parts.proxy_infos,
    })
}

/// Parse one SWm STA.
pub fn parse_swm_session_termination_answer(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmSessionTerminationAnswer, DecodeError> {
    parse_answer_parts(message, ctx).map(|parts| parts.answer)
}

/// Parse one SWm STA while retaining its authenticated connection generation
/// and identifiers for exact STR correlation.
pub fn parse_swm_session_termination_answer_envelope_from_connection(
    message: &Message<'_>,
    received_on: SwmDiameterConnectionToken,
    ctx: DecodeContext,
) -> Result<SwmSessionTerminationAnswerEnvelope, DecodeError> {
    let parts = parse_answer_parts(message, ctx)?;
    Ok(SwmSessionTerminationAnswerEnvelope {
        transaction: super::SwmDiameterTransaction::from_message(message),
        proxiable: message.header.flags.is_proxiable(),
        received_on,
        error: message.header.flags.is_error(),
        answer: parts.answer,
        proxy_infos: parts.proxy_infos,
    })
}

struct ParsedRequestParts {
    request: SwmSessionTerminationRequest,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

fn parse_request_parts(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<ParsedRequestParts, DiameterParserError> {
    builder_helpers::ensure_app_header(
        message,
        COMMAND_SESSION_TERMINATION,
        APPLICATION_ID,
        CommandKind::Request,
        "7.2.2.2.1",
    )
    .and_then(|()| validate_request_header(message))
    .map_err(|error| DiameterParserError::decoded(message, error))?;

    let mut session_id = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut destination_realm = None;
    let mut destination_host = None;
    let mut auth_application_id = None;
    let mut termination_cause = None;
    let mut user_name = None;
    let mut drmp = None;
    let mut route_records = Vec::new();
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    let mut proxy_infos = Vec::new();

    builder_helpers::for_each_avp(
        message.raw_avps,
        ctx,
        DIAMETER_HEADER_LEN,
        0,
        |offset, avp| {
            let value_offset =
                builder_helpers::offset_add(offset, avp.header.header_len(), "7.2.2.2.1")?;
            let key = avp.header.key();
            if key == AvpKey::ietf(base::AVP_SESSION_ID) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "8.8")?;
                builder_helpers::set_once(&mut session_id, Sensitive::from(value), offset, "8.8")?;
            } else if key == AvpKey::ietf(AVP_DRMP) {
                validate_drmp(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "9.1")?;
                let value = SwmRoutingMessagePriority::from_value(value).ok_or_else(|| {
                    DecodeError::new(
                        DecodeErrorCode::InvalidEnumValue {
                            field: "DRMP priority",
                            value: u64::from(value),
                        },
                        value_offset,
                    )
                    .with_spec_ref(SpecRef::new("ietf", "RFC7944", "9.1"))
                })?;
                builder_helpers::set_once(&mut drmp, value, offset, "9.1")?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_HOST) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "6.3")?;
                builder_helpers::set_once(&mut origin_host, Redacted::from(value), offset, "6.3")?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_REALM) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "6.4")?;
                builder_helpers::set_once(&mut origin_realm, Redacted::from(value), offset, "6.4")?;
            } else if key == AvpKey::ietf(base::AVP_DESTINATION_REALM) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "6.6")?;
                builder_helpers::set_once(
                    &mut destination_realm,
                    Redacted::from(value),
                    offset,
                    "6.6",
                )?;
            } else if key == AvpKey::ietf(base::AVP_DESTINATION_HOST) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "6.5")?;
                builder_helpers::set_once(
                    &mut destination_host,
                    Redacted::from(value),
                    offset,
                    "6.5",
                )?;
            } else if key == AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID) {
                validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "6.8")?;
                builder_helpers::set_once(&mut auth_application_id, value, offset, "6.8")?;
            } else if key == AvpKey::ietf(base::AVP_TERMINATION_CAUSE) {
                validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.15")?;
                let value = SwmTerminationCause::from_value(value).ok_or_else(|| {
                    DecodeError::new(
                        DecodeErrorCode::InvalidEnumValue {
                            field: "Termination-Cause",
                            value: u64::from(value),
                        },
                        value_offset,
                    )
                    .with_spec_ref(SpecRef::new("ietf", "RFC6733", "8.15"))
                })?;
                builder_helpers::set_once(&mut termination_cause, value, offset, "8.15")?;
            } else if key == AvpKey::ietf(base::AVP_USER_NAME) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "8.14")?;
                builder_helpers::set_once(&mut user_name, Sensitive::from(value), offset, "8.14")?;
            } else if key == AvpKey::ietf(base::AVP_PROXY_INFO) {
                if proxy_infos.len() >= MAX_PROXY_INFOS {
                    return Err(count_error(
                        offset,
                        "SWm STR Proxy-Info count exceeds its bound",
                    ));
                }
                validate_proxy_info(&avp, ctx, offset, value_offset)?;
                proxy_infos.push(SwmAdditionalAvp::from_raw(&avp));
            } else if key == AvpKey::ietf(base::AVP_ROUTE_RECORD) {
                if route_records.len() >= MAX_ROUTE_RECORDS {
                    return Err(count_error(
                        offset,
                        "SWm STR Route-Record count exceeds its bound",
                    ));
                }
                let value = parse_core_string(&avp, ctx, offset, value_offset, "6.7.1")?;
                route_records.push(Redacted::from(value));
            } else if key == AvpKey::ietf(base::AVP_RESULT_CODE)
                || key == AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT)
                || key == AvpKey::ietf(AVP_OC_OLR)
                || key == AvpKey::ietf(AVP_LOAD)
            {
                return Err(forbidden_error(
                    offset,
                    "SWm STR contains an answer-only AVP",
                ));
            } else if let Some(additional) = parse_additional_avp(
                &avp,
                ctx,
                offset,
                value_offset,
                LifecycleRole::TerminationRequest,
            )? {
                if additional_avps.len() >= MAX_ADDITIONAL_AVPS {
                    return Err(count_error(
                        offset,
                        "SWm STR additional AVP count exceeds its bound",
                    ));
                }
                if !additional_key_is_repeatable(key, LifecycleRole::TerminationRequest)
                    && !additional_keys.insert(key)
                {
                    return Err(duplicate_error(
                        offset,
                        "SWm STR additional singleton AVP is duplicated",
                    ));
                }
                additional_avps.push(additional);
            }
            Ok(())
        },
    )
    .map_err(|error| DiameterParserError::decoded(message, error))?;

    let auth_application_id = require_request_field(
        auth_application_id,
        "SWm STR requires Auth-Application-Id",
        AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID),
        message,
    )?;
    if auth_application_id != APPLICATION_ID.get() {
        return Err(DiameterParserError::decoded(
            message,
            decode_error(
                "SWm STR Auth-Application-Id does not match the SWm application id",
                DIAMETER_HEADER_LEN,
                "7.2.2.2.1",
            ),
        ));
    }

    Ok(ParsedRequestParts {
        request: SwmSessionTerminationRequest {
            session_id: require_request_field(
                session_id,
                "SWm STR requires Session-Id",
                AvpKey::ietf(base::AVP_SESSION_ID),
                message,
            )?,
            origin_host: require_request_field(
                origin_host,
                "SWm STR requires Origin-Host",
                AvpKey::ietf(base::AVP_ORIGIN_HOST),
                message,
            )?,
            origin_realm: require_request_field(
                origin_realm,
                "SWm STR requires Origin-Realm",
                AvpKey::ietf(base::AVP_ORIGIN_REALM),
                message,
            )?,
            destination_realm: require_request_field(
                destination_realm,
                "SWm STR requires Destination-Realm",
                AvpKey::ietf(base::AVP_DESTINATION_REALM),
                message,
            )?,
            destination_host,
            termination_cause: require_request_field(
                termination_cause,
                "SWm STR requires Termination-Cause",
                AvpKey::ietf(base::AVP_TERMINATION_CAUSE),
                message,
            )?,
            user_name: require_request_field(
                user_name,
                "SWm STR requires User-Name",
                AvpKey::ietf(base::AVP_USER_NAME),
                message,
            )?,
            drmp,
            route_records,
            additional_avps,
        },
        proxy_infos,
    })
}

struct ParsedAnswerParts {
    answer: SwmSessionTerminationAnswer,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

fn parse_answer_parts(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<ParsedAnswerParts, DecodeError> {
    builder_helpers::ensure_app_header(
        message,
        COMMAND_SESSION_TERMINATION,
        APPLICATION_ID,
        CommandKind::Answer,
        "7.2.2.2.2",
    )?;
    validate_answer_header(message)?;

    let mut session_id = None;
    let mut result_code = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut drmp = None;
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    let mut proxy_infos = Vec::new();

    builder_helpers::for_each_avp(
        message.raw_avps,
        ctx,
        DIAMETER_HEADER_LEN,
        0,
        |offset, avp| {
            let value_offset =
                builder_helpers::offset_add(offset, avp.header.header_len(), "7.2.2.2.2")?;
            let key = avp.header.key();
            if key == AvpKey::ietf(base::AVP_SESSION_ID) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "8.8")?;
                builder_helpers::set_once(&mut session_id, Sensitive::from(value), offset, "8.8")?;
            } else if key == AvpKey::ietf(AVP_DRMP) {
                validate_drmp(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "9.1")?;
                let value = SwmRoutingMessagePriority::from_value(value).ok_or_else(|| {
                    DecodeError::new(
                        DecodeErrorCode::InvalidEnumValue {
                            field: "DRMP priority",
                            value: u64::from(value),
                        },
                        value_offset,
                    )
                    .with_spec_ref(SpecRef::new("ietf", "RFC7944", "9.1"))
                })?;
                builder_helpers::set_once(&mut drmp, value, offset, "9.1")?;
            } else if key == AvpKey::ietf(base::AVP_RESULT_CODE) {
                validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.1")?;
                builder_helpers::set_once(&mut result_code, value, offset, "7.1")?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_HOST) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "6.3")?;
                builder_helpers::set_once(&mut origin_host, Redacted::from(value), offset, "6.3")?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_REALM) {
                let value = parse_core_string(&avp, ctx, offset, value_offset, "6.4")?;
                builder_helpers::set_once(&mut origin_realm, Redacted::from(value), offset, "6.4")?;
            } else if key == AvpKey::ietf(base::AVP_PROXY_INFO) {
                if proxy_infos.len() >= MAX_PROXY_INFOS {
                    return Err(count_error(
                        offset,
                        "SWm STA Proxy-Info count exceeds its bound",
                    ));
                }
                validate_proxy_info(&avp, ctx, offset, value_offset)?;
                proxy_infos.push(SwmAdditionalAvp::from_raw(&avp));
            } else if key == AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT)
                && !message.header.flags.is_error()
            {
                return Err(forbidden_error(
                    offset,
                    "ordinary SWm STA cannot contain Experimental-Result with Result-Code",
                ));
            } else if key == AvpKey::ietf(base::AVP_DESTINATION_REALM)
                || key == AvpKey::ietf(base::AVP_DESTINATION_HOST)
                || key == AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID)
                || key == AvpKey::ietf(base::AVP_TERMINATION_CAUSE)
                || key == AvpKey::ietf(base::AVP_ROUTE_RECORD)
            {
                return Err(forbidden_error(
                    offset,
                    "SWm STA contains a request-only AVP",
                ));
            } else if let Some(additional) = parse_additional_avp(
                &avp,
                ctx,
                offset,
                value_offset,
                LifecycleRole::TerminationAnswer,
            )? {
                if additional_avps.len() >= MAX_ADDITIONAL_AVPS {
                    return Err(count_error(
                        offset,
                        "SWm STA additional AVP count exceeds its bound",
                    ));
                }
                if !additional_key_is_repeatable(key, LifecycleRole::TerminationAnswer)
                    && !additional_keys.insert(key)
                {
                    return Err(duplicate_error(
                        offset,
                        "SWm STA additional singleton AVP is duplicated",
                    ));
                }
                additional_avps.push(additional);
            }
            Ok(())
        },
    )?;

    let result_code =
        builder_helpers::require_field(result_code, "SWm STA requires Result-Code", "7.2.2.2.2")?;
    validate_result_code(result_code, "7.2.2.2.2")?;
    validate_supported_result_context_decode(result_code, DIAMETER_HEADER_LEN)?;
    validate_received_answer_error_bit(result_code, message.header.flags.is_error())?;
    validate_answer_overload_control_decode(&additional_avps, ctx)?;

    let session_id = if message.header.flags.is_error() {
        session_id
    } else {
        Some(builder_helpers::require_field(
            session_id,
            "SWm STA requires Session-Id",
            "7.2.2.2.2",
        )?)
    };

    Ok(ParsedAnswerParts {
        answer: SwmSessionTerminationAnswer {
            session_id,
            result: SwmSessionTerminationResult::from_result_code(result_code),
            origin_host: builder_helpers::require_field(
                origin_host,
                "SWm STA requires Origin-Host",
                "7.2.2.2.2",
            )?,
            origin_realm: builder_helpers::require_field(
                origin_realm,
                "SWm STA requires Origin-Realm",
                "7.2.2.2.2",
            )?,
            drmp,
            additional_avps,
        },
        proxy_infos,
    })
}

fn validate_abort_request_for_encode(
    request: &SwmAbortSessionRequest,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    validate_nonempty(
        request.session_id.as_ref(),
        "SWm ASR Session-Id must not be empty",
    )?;
    validate_identity_for_encode(
        request.origin_host.as_ref(),
        "SWm ASR Origin-Host must be a nonempty ASCII DiameterIdentity",
        "6.3",
    )?;
    validate_identity_for_encode(
        request.origin_realm.as_ref(),
        "SWm ASR Origin-Realm must be a nonempty ASCII DiameterIdentity",
        "6.4",
    )?;
    validate_identity_for_encode(
        request.destination_realm.as_ref(),
        "SWm ASR Destination-Realm must be a nonempty ASCII DiameterIdentity",
        "6.6",
    )?;
    validate_identity_for_encode(
        request.destination_host.as_ref(),
        "SWm ASR Destination-Host must be a nonempty ASCII DiameterIdentity",
        "6.5",
    )?;
    validate_nonempty(
        request.user_name.as_ref(),
        "SWm ASR User-Name must not be empty",
    )?;
    if request.route_records.len() > MAX_ROUTE_RECORDS {
        return Err(encode_error(
            "SWm ASR Route-Record count exceeds the typed boundary",
            "7.2.2.3.1",
        ));
    }
    for route_record in &request.route_records {
        validate_identity_for_encode(
            route_record.as_ref(),
            "SWm ASR Route-Record must be a nonempty ASCII DiameterIdentity",
            "6.7.1",
        )?;
    }
    validate_additional_for_encode(
        &request.additional_avps,
        LifecycleRole::AbortRequest,
        None,
        ctx,
    )
}

fn validate_abort_answer_for_encode(
    request: &SwmAbortSessionRequestEnvelope,
    answer: &SwmAbortSessionAnswer,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let Some(answer_session_id) = answer.session_id.as_ref() else {
        return Err(encode_error(
            "originated SWm ASA requires Session-Id",
            "7.2.2.3.2",
        ));
    };
    if answer_session_id.as_ref() != request.request.session_id.as_ref() {
        return Err(encode_error(
            "SWm ASA Session-Id does not match its request",
            "7.2.2.3.2",
        ));
    }
    if let Some(answer_user_name) = answer.user_name.as_ref() {
        if request.request.user_name.as_ref() != answer_user_name.as_ref() {
            return Err(encode_error(
                "SWm ASA User-Name does not match its request",
                "7.2.2.3.2",
            ));
        }
    }
    validate_nonempty(
        answer_session_id.as_ref(),
        "SWm ASA Session-Id must not be empty",
    )?;
    validate_identity_for_encode(
        answer.origin_host.as_ref(),
        "SWm ASA Origin-Host must be a nonempty ASCII DiameterIdentity",
        "6.3",
    )?;
    validate_identity_for_encode(
        answer.origin_realm.as_ref(),
        "SWm ASA Origin-Realm must be a nonempty ASCII DiameterIdentity",
        "6.4",
    )?;
    if let Some(value) = answer.user_name.as_ref() {
        validate_nonempty(value.as_ref(), "SWm ASA User-Name must not be empty")?;
    }
    if let Some(value) = answer.error_reporting_host.as_ref() {
        validate_identity_for_encode(
            value.as_ref(),
            "SWm ASA Error-Reporting-Host must be a nonempty ASCII DiameterIdentity",
            "7.4",
        )?;
    }
    if answer.result == SwmAbortSessionResult::Success
        && (answer.error_message.is_some() || answer.error_reporting_host.is_some())
    {
        return Err(encode_error(
            "successful SWm ASA must not carry error diagnostics",
            "7.2.2.3.2",
        ));
    }
    validate_result_code(answer.result.result_code(), "7.2.2.3.2").map_err(|_| {
        encode_error(
            "SWm ASA Result-Code is outside the base result ranges",
            "7.1",
        )
    })?;
    validate_abort_supported_result_context_encode(answer.result, &answer.additional_avps)?;
    if request.proxy_infos.len() > MAX_PROXY_INFOS {
        return Err(encode_error(
            "SWm ASA Proxy-Info count exceeds the typed boundary",
            "7.2.2.3.2",
        ));
    }
    validate_additional_for_encode(
        &answer.additional_avps,
        LifecycleRole::AbortAnswer,
        Some(&request.request.additional_avps),
        ctx,
    )
}

fn validate_request_for_encode(
    request: &SwmSessionTerminationRequest,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    validate_nonempty(
        request.session_id.as_ref(),
        "SWm STR Session-Id must not be empty",
    )?;
    validate_identity_for_encode(
        request.origin_host.as_ref(),
        "SWm STR Origin-Host must be a nonempty ASCII DiameterIdentity",
        "6.3",
    )?;
    validate_identity_for_encode(
        request.origin_realm.as_ref(),
        "SWm STR Origin-Realm must be a nonempty ASCII DiameterIdentity",
        "6.4",
    )?;
    validate_identity_for_encode(
        request.destination_realm.as_ref(),
        "SWm STR Destination-Realm must be a nonempty ASCII DiameterIdentity",
        "6.6",
    )?;
    if let Some(value) = request.destination_host.as_ref() {
        validate_identity_for_encode(
            value.as_ref(),
            "SWm STR Destination-Host must be a nonempty ASCII DiameterIdentity",
            "6.5",
        )?;
    }
    validate_nonempty(
        request.user_name.as_ref(),
        "SWm STR User-Name must not be empty",
    )?;
    if request.termination_cause.value() == 0 {
        return Err(encode_error(
            "SWm STR Termination-Cause value zero is reserved",
            "8.15",
        ));
    }
    if request.route_records.len() > MAX_ROUTE_RECORDS {
        return Err(encode_error(
            "SWm STR Route-Record count exceeds the typed boundary",
            "7.2.2.2.1",
        ));
    }
    for route_record in &request.route_records {
        validate_identity_for_encode(
            route_record.as_ref(),
            "SWm STR Route-Record must be a nonempty ASCII DiameterIdentity",
            "6.7.1",
        )?;
    }
    validate_additional_for_encode(
        &request.additional_avps,
        LifecycleRole::TerminationRequest,
        None,
        ctx,
    )
}

fn validate_answer_for_encode(
    request: &SwmSessionTerminationRequestEnvelope,
    answer: &SwmSessionTerminationAnswer,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let session_id = answer
        .session_id
        .as_ref()
        .ok_or_else(|| encode_error("originated SWm STA requires Session-Id", "7.2.2.2.2"))?;
    if session_id.as_ref() != request.request.session_id.as_ref() {
        return Err(encode_error(
            "SWm STA Session-Id does not match its request",
            "7.2.2.2.2",
        ));
    }
    validate_nonempty(session_id.as_ref(), "SWm STA Session-Id must not be empty")?;
    validate_identity_for_encode(
        answer.origin_host.as_ref(),
        "SWm STA Origin-Host must be a nonempty ASCII DiameterIdentity",
        "6.3",
    )?;
    validate_identity_for_encode(
        answer.origin_realm.as_ref(),
        "SWm STA Origin-Realm must be a nonempty ASCII DiameterIdentity",
        "6.4",
    )?;
    validate_result_code(answer.result.result_code(), "7.2.2.2.2").map_err(|_| {
        encode_error(
            "SWm STA Result-Code is outside the base result ranges",
            "7.1",
        )
    })?;
    validate_supported_result_context_encode(answer.result)?;
    if request.proxy_infos.len() > MAX_PROXY_INFOS {
        return Err(encode_error(
            "SWm STA Proxy-Info count exceeds the typed boundary",
            "7.2.2.2.2",
        ));
    }
    validate_additional_for_encode(
        &answer.additional_avps,
        LifecycleRole::TerminationAnswer,
        Some(&request.request.additional_avps),
        ctx,
    )
}

fn validate_additional_for_encode(
    avps: &[SwmAdditionalAvp],
    role: LifecycleRole,
    request_avps: Option<&[SwmAdditionalAvp]>,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    if avps.len() > MAX_ADDITIONAL_AVPS {
        return Err(encode_error(
            "SWm lifecycle additional AVP count exceeds the typed boundary",
            role.section(),
        ));
    }
    let mut seen = HashSet::new();
    for avp in avps {
        let key = avp.header.key();
        if core_key_for_role(key, role) || key == AvpKey::ietf(base::AVP_PROXY_INFO) {
            return Err(encode_error(
                "SWm lifecycle additional AVP duplicates command-owned state",
                role.section(),
            ));
        }
        if wrong_role_key(key, role) {
            return Err(encode_error(
                "SWm lifecycle additional AVP is invalid for this command role",
                role.section(),
            ));
        }
        if !additional_key_is_repeatable(key, role) && !seen.insert(key) {
            return Err(encode_error(
                "SWm lifecycle additional singleton AVP is duplicated",
                role.section(),
            ));
        }
        validate_additional_header_for_encode(avp, role, ctx)?;
    }
    if let Some(request_avps) = request_avps {
        validate_answer_overload_control_encode(request_avps, avps, role, ctx)?;
    }
    Ok(())
}

fn additional_key_is_repeatable(key: AvpKey, role: LifecycleRole) -> bool {
    // A command's trailing `*[ AVP ]` extension point does not make every
    // extension repeatable. Only an explicit command rule may bypass the
    // conservative duplicate guard.
    role.command_definition().allows_multiple(key)
}

fn validate_additional_header_for_encode(
    avp: &SwmAdditionalAvp,
    role: LifecycleRole,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let key = avp.header.key();
    if key == AvpKey::ietf(AVP_LOAD) && avp.header.flags.is_mandatory() {
        return Err(encode_error(
            "originated SWm Load AVP must clear the M bit",
            role.section(),
        ));
    }
    if let Some(definition) = find_definition(key) {
        validate_flags_for_encode(&avp.header, definition.flags(), role.section())?;
        validate_known_value_for_encode(avp, definition, role, ctx)?;
    } else if avp.header.flags.is_mandatory() {
        return Err(encode_error(
            "SWm lifecycle unknown extension AVP must clear the M bit",
            role.section(),
        ));
    }
    let mut proof = BytesMut::new();
    avp.append_to(&mut proof, ctx)
}

fn validate_known_value_for_encode(
    avp: &SwmAdditionalAvp,
    definition: &AvpDefinition,
    role: LifecycleRole,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let decode_ctx = DecodeContext {
        max_message_len: ctx.max_message_len,
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::default()
    };
    let raw = RawAvp {
        header: avp.header.clone(),
        value: &avp.value,
        padding: &[],
    };
    validate_known_value(
        &raw,
        definition,
        decode_ctx,
        0,
        role,
        ValueValidationPurpose::Encode,
    )
    .map_err(|_| {
        encode_error(
            "SWm lifecycle known additional AVP value violates its dictionary type",
            role.section(),
        )
    })
}

fn parse_additional_avp(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    offset: usize,
    value_offset: usize,
    role: LifecycleRole,
) -> Result<Option<SwmAdditionalAvp>, DecodeError> {
    let key = avp.header.key();
    if wrong_role_key(key, role) {
        return Err(forbidden_error(
            offset,
            "SWm lifecycle grouped child or wrong-role AVP appears at top level",
        ));
    }
    if let Some(definition) = find_definition(key) {
        if key == AvpKey::ietf(AVP_LOAD) {
            // TS 29.273 section 7.2.3.1, table 2 note 2 requires a
            // receiver that understands Load to ignore an M-bit mismatch.
            // The remaining trusted V/P rules continue to apply, and the
            // encode path still enforces the table's Must-not-set rule.
            validate_flags_ignoring_m(&avp.header, definition.flags(), offset, role.section())?;
        } else {
            validate_flags(&avp.header, definition.flags(), offset, role.section())?;
        }
        validate_known_value(
            avp,
            definition,
            ctx,
            value_offset,
            role,
            ValueValidationPurpose::Decode,
        )?;
        return retain_additional_avp(avp, ctx, value_offset).map(Some);
    }
    if avp.header.flags.is_mandatory() || ctx.unknown_ie_policy == UnknownIePolicy::Reject {
        return Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, offset)
            .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4.1")));
    }
    if ctx.unknown_ie_policy == UnknownIePolicy::Drop {
        Ok(None)
    } else {
        Ok(Some(SwmAdditionalAvp::from_raw(avp)))
    }
}

fn validate_known_value(
    avp: &RawAvp<'_>,
    definition: &AvpDefinition,
    ctx: DecodeContext,
    value_offset: usize,
    role: LifecycleRole,
    purpose: ValueValidationPurpose,
) -> Result<(), DecodeError> {
    builder_helpers::validate_known_avp_value(
        avp.value,
        definition.data_type(),
        ctx,
        value_offset,
        role.section(),
    )?;
    if avp.header.key() == AvpKey::ietf(base::AVP_REDIRECT_HOST_USAGE) {
        let value = builder_helpers::parse_u32_value(avp.value, value_offset, "6.13")?;
        if value > 6 {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidEnumValue {
                    field: "Redirect-Host-Usage",
                    value: u64::from(value),
                },
                value_offset,
            )
            .with_spec_ref(SpecRef::new("ietf", "RFC6733", "6.13")));
        }
    }
    if definition.data_type() != AvpDataType::Grouped {
        return Ok(());
    }
    match avp.header.key() {
        key if key == AvpKey::ietf(AVP_OC_SUPPORTED_FEATURES) => {
            let features = parse_oc_supported_features(avp, ctx, value_offset, role)?;
            if purpose == ValueValidationPurpose::Encode
                && role.is_request()
                && features.effective_vector() != OC_DEFAULT_ALGORITHM
            {
                return Err(forbidden_rfc_error(
                    value_offset,
                    "originated OC-Supported-Features may advertise only executable algorithms",
                    "RFC7683",
                    "5.1.1",
                ));
            }
            Ok(())
        }
        key if key == AvpKey::ietf(AVP_OC_OLR) => {
            let facts = parse_oc_olr(avp, ctx, value_offset)?;
            if purpose == ValueValidationPurpose::Encode {
                validate_originated_oc_olr_values(facts, value_offset)?;
            }
            Ok(())
        }
        key if key == AvpKey::ietf(AVP_LOAD) => validate_load(avp, ctx, value_offset, purpose),
        key if key == AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT) => {
            if purpose == ValueValidationPurpose::Encode {
                return Err(forbidden_error_at(
                    value_offset,
                    "originated typed SWm lifecycle answer cannot contain Experimental-Result",
                    role.section(),
                ));
            }
            super::parse_experimental_result(avp.value, ctx, value_offset, 1).map(|_| ())
        }
        _ => validate_grouped(avp, ctx, value_offset, role.section()),
    }
}

/// Validate a known extension value using request-side overload semantics.
///
/// This stable procedure-neutral boundary keeps sibling SWm command codecs
/// independent of the lifecycle command's internal role variants.
pub(super) fn validate_known_request_extension_value(
    avp: &RawAvp<'_>,
    definition: &AvpDefinition,
    ctx: DecodeContext,
    value_offset: usize,
    purpose: ValueValidationPurpose,
) -> Result<(), DecodeError> {
    validate_known_value(
        avp,
        definition,
        ctx,
        value_offset,
        LifecycleRole::TerminationRequest,
        purpose,
    )
}

/// Validate a known extension value using answer-side overload semantics.
///
/// This stable procedure-neutral boundary keeps sibling SWm command codecs
/// independent of the lifecycle command's internal role variants.
pub(super) fn validate_known_answer_extension_value(
    avp: &RawAvp<'_>,
    definition: &AvpDefinition,
    ctx: DecodeContext,
    value_offset: usize,
    purpose: ValueValidationPurpose,
) -> Result<(), DecodeError> {
    validate_known_value(
        avp,
        definition,
        ctx,
        value_offset,
        LifecycleRole::TerminationAnswer,
        purpose,
    )
}

pub(super) fn retain_additional_avp(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    value_offset: usize,
) -> Result<SwmAdditionalAvp, DecodeError> {
    if ctx.unknown_ie_policy != UnknownIePolicy::Drop
        || !matches!(
            avp.header.key(),
            key if key == AvpKey::ietf(AVP_OC_SUPPORTED_FEATURES)
                || key == AvpKey::ietf(AVP_OC_OLR)
                || key == AvpKey::ietf(AVP_LOAD)
        )
    {
        return Ok(SwmAdditionalAvp::from_raw(avp));
    }

    let outer_key = avp.header.key();
    let mut retained = BytesMut::new();
    builder_helpers::for_each_avp(avp.value, ctx, value_offset, 1, |offset, child| {
        if !known_grouped_child(outer_key, child.header.key()) {
            return Ok(());
        }
        let relative = offset.checked_sub(value_offset).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, offset)
                .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4.4"))
        })?;
        let child_len = child
            .header
            .header_len()
            .checked_add(child.value.len())
            .and_then(|length| length.checked_add(child.padding.len()))
            .ok_or_else(|| {
                DecodeError::new(DecodeErrorCode::LengthOverflow, offset)
                    .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4.4"))
            })?;
        let end = relative.checked_add(child_len).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, offset)
                .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4.4"))
        })?;
        let bytes = avp.value.get(relative..end).ok_or_else(|| {
            DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "grouped child extends beyond its validated parent value",
                },
                offset,
            )
            .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4.4"))
        })?;
        retained.extend_from_slice(bytes);
        Ok(())
    })?;

    let mut additional = SwmAdditionalAvp::from_raw(avp);
    additional.value = retained.freeze();
    Ok(additional)
}

fn known_grouped_child(outer: AvpKey, child: AvpKey) -> bool {
    if outer == AvpKey::ietf(AVP_OC_SUPPORTED_FEATURES) {
        child == AvpKey::ietf(AVP_OC_FEATURE_VECTOR)
    } else if outer == AvpKey::ietf(AVP_OC_OLR) {
        child.vendor_id().is_none() && is_oc_olr_child_code(child.code())
    } else if outer == AvpKey::ietf(AVP_LOAD) {
        child.vendor_id().is_none() && is_load_child_code(child.code())
    } else {
        false
    }
}

fn validate_grouped(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    value_offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    avp.validate_grouped_value(ctx).map_err(|error| {
        let offset = value_offset.saturating_add(error.offset());
        let mut shifted = DecodeError::new(error.code().clone(), offset);
        if let Some(spec_ref) = error.spec_ref() {
            shifted = shifted.with_spec_ref(spec_ref.clone());
        } else {
            shifted = shifted.with_spec_ref(SpecRef::new("ietf", "RFC6733", section));
        }
        shifted
    })
}

fn parse_oc_supported_features(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    value_offset: usize,
    role: LifecycleRole,
) -> Result<OcSupportedFeatures, DecodeError> {
    let mut feature_vector = None;
    builder_helpers::for_each_avp(avp.value, ctx, value_offset, 1, |offset, child| {
        let child_value_offset =
            builder_helpers::offset_add(offset, child.header.header_len(), "RFC7683-7.1")?;
        if child.header.key() == AvpKey::ietf(AVP_OC_FEATURE_VECTOR) {
            validate_known_child(&child, offset, child_value_offset, ctx, "RFC7683-7.2")?;
            let value =
                builder_helpers::parse_u64_value(child.value, child_value_offset, "RFC7683-7.2")?;
            builder_helpers::set_once(&mut feature_vector, value, offset, "RFC7683-7.1")?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &child, offset, "RFC7683-7.1")?;
        }
        Ok(())
    })?;

    if let Some(value) = feature_vector {
        if value == 0 {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidEnumValue {
                    field: "OC-Feature-Vector",
                    value,
                },
                value_offset,
            )
            .with_spec_ref(SpecRef::new("ietf", "RFC7683", "7.2")));
        }
        match role {
            role if role.is_request() && value & OC_DEFAULT_ALGORITHM == 0 => {
                return Err(forbidden_rfc_error(
                    value_offset,
                    "request OC-Feature-Vector must advertise the loss algorithm",
                    "RFC7683",
                    "5.1.1",
                ));
            }
            role if role.is_answer() && value != OC_DEFAULT_ALGORITHM => {
                return Err(forbidden_rfc_error(
                    value_offset,
                    "typed SWm lifecycle answers support only the RFC 7683 loss algorithm",
                    "RFC7683",
                    "5.1.2",
                ));
            }
            _ => {}
        }
    }

    Ok(OcSupportedFeatures { feature_vector })
}

fn parse_oc_olr(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    value_offset: usize,
) -> Result<OcOlrFacts, DecodeError> {
    let mut sequence_number = None;
    let mut validity_duration = None;
    let mut report_type = None;
    let mut reduction_percentage = None;
    builder_helpers::for_each_avp(avp.value, ctx, value_offset, 1, |offset, child| {
        let child_value_offset =
            builder_helpers::offset_add(offset, child.header.header_len(), "RFC7683-7.3")?;
        let key = child.header.key();
        if key == AvpKey::ietf(AVP_OC_SEQUENCE_NUMBER) {
            validate_known_child(&child, offset, child_value_offset, ctx, "RFC7683-7.4")?;
            let value =
                builder_helpers::parse_u64_value(child.value, child_value_offset, "RFC7683-7.4")?;
            builder_helpers::set_once(&mut sequence_number, value, offset, "RFC7683-7.3")?;
        } else if key == AvpKey::ietf(AVP_OC_VALIDITY_DURATION) {
            validate_known_child(&child, offset, child_value_offset, ctx, "RFC7683-7.5")?;
            let value =
                builder_helpers::parse_u32_value(child.value, child_value_offset, "RFC7683-7.5")?;
            builder_helpers::set_once(&mut validity_duration, value, offset, "RFC7683-7.3")?;
        } else if key == AvpKey::ietf(AVP_OC_REPORT_TYPE) {
            validate_known_child(&child, offset, child_value_offset, ctx, "RFC7683-7.6")?;
            let value =
                builder_helpers::parse_u32_value(child.value, child_value_offset, "RFC7683-7.6")?;
            if value > 1 {
                return Err(DecodeError::new(
                    DecodeErrorCode::InvalidEnumValue {
                        field: "OC-Report-Type",
                        value: u64::from(value),
                    },
                    child_value_offset,
                )
                .with_spec_ref(SpecRef::new("ietf", "RFC7683", "7.6")));
            }
            builder_helpers::set_once(&mut report_type, value, offset, "RFC7683-7.3")?;
        } else if key == AvpKey::ietf(AVP_OC_REDUCTION_PERCENTAGE) {
            validate_known_child(&child, offset, child_value_offset, ctx, "RFC7683-7.7")?;
            let value =
                builder_helpers::parse_u32_value(child.value, child_value_offset, "RFC7683-7.7")?;
            builder_helpers::set_once(&mut reduction_percentage, value, offset, "RFC7683-7.3")?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &child, offset, "RFC7683-7.3")?;
        }
        Ok(())
    })?;

    require_grouped_field(
        sequence_number,
        value_offset,
        "OC-OLR requires OC-Sequence-Number",
        "RFC7683",
        "7.3",
    )?;
    require_grouped_field(
        report_type,
        value_offset,
        "OC-OLR requires OC-Report-Type",
        "RFC7683",
        "7.3",
    )?;
    Ok(OcOlrFacts {
        validity_duration,
        reduction_percentage,
    })
}

fn validate_originated_oc_olr_values(facts: OcOlrFacts, offset: usize) -> Result<(), DecodeError> {
    if facts.validity_duration.is_some_and(|value| value > 86_400) {
        return Err(forbidden_rfc_error(
            offset,
            "originated OC-Validity-Duration exceeds the RFC 7683 maximum",
            "RFC7683",
            "7.5",
        ));
    }
    if facts.reduction_percentage.is_some_and(|value| value > 100) {
        return Err(forbidden_rfc_error(
            offset,
            "originated OC-Reduction-Percentage exceeds 100",
            "RFC7683",
            "7.7",
        ));
    }
    Ok(())
}

fn validate_load(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    value_offset: usize,
    purpose: ValueValidationPurpose,
) -> Result<(), DecodeError> {
    let mut load_type = None;
    let mut load_value = None;
    let mut source_id = None;
    builder_helpers::for_each_avp(avp.value, ctx, value_offset, 1, |offset, child| {
        let child_value_offset =
            builder_helpers::offset_add(offset, child.header.header_len(), "RFC8583-7.1")?;
        let key = child.header.key();
        if key == AvpKey::ietf(AVP_LOAD_TYPE) {
            validate_known_child(&child, offset, child_value_offset, ctx, "RFC8583-7.2")?;
            let value =
                builder_helpers::parse_u32_value(child.value, child_value_offset, "RFC8583-7.2")?;
            if value > 1 {
                return Err(DecodeError::new(
                    DecodeErrorCode::InvalidEnumValue {
                        field: "Load-Type",
                        value: u64::from(value),
                    },
                    child_value_offset,
                )
                .with_spec_ref(SpecRef::new("ietf", "RFC8583", "7.2")));
            }
            builder_helpers::set_once(&mut load_type, value, offset, "RFC8583-7.1")?;
        } else if key == AvpKey::ietf(AVP_LOAD_VALUE) {
            validate_known_child(&child, offset, child_value_offset, ctx, "RFC8583-7.3")?;
            let value =
                builder_helpers::parse_u64_value(child.value, child_value_offset, "RFC8583-7.3")?;
            if value > LOAD_VALUE_MAX {
                return Err(DecodeError::new(
                    DecodeErrorCode::InvalidEnumValue {
                        field: "Load-Value",
                        value,
                    },
                    child_value_offset,
                )
                .with_spec_ref(SpecRef::new("ietf", "RFC8583", "7.3")));
            }
            builder_helpers::set_once(&mut load_value, value, offset, "RFC8583-7.1")?;
        } else if key == AvpKey::ietf(AVP_SOURCE_ID) {
            validate_known_child(&child, offset, child_value_offset, ctx, "RFC8581-7.3")?;
            builder_helpers::set_once(&mut source_id, (), offset, "RFC8583-7.1")?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &child, offset, "RFC8583-7.1")?;
        }
        Ok(())
    })?;

    if purpose == ValueValidationPurpose::Encode {
        require_grouped_field(
            load_type,
            value_offset,
            "originated Load requires Load-Type",
            "RFC8583",
            "6.1",
        )?;
        require_grouped_field(
            load_value,
            value_offset,
            "originated Load requires Load-Value",
            "RFC8583",
            "6.1",
        )?;
        require_grouped_field(
            source_id,
            value_offset,
            "originated Load requires SourceID",
            "RFC8583",
            "6.1",
        )?;
    }
    Ok(())
}

fn validate_known_child(
    child: &RawAvp<'_>,
    offset: usize,
    value_offset: usize,
    ctx: DecodeContext,
    section: &'static str,
) -> Result<(), DecodeError> {
    let definition = find_definition(child.header.key()).ok_or_else(|| {
        forbidden_rfc_error(
            offset,
            "known grouped child is missing its dictionary definition",
            "RFC6733",
            "4.4",
        )
    })?;
    validate_flags(&child.header, definition.flags(), offset, section)?;
    builder_helpers::validate_known_avp_value(
        child.value,
        definition.data_type(),
        ctx,
        value_offset,
        section,
    )
}

fn require_grouped_field<T>(
    field: Option<T>,
    offset: usize,
    reason: &'static str,
    document: &'static str,
    section: &'static str,
) -> Result<T, DecodeError> {
    field.ok_or_else(|| forbidden_rfc_error(offset, reason, document, section))
}

const fn is_oc_olr_child_code(code: AvpCode) -> bool {
    matches!(
        code,
        AVP_OC_SEQUENCE_NUMBER
            | AVP_OC_VALIDITY_DURATION
            | AVP_OC_REPORT_TYPE
            | AVP_OC_REDUCTION_PERCENTAGE
    )
}

const fn is_load_child_code(code: AvpCode) -> bool {
    matches!(code, AVP_LOAD_TYPE | AVP_LOAD_VALUE | AVP_SOURCE_ID)
}

fn find_oc_supported_features(
    avps: &[SwmAdditionalAvp],
    ctx: DecodeContext,
    role: LifecycleRole,
) -> Result<Option<OcSupportedFeatures>, DecodeError> {
    let mut retained = None;
    for avp in avps {
        if avp.header.key() != AvpKey::ietf(AVP_OC_SUPPORTED_FEATURES) {
            continue;
        }
        let raw = RawAvp {
            header: avp.header.clone(),
            value: &avp.value,
            padding: &[],
        };
        let value = parse_oc_supported_features(&raw, ctx, 0, role)?;
        builder_helpers::set_once(&mut retained, value, 0, "RFC7683-5.1")?;
    }
    Ok(retained)
}

fn find_oc_olr(
    avps: &[SwmAdditionalAvp],
    ctx: DecodeContext,
) -> Result<Option<OcOlrFacts>, DecodeError> {
    let mut retained = None;
    for avp in avps {
        if avp.header.key() != AvpKey::ietf(AVP_OC_OLR) {
            continue;
        }
        let raw = RawAvp {
            header: avp.header.clone(),
            value: &avp.value,
            padding: &[],
        };
        let value = parse_oc_olr(&raw, ctx, 0)?;
        builder_helpers::set_once(&mut retained, value, 0, "RFC7683-7.3")?;
    }
    Ok(retained)
}

pub(super) fn validate_answer_overload_control_decode(
    answer_avps: &[SwmAdditionalAvp],
    ctx: DecodeContext,
) -> Result<(), DecodeError> {
    let answer = find_oc_supported_features(answer_avps, ctx, LifecycleRole::TerminationAnswer)?;
    let olr = find_oc_olr(answer_avps, ctx)?;
    validate_answer_olr_presence(answer, olr)
}

fn validate_abort_answer_overload_control_decode(
    answer_avps: &[SwmAdditionalAvp],
    ctx: DecodeContext,
) -> Result<(), DecodeError> {
    let answer = find_oc_supported_features(answer_avps, ctx, LifecycleRole::AbortAnswer)?;
    let olr = find_oc_olr(answer_avps, ctx)?;
    validate_answer_olr_presence(answer, olr)
}

fn validate_answer_overload_control_encode(
    request_avps: &[SwmAdditionalAvp],
    answer_avps: &[SwmAdditionalAvp],
    answer_role: LifecycleRole,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let decode_ctx = DecodeContext {
        max_message_len: ctx.max_message_len,
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::default()
    };
    let request_role = answer_role.request_role().ok_or_else(|| {
        encode_error(
            "SWm lifecycle overload correlation requires an answer role",
            answer_role.section(),
        )
    })?;
    validate_offered_overload_control_for_roles(
        request_avps,
        answer_avps,
        decode_ctx,
        request_role,
        answer_role,
    )
    .map_err(|_| {
        encode_error(
            "SWm lifecycle answer overload-control selection is invalid for its request",
            "RFC7683-5.1.2",
        )
    })
}

pub(super) fn validate_offered_overload_control(
    request_avps: &[SwmAdditionalAvp],
    answer_avps: &[SwmAdditionalAvp],
    ctx: DecodeContext,
) -> Result<(), DecodeError> {
    validate_offered_overload_control_for_roles(
        request_avps,
        answer_avps,
        ctx,
        LifecycleRole::TerminationRequest,
        LifecycleRole::TerminationAnswer,
    )
}

fn validate_offered_overload_control_for_roles(
    request_avps: &[SwmAdditionalAvp],
    answer_avps: &[SwmAdditionalAvp],
    ctx: DecodeContext,
    request_role: LifecycleRole,
    answer_role: LifecycleRole,
) -> Result<(), DecodeError> {
    let request = find_oc_supported_features(request_avps, ctx, request_role)?;
    let answer = find_oc_supported_features(answer_avps, ctx, answer_role)?;
    let olr = find_oc_olr(answer_avps, ctx)?;
    validate_answer_olr_presence(answer, olr)?;

    match (request, answer) {
        (None, None) => Ok(()),
        (None, _) => Err(forbidden_rfc_error(
            0,
            "answer overload control requires a request capability offer",
            "RFC7683",
            "5.1.2",
        )),
        // RFC 7683 sections 4.2 and 5.1.1 permit the selected server to be a
        // non-reporting node. Absence after an offer is therefore meaningful,
        // not a failed echo.
        (Some(_), None) => Ok(()),
        (Some(request), Some(answer)) => {
            if answer.effective_vector() & !request.effective_vector() != 0 {
                return Err(forbidden_rfc_error(
                    0,
                    "answer selected an overload feature not offered by the request",
                    "RFC7683",
                    "5.1.2",
                ));
            }
            validate_originated_loss_olr(Some(answer), olr)
        }
    }
}

fn validate_answer_olr_presence(
    answer: Option<OcSupportedFeatures>,
    olr: Option<OcOlrFacts>,
) -> Result<(), DecodeError> {
    if olr.is_none() {
        return Ok(());
    }
    answer.map(|_| ()).ok_or_else(|| {
        forbidden_rfc_error(
            0,
            "OC-OLR requires OC-Supported-Features in the same answer",
            "RFC7683",
            "5.1.2",
        )
    })
}

fn validate_originated_loss_olr(
    answer: Option<OcSupportedFeatures>,
    olr: Option<OcOlrFacts>,
) -> Result<(), DecodeError> {
    let (Some(answer), Some(olr)) = (answer, olr) else {
        return Ok(());
    };
    if answer.selects_default_algorithm() && olr.reduction_percentage.is_none() {
        return Err(forbidden_rfc_error(
            0,
            "loss-algorithm OC-OLR requires OC-Reduction-Percentage",
            "RFC7683",
            "6.2",
        ));
    }
    Ok(())
}

fn validate_correlated_overload_control(
    request_avps: &[SwmAdditionalAvp],
    answer_avps: &[SwmAdditionalAvp],
) -> Result<(), SwmSessionTerminationCorrelationError> {
    let ctx = DecodeContext::default();
    let request = find_oc_supported_features(request_avps, ctx, LifecycleRole::TerminationRequest)
        .map_err(|_| SwmSessionTerminationCorrelationError::MalformedOverloadControl)?;
    let answer = find_oc_supported_features(answer_avps, ctx, LifecycleRole::TerminationAnswer)
        .map_err(|_| SwmSessionTerminationCorrelationError::MalformedOverloadControl)?;
    let olr = find_oc_olr(answer_avps, ctx)
        .map_err(|_| SwmSessionTerminationCorrelationError::MalformedOverloadControl)?;

    validate_answer_olr_presence(answer, olr)
        .map_err(|_| SwmSessionTerminationCorrelationError::MalformedOverloadControl)?;

    match (request, answer) {
        (None, None) => Ok(()),
        (None, _) => Err(SwmSessionTerminationCorrelationError::UnsolicitedOverloadControl),
        (Some(_), None) => Ok(()),
        (Some(request), Some(answer)) => {
            if answer.effective_vector() & !request.effective_vector() != 0 {
                return Err(SwmSessionTerminationCorrelationError::IncompatibleOverloadControl);
            }
            Ok(())
        }
    }
}

fn validate_abort_correlated_overload_control(
    request_avps: &[SwmAdditionalAvp],
    answer_avps: &[SwmAdditionalAvp],
) -> Result<(), SwmAbortSessionCorrelationError> {
    let ctx = DecodeContext::default();
    let request = find_oc_supported_features(request_avps, ctx, LifecycleRole::AbortRequest)
        .map_err(|_| SwmAbortSessionCorrelationError::MalformedOverloadControl)?;
    let answer = find_oc_supported_features(answer_avps, ctx, LifecycleRole::AbortAnswer)
        .map_err(|_| SwmAbortSessionCorrelationError::MalformedOverloadControl)?;
    let olr = find_oc_olr(answer_avps, ctx)
        .map_err(|_| SwmAbortSessionCorrelationError::MalformedOverloadControl)?;
    validate_answer_olr_presence(answer, olr)
        .map_err(|_| SwmAbortSessionCorrelationError::MalformedOverloadControl)?;

    match (request, answer) {
        (None, None) => Ok(()),
        (None, _) => Err(SwmAbortSessionCorrelationError::UnsolicitedOverloadControl),
        (Some(_), None) => Ok(()),
        (Some(request), Some(answer)) => {
            if answer.effective_vector() & !request.effective_vector() != 0 {
                return Err(SwmAbortSessionCorrelationError::IncompatibleOverloadControl);
            }
            Ok(())
        }
    }
}

pub(super) fn validate_proxy_info(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    offset: usize,
    value_offset: usize,
) -> Result<(), DecodeError> {
    validate_base_definition(avp, offset)?;
    let mut proxy_host = None;
    let mut proxy_state = None;
    builder_helpers::for_each_avp(avp.value, ctx, value_offset, 1, |child_offset, child| {
        let child_value_offset =
            builder_helpers::offset_add(child_offset, child.header.header_len(), "6.7.2")?;
        if child.header.key() == AvpKey::ietf(base::AVP_PROXY_HOST) {
            let _ = parse_core_string(&child, ctx, child_offset, child_value_offset, "6.7.3")?;
            builder_helpers::set_once(&mut proxy_host, (), child_offset, "6.7.2")?;
        } else if child.header.key() == AvpKey::ietf(base::AVP_PROXY_STATE) {
            validate_base_definition(&child, child_offset)?;
            builder_helpers::set_once(&mut proxy_state, (), child_offset, "6.7.2")?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &child, child_offset, "6.7.2")?;
        }
        Ok(())
    })?;
    if proxy_host.is_none() || proxy_state.is_none() {
        return Err(decode_error(
            "SWm lifecycle Proxy-Info requires Proxy-Host and Proxy-State",
            offset,
            "6.7.2",
        ));
    }
    Ok(())
}

fn validate_abort_request_header(message: &Message<'_>) -> Result<(), DecodeError> {
    let flags = message.header.flags;
    if !flags.is_proxiable() || flags.is_error() {
        return Err(decode_error(
            "SWm ASR must set P and clear E",
            4,
            "7.2.2.3.1",
        ));
    }
    Ok(())
}

fn validate_abort_answer_header(message: &Message<'_>) -> Result<(), DecodeError> {
    let flags = message.header.flags;
    if !flags.is_proxiable() || flags.is_potentially_retransmitted() {
        return Err(decode_error(
            "SWm ASA must set P and clear T",
            4,
            "7.2.2.3.2",
        ));
    }
    Ok(())
}

fn validate_request_header(message: &Message<'_>) -> Result<(), DecodeError> {
    let flags = message.header.flags;
    if !flags.is_proxiable() || flags.is_error() {
        return Err(decode_error(
            "SWm STR must set P and clear E",
            4,
            "7.2.2.2.1",
        ));
    }
    Ok(())
}

fn validate_answer_header(message: &Message<'_>) -> Result<(), DecodeError> {
    let flags = message.header.flags;
    if !flags.is_proxiable() || flags.is_potentially_retransmitted() {
        return Err(decode_error(
            "SWm STA must set P and clear T",
            4,
            "7.2.2.2.2",
        ));
    }
    Ok(())
}

pub(super) fn validate_base_definition(avp: &RawAvp<'_>, offset: usize) -> Result<(), DecodeError> {
    match base::dictionary().find_avp(avp.header.key()) {
        Some(definition) => validate_flags(&avp.header, definition.flags(), offset, "4.5"),
        None => Err(decode_error(
            "SWm lifecycle base AVP definition is missing",
            offset,
            "4.5",
        )),
    }
}

fn parse_core_string(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    offset: usize,
    value_offset: usize,
    section: &'static str,
) -> Result<String, DecodeError> {
    validate_base_definition(avp, offset)?;
    let definition = base::dictionary()
        .find_avp(avp.header.key())
        .ok_or_else(|| decode_error("SWm core AVP definition is missing", offset, section))?;
    builder_helpers::validate_known_avp_value(
        avp.value,
        definition.data_type(),
        ctx,
        value_offset,
        section,
    )?;
    builder_helpers::parse_string_value(avp.value, value_offset, section)
}

fn parse_core_utf8(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    offset: usize,
    value_offset: usize,
    section: &'static str,
) -> Result<String, DecodeError> {
    validate_base_definition(avp, offset)?;
    let definition = base::dictionary()
        .find_avp(avp.header.key())
        .ok_or_else(|| decode_error("SWm core AVP definition is missing", offset, section))?;
    builder_helpers::validate_known_avp_value(
        avp.value,
        definition.data_type(),
        ctx,
        value_offset,
        section,
    )?;
    builder_helpers::parse_utf8_value(avp.value, value_offset, section)
}

fn validate_drmp(avp: &RawAvp<'_>, offset: usize) -> Result<(), DecodeError> {
    // RFC 7944 requires originators to clear M. TS 29.273 7.2.3.1 note 2
    // requires an SWm receiver that understands DRMP to ignore a mismatched M.
    validate_flags_ignoring_m(
        &avp.header,
        AvpFlagRules::base_optional(),
        offset,
        "RFC7944-9.1",
    )
}

pub(super) fn validate_flags(
    header: &AvpHeader,
    rules: AvpFlagRules,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    if !flag_matches(header.flags.is_vendor_specific(), rules.vendor())
        || !flag_matches(header.flags.is_mandatory(), rules.mandatory())
        || !flag_matches(header.flags.is_protected(), rules.protected())
    {
        return Err(decode_error(
            "SWm lifecycle AVP flags violate the trusted definition",
            offset.saturating_add(4),
            section,
        ));
    }
    Ok(())
}

fn validate_flags_ignoring_m(
    header: &AvpHeader,
    rules: AvpFlagRules,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    if !flag_matches(header.flags.is_vendor_specific(), rules.vendor())
        || !flag_matches(header.flags.is_protected(), rules.protected())
    {
        return Err(decode_error(
            "SWm lifecycle AVP flags violate the trusted definition",
            offset.saturating_add(4),
            section,
        ));
    }
    Ok(())
}

pub(super) fn validate_flags_for_encode(
    header: &AvpHeader,
    rules: AvpFlagRules,
    section: &'static str,
) -> Result<(), EncodeError> {
    if !flag_matches(header.flags.is_vendor_specific(), rules.vendor())
        || !flag_matches(header.flags.is_mandatory(), rules.mandatory())
        || !flag_matches(header.flags.is_protected(), rules.protected())
    {
        return Err(encode_error(
            "SWm lifecycle AVP flags violate the trusted definition",
            section,
        ));
    }
    Ok(())
}

const fn flag_matches(actual: bool, requirement: FlagRequirement) -> bool {
    match requirement {
        FlagRequirement::MustBeSet => actual,
        FlagRequirement::MustBeUnset => !actual,
        FlagRequirement::MayBeSet => true,
    }
}

fn require_request_field<T>(
    field: Option<T>,
    reason: &'static str,
    key: AvpKey,
    message: &Message<'_>,
) -> Result<T, DiameterParserError> {
    field.ok_or_else(|| {
        let error = decode_error(reason, DIAMETER_HEADER_LEN, "7.2.2.2.1");
        match find_definition(key) {
            Some(definition) => DiameterParserError::missing_for_definition(
                message,
                error,
                definition,
                APPLICATION_ID,
                COMMAND_SESSION_TERMINATION,
            ),
            None => DiameterParserError::decoded(message, error),
        }
    })
}

fn require_abort_request_field<T>(
    field: Option<T>,
    reason: &'static str,
    key: AvpKey,
    message: &Message<'_>,
) -> Result<T, DiameterParserError> {
    field.ok_or_else(|| {
        let error = decode_error(reason, DIAMETER_HEADER_LEN, "7.2.2.3.1");
        match find_definition(key) {
            Some(definition) => DiameterParserError::missing_for_definition(
                message,
                error,
                definition,
                APPLICATION_ID,
                COMMAND_ABORT_SESSION,
            ),
            None => DiameterParserError::decoded(message, error),
        }
    })
}

fn find_definition(key: AvpKey) -> Option<&'static AvpDefinition> {
    base::dictionary()
        .find_avp(key)
        .or_else(|| super::dictionary().find_avp(key))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleRole {
    TerminationRequest,
    TerminationAnswer,
    AbortRequest,
    AbortAnswer,
}

impl LifecycleRole {
    fn command_definition(self) -> &'static CommandDefinition {
        match self {
            Self::TerminationRequest => &COMMAND_SESSION_TERMINATION_REQUEST,
            Self::TerminationAnswer => &COMMAND_SESSION_TERMINATION_ANSWER,
            Self::AbortRequest => &COMMAND_ABORT_SESSION_REQUEST,
            Self::AbortAnswer => &COMMAND_ABORT_SESSION_ANSWER,
        }
    }

    const fn section(self) -> &'static str {
        match self {
            Self::TerminationRequest => "7.2.2.2.1",
            Self::TerminationAnswer => "7.2.2.2.2",
            Self::AbortRequest => "7.2.2.3.1",
            Self::AbortAnswer => "7.2.2.3.2",
        }
    }

    const fn is_request(self) -> bool {
        matches!(self, Self::TerminationRequest | Self::AbortRequest)
    }

    const fn is_answer(self) -> bool {
        !self.is_request()
    }

    const fn request_role(self) -> Option<Self> {
        match self {
            Self::TerminationAnswer => Some(Self::TerminationRequest),
            Self::AbortAnswer => Some(Self::AbortRequest),
            Self::TerminationRequest | Self::AbortRequest => None,
        }
    }
}

fn core_key_for_role(key: AvpKey, role: LifecycleRole) -> bool {
    if key.vendor_id().is_some() {
        return false;
    }
    let code = key.code();
    match role {
        LifecycleRole::TerminationRequest => matches!(
            code,
            base::AVP_SESSION_ID
                | base::AVP_ORIGIN_HOST
                | base::AVP_ORIGIN_REALM
                | base::AVP_DESTINATION_REALM
                | base::AVP_DESTINATION_HOST
                | base::AVP_AUTH_APPLICATION_ID
                | base::AVP_TERMINATION_CAUSE
                | base::AVP_USER_NAME
                | base::AVP_ROUTE_RECORD
                | AVP_DRMP
        ),
        LifecycleRole::TerminationAnswer => matches!(
            code,
            base::AVP_SESSION_ID
                | base::AVP_RESULT_CODE
                | base::AVP_ORIGIN_HOST
                | base::AVP_ORIGIN_REALM
                | AVP_DRMP
        ),
        LifecycleRole::AbortRequest => matches!(
            code,
            base::AVP_SESSION_ID
                | base::AVP_ORIGIN_HOST
                | base::AVP_ORIGIN_REALM
                | base::AVP_DESTINATION_REALM
                | base::AVP_DESTINATION_HOST
                | base::AVP_AUTH_APPLICATION_ID
                | base::AVP_USER_NAME
                | base::AVP_AUTH_SESSION_STATE
                | base::AVP_ORIGIN_STATE_ID
                | base::AVP_ROUTE_RECORD
                | AVP_DRMP
        ),
        LifecycleRole::AbortAnswer => matches!(
            code,
            base::AVP_SESSION_ID
                | base::AVP_RESULT_CODE
                | base::AVP_ORIGIN_HOST
                | base::AVP_ORIGIN_REALM
                | base::AVP_USER_NAME
                | base::AVP_ORIGIN_STATE_ID
                | base::AVP_ERROR_MESSAGE
                | base::AVP_ERROR_REPORTING_HOST
                | AVP_DRMP
        ),
    }
}

fn wrong_role_key(key: AvpKey, role: LifecycleRole) -> bool {
    if key.vendor_id().is_some() {
        return false;
    }
    if key.code() == AVP_OC_FEATURE_VECTOR
        || is_oc_olr_child_code(key.code())
        || is_load_child_code(key.code())
    {
        return true;
    }
    role.command_definition()
        .find_avp_rule(key)
        .is_some_and(|rule| rule.cardinality().is_forbidden())
}

fn append_string(
    dst: &mut BytesMut,
    code: AvpCode,
    value: &str,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    builder_helpers::append_utf8_avp(dst, code, value, true, ctx)
}

fn append_drmp(
    dst: &mut BytesMut,
    priority: SwmRoutingMessagePriority,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    builder_helpers::append_u32_avp(dst, AVP_DRMP, u32::from(priority.value()), false, ctx)
}

const fn abort_core_code(code: AvpCode) -> bool {
    matches!(
        code,
        base::AVP_SESSION_ID
            | base::AVP_ORIGIN_HOST
            | base::AVP_ORIGIN_REALM
            | base::AVP_DESTINATION_REALM
            | base::AVP_DESTINATION_HOST
            | base::AVP_AUTH_APPLICATION_ID
            | base::AVP_USER_NAME
            | base::AVP_CLASS
            | base::AVP_AUTH_SESSION_STATE
            | base::AVP_ORIGIN_STATE_ID
            | base::AVP_RESULT_CODE
            | base::AVP_ERROR_MESSAGE
            | base::AVP_ERROR_REPORTING_HOST
            | base::AVP_FAILED_AVP
            | base::AVP_REDIRECT_HOST
            | base::AVP_REDIRECT_HOST_USAGE
            | base::AVP_REDIRECT_MAX_CACHE_TIME
            | base::AVP_PROXY_INFO
            | base::AVP_ROUTE_RECORD
            | super::AVP_STATE
            | super::AVP_REPLY_MESSAGE
            | AVP_DRMP
            | AVP_OC_SUPPORTED_FEATURES
            | AVP_OC_OLR
            | AVP_LOAD
    )
}

fn validate_identity_for_encode(
    value: &str,
    reason: &'static str,
    section: &'static str,
) -> Result<(), EncodeError> {
    if value.is_empty() || !value.is_ascii() {
        Err(encode_error(reason, section))
    } else {
        Ok(())
    }
}

fn validate_nonempty(value: &str, reason: &'static str) -> Result<(), EncodeError> {
    if value.is_empty() {
        Err(encode_error(reason, "7.2.2.2"))
    } else {
        Ok(())
    }
}

fn validate_result_code(result_code: u32, section: &'static str) -> Result<(), DecodeError> {
    if result_code >= 1000 {
        Ok(())
    } else {
        Err(DecodeError::new(
            DecodeErrorCode::InvalidEnumValue {
                field: "Diameter Result-Code",
                value: u64::from(result_code),
            },
            DIAMETER_HEADER_LEN,
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC6733", section)))
    }
}

fn validate_received_answer_error_bit(
    result_code: u32,
    error_bit: bool,
) -> Result<(), DecodeError> {
    let valid = match result_code / 1000 {
        3 => error_bit,
        1 | 2 | 4 => !error_bit,
        // RFC 6733 sections 7.1 and 7.1.5 treat 5xxx and unrecognized
        // classes as permanent failures. They normally use the application
        // CCF with E clear, but may use the generic section 7.2 E-bit grammar
        // when that CCF cannot be composed.
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(forbidden_rfc_error(
            4,
            "SWm lifecycle answer E bit does not match the Result-Code family",
            "RFC6733",
            "7.1",
        ))
    }
}

fn validate_supported_result_context_decode(
    result_code: u32,
    offset: usize,
) -> Result<(), DecodeError> {
    if result_code == RESULT_CODE_DIAMETER_REDIRECT_INDICATION {
        return Err(forbidden_rfc_error(
            offset,
            "SWm STA redirect result requires a typed Redirect-Host surface",
            "RFC6733",
            "7.2",
        ));
    }
    Ok(())
}

fn validate_supported_result_context_encode(
    result: SwmSessionTerminationResult,
) -> Result<(), EncodeError> {
    match result {
        SwmSessionTerminationResult::Success
        | SwmSessionTerminationResult::UnknownSession
        | SwmSessionTerminationResult::UnableToComply => Ok(()),
        SwmSessionTerminationResult::Other(_) => Err(encode_error(
            "typed SWm STA builder supports only result codes with a complete modeled AVP context",
            "7.2.2.2.2",
        )),
    }
}

fn validate_abort_supported_result_context_decode(
    result_code: u32,
    additional_avps: &[SwmAdditionalAvp],
    offset: usize,
) -> Result<(), DecodeError> {
    if result_code == RESULT_CODE_DIAMETER_REDIRECT_INDICATION
        || additional_avps.iter().any(|avp| {
            matches!(
                avp.header.key(),
                key if key == AvpKey::ietf(base::AVP_REDIRECT_HOST)
                    || key == AvpKey::ietf(base::AVP_REDIRECT_HOST_USAGE)
                    || key == AvpKey::ietf(base::AVP_REDIRECT_MAX_CACHE_TIME)
            )
        })
    {
        return Err(forbidden_rfc_error(
            offset,
            "typed SWm ASA does not support redirect result context",
            "RFC6733",
            "7.2",
        ));
    }
    Ok(())
}

fn validate_abort_supported_result_context_encode(
    result: SwmAbortSessionResult,
    additional_avps: &[SwmAdditionalAvp],
) -> Result<(), EncodeError> {
    if additional_avps.iter().any(|avp| {
        matches!(
            avp.header.key(),
            key if key == AvpKey::ietf(base::AVP_REDIRECT_HOST)
                || key == AvpKey::ietf(base::AVP_REDIRECT_HOST_USAGE)
                || key == AvpKey::ietf(base::AVP_REDIRECT_MAX_CACHE_TIME)
        )
    }) {
        return Err(encode_error(
            "typed SWm ASA builder does not originate redirect AVP context",
            "7.2.2.3.2",
        ));
    }
    match result {
        SwmAbortSessionResult::Success
        | SwmAbortSessionResult::UnknownSession
        | SwmAbortSessionResult::UnableToComply => Ok(()),
        SwmAbortSessionResult::Other(_) => Err(encode_error(
            "typed SWm ASA builder supports only result codes with a complete modeled AVP context",
            "7.2.2.3.2",
        )),
    }
}

fn forbidden_rfc_error(
    offset: usize,
    reason: &'static str,
    document: &'static str,
    section: &'static str,
) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new("ietf", document, section))
}

fn forbidden_error(offset: usize, reason: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "7.2.2.2"))
}

fn forbidden_error_at(offset: usize, reason: &'static str, section: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", section))
}

fn count_error(offset: usize, _reason: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "7.2.2.2"))
}

fn count_error_at(offset: usize, _reason: &'static str, section: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", section))
}

fn duplicate_error(offset: usize, _reason: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::DuplicateIe, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "7.2.2.2"))
}

fn duplicate_error_at(offset: usize, _reason: &'static str, section: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::DuplicateIe, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", section))
}

fn decode_error(reason: &'static str, offset: usize, section: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", section))
}

fn encode_error(reason: &'static str, section: &'static str) -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural { reason })
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", section))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_payload_requires_the_same_proxiable_bit() {
        let initial = SwmSessionTerminationRequestEnvelope {
            transaction: super::super::SwmDiameterTransaction::new(1, 2),
            proxiable: true,
            potentially_retransmitted: false,
            expected_answer_peer: None,
            request: SwmSessionTerminationRequest {
                session_id: Sensitive::from("synthetic-session"),
                origin_host: Redacted::from("epdg.example.invalid"),
                origin_realm: Redacted::from("example.invalid"),
                destination_realm: Redacted::from("aaa.invalid"),
                destination_host: None,
                termination_cause: SwmTerminationCause::Administrative,
                user_name: Sensitive::from("synthetic-user@example.invalid"),
                drmp: None,
                route_records: Vec::new(),
                additional_avps: Vec::new(),
            },
            proxy_infos: Vec::new(),
        };
        let mut changed = initial.clone();
        changed.proxiable = false;

        assert!(!initial.same_replay_payload(&changed));
    }

    #[test]
    fn abort_replay_payload_requires_the_same_proxiable_bit() {
        let initial = SwmAbortSessionRequestEnvelope {
            transaction: super::super::SwmDiameterTransaction::new(1, 2),
            proxiable: true,
            potentially_retransmitted: false,
            expected_answer_peer: None,
            request: SwmAbortSessionRequest {
                session_id: Redacted::from("synthetic-session.example"),
                origin_host: Redacted::from("origin-host.example"),
                origin_realm: Redacted::from("origin-realm.example"),
                destination_realm: Redacted::from("destination-realm.example"),
                destination_host: Redacted::from("destination-host.example"),
                user_name: Redacted::from("synthetic-user@identity.example"),
                auth_session_state: Some(SwmAuthSessionState::StateMaintained),
                origin_state_id: Some(1),
                drmp: None,
                route_records: Vec::new(),
                additional_avps: Vec::new(),
            },
            proxy_infos: Vec::new(),
        };
        let mut changed = initial.clone();
        changed.proxiable = false;

        assert!(!initial.same_replay_payload(&changed));
    }
}
