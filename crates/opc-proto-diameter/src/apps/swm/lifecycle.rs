//! Typed SWm Session-Termination Request/Answer lifecycle boundary.
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
use crate::base;
use crate::dictionary::{
    AvpCardinality, AvpDataType, AvpDefinition, AvpFlagRules, AvpKey, CommandAvpRule,
    CommandDefinition, CommandKind, FlagRequirement,
};
use crate::parser_error::DiameterParserError;
use crate::{
    AvpCode, AvpHeader, CommandCode, CommandFlags, Message, OwnedMessage, RawAvp, VendorId,
    DIAMETER_HEADER_LEN,
};

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
enum ValueValidationPurpose {
    Decode,
    Encode,
}

const MAX_ROUTE_RECORDS: usize = 128;
const MAX_ADDITIONAL_AVPS: usize = 128;
const MAX_PROXY_INFOS: usize = 128;

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

    fn from_raw(avp: &RawAvp<'_>) -> Self {
        Self {
            header: avp.header.clone(),
            value: Bytes::copy_from_slice(avp.value),
        }
    }

    fn append_to(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        builder_helpers::append_avp(dst, self.header.clone(), &self.value, ctx)
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

    fn matches_origin(&self, origin_host: &str, origin_realm: &str) -> bool {
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

    fn validate_for_encode(&self) -> Result<(), EncodeError> {
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
#[derive(Clone, PartialEq, Eq)]
pub struct SwmSessionTerminationRequest {
    /// Session-Id; diagnostic formatting is redacted.
    pub session_id: Redacted<String>,
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
    /// Required permanent User-Name; diagnostic formatting is redacted.
    pub user_name: Redacted<String>,
    /// Optional RFC 7944 routing priority.
    pub drmp: Option<SwmRoutingMessagePriority>,
    /// Ordered Route-Record values; diagnostic formatting is redacted.
    pub route_records: Vec<Redacted<String>>,
    /// Ordered, well-formed additional command AVPs.
    pub additional_avps: Vec<SwmAdditionalAvp>,
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

/// Typed SWm Session-Termination-Answer facts.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmSessionTerminationAnswer {
    /// Session-Id; absent only on a received RFC 6733 generic E-bit answer,
    /// including the permitted permanent-failure fallback. Diagnostic
    /// formatting is redacted when present.
    pub session_id: Option<Redacted<String>>,
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

/// Parsed or outbound STR together with retained request-correlation facts.
///
/// An inbound request parsed for server-side STA construction has no expected
/// answer peer. Outbound requests and forwarded requests bind one explicitly;
/// attempting answer correlation without that binding fails closed.
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

/// Parsed STA together with immutable answer-correlation facts.
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
                builder_helpers::set_once(&mut user_name, Redacted::from(value), offset, "8.14")?;
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
            } else if let Some(additional) =
                parse_additional_avp(&avp, ctx, offset, value_offset, LifecycleRole::Request)?
            {
                if additional_avps.len() >= MAX_ADDITIONAL_AVPS {
                    return Err(count_error(
                        offset,
                        "SWm STR additional AVP count exceeds its bound",
                    ));
                }
                if !additional_key_is_repeatable(key, LifecycleRole::Request)
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
            } else if let Some(additional) =
                parse_additional_avp(&avp, ctx, offset, value_offset, LifecycleRole::Answer)?
            {
                if additional_avps.len() >= MAX_ADDITIONAL_AVPS {
                    return Err(count_error(
                        offset,
                        "SWm STA additional AVP count exceeds its bound",
                    ));
                }
                if !additional_key_is_repeatable(key, LifecycleRole::Answer)
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
    validate_additional_for_encode(&request.additional_avps, LifecycleRole::Request, None, ctx)
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
        LifecycleRole::Answer,
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
        validate_answer_overload_control_encode(request_avps, avps, ctx)?;
    }
    Ok(())
}

fn additional_key_is_repeatable(key: AvpKey, role: LifecycleRole) -> bool {
    key == AvpKey::ietf(base::AVP_CLASS)
        || (role == LifecycleRole::Answer && key == AvpKey::ietf(AVP_LOAD))
}

fn validate_additional_header_for_encode(
    avp: &SwmAdditionalAvp,
    role: LifecycleRole,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let key = avp.header.key();
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
    if definition.data_type() != AvpDataType::Grouped {
        return Ok(());
    }
    match avp.header.key() {
        key if key == AvpKey::ietf(AVP_OC_SUPPORTED_FEATURES) => {
            let features = parse_oc_supported_features(avp, ctx, value_offset, role)?;
            if purpose == ValueValidationPurpose::Encode
                && role == LifecycleRole::Request
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
                return Err(forbidden_error(
                    value_offset,
                    "originated typed SWm STA cannot contain Experimental-Result",
                ));
            }
            super::parse_experimental_result(avp.value, ctx, value_offset, 1).map(|_| ())
        }
        _ => validate_grouped(avp, ctx, value_offset, role.section()),
    }
}

fn retain_additional_avp(
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

    Ok(SwmAdditionalAvp {
        header: avp.header.clone(),
        value: retained.freeze(),
    })
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
            LifecycleRole::Request if value & OC_DEFAULT_ALGORITHM == 0 => {
                return Err(forbidden_rfc_error(
                    value_offset,
                    "request OC-Feature-Vector must advertise the loss algorithm",
                    "RFC7683",
                    "5.1.1",
                ));
            }
            LifecycleRole::Answer if value != OC_DEFAULT_ALGORITHM => {
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

fn validate_answer_overload_control_decode(
    answer_avps: &[SwmAdditionalAvp],
    ctx: DecodeContext,
) -> Result<(), DecodeError> {
    let answer = find_oc_supported_features(answer_avps, ctx, LifecycleRole::Answer)?;
    let olr = find_oc_olr(answer_avps, ctx)?;
    validate_answer_olr_presence(answer, olr)
}

fn validate_answer_overload_control_encode(
    request_avps: &[SwmAdditionalAvp],
    answer_avps: &[SwmAdditionalAvp],
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let decode_ctx = DecodeContext {
        max_message_len: ctx.max_message_len,
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::default()
    };
    validate_offered_overload_control(request_avps, answer_avps, decode_ctx).map_err(|_| {
        encode_error(
            "SWm STA overload-control selection is invalid for its request",
            "RFC7683-5.1.2",
        )
    })
}

fn validate_offered_overload_control(
    request_avps: &[SwmAdditionalAvp],
    answer_avps: &[SwmAdditionalAvp],
    ctx: DecodeContext,
) -> Result<(), DecodeError> {
    let request = find_oc_supported_features(request_avps, ctx, LifecycleRole::Request)?;
    let answer = find_oc_supported_features(answer_avps, ctx, LifecycleRole::Answer)?;
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
    let request = find_oc_supported_features(request_avps, ctx, LifecycleRole::Request)
        .map_err(|_| SwmSessionTerminationCorrelationError::MalformedOverloadControl)?;
    let answer = find_oc_supported_features(answer_avps, ctx, LifecycleRole::Answer)
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

fn validate_proxy_info(
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

fn validate_base_definition(avp: &RawAvp<'_>, offset: usize) -> Result<(), DecodeError> {
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

fn validate_drmp(avp: &RawAvp<'_>, offset: usize) -> Result<(), DecodeError> {
    // TS 29.273 section 7.2.3.1, table 2 note 2 requires a receiver
    // that understands DRMP to ignore an M-bit mismatch. Originated DRMP
    // remains canonical with M clear through `append_drmp`.
    validate_flags_ignoring_m(
        &avp.header,
        AvpFlagRules::base_must_not_set_m(),
        offset,
        "RFC7944-9.1",
    )
}

fn validate_flags(
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

fn validate_flags_for_encode(
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

fn find_definition(key: AvpKey) -> Option<&'static AvpDefinition> {
    base::dictionary()
        .find_avp(key)
        .or_else(|| super::dictionary().find_avp(key))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleRole {
    Request,
    Answer,
}

impl LifecycleRole {
    const fn section(self) -> &'static str {
        match self {
            Self::Request => "7.2.2.2.1",
            Self::Answer => "7.2.2.2.2",
        }
    }
}

fn core_key_for_role(key: AvpKey, role: LifecycleRole) -> bool {
    if key.vendor_id().is_some() {
        return false;
    }
    let code = key.code();
    match role {
        LifecycleRole::Request => matches!(
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
        LifecycleRole::Answer => matches!(
            code,
            base::AVP_SESSION_ID
                | base::AVP_RESULT_CODE
                | base::AVP_ORIGIN_HOST
                | base::AVP_ORIGIN_REALM
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
    match role {
        LifecycleRole::Request => matches!(
            key.code(),
            base::AVP_RESULT_CODE | base::AVP_EXPERIMENTAL_RESULT | AVP_OC_OLR | AVP_LOAD
        ),
        LifecycleRole::Answer => matches!(
            key.code(),
            base::AVP_DESTINATION_REALM
                | base::AVP_DESTINATION_HOST
                | base::AVP_AUTH_APPLICATION_ID
                | base::AVP_TERMINATION_CAUSE
                | base::AVP_ROUTE_RECORD
        ),
    }
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
            "SWm STA E bit does not match the Result-Code family",
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

fn count_error(offset: usize, _reason: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "7.2.2.2"))
}

fn duplicate_error(offset: usize, _reason: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::DuplicateIe, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "7.2.2.2"))
}

fn decode_error(reason: &'static str, offset: usize, section: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", section))
}

fn encode_error(reason: &'static str, section: &'static str) -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural { reason })
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", section))
}
