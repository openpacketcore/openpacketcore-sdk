//! Reply-safe GTPv2-C protocol-error inspection and response planning.
//!
//! This module deliberately sits beside the full message decoder. It inspects
//! only the fixed common-header bytes needed to prove that a datagram belongs
//! to an answerable request class, and it never interprets subscriber IEs or
//! makes peer-admission, rate-limit, transaction, or session-lookup decisions.
//!
//! @spec 3GPP TS29274 R18 5.3, 5.5.2, 7.1.2, 7.1.3, 7.6, 7.7.2-7.7.8, 8.4
//! @req REQ-3GPP-TS29274-R18-ERROR-RESPONSE-001

use core::fmt;
use core::num::NonZeroU32;

use bytes::{Bytes, BytesMut};
use opc_protocol::{Encode, EncodeContext, EncodeError, EncodeErrorCode, SpecRef};

use crate::header::{
    Header, MessagePriority, MessageType, GTPV2C_VERSION, HEADER_LEN_WITHOUT_TEID,
    HEADER_LEN_WITH_TEID, MAX_SEQUENCE_NUMBER,
};
use crate::ie::{encode_typed_ie_sequence, Cause, CauseValue, Recovery, TypedIe, TypedIeValue};
use crate::s2b::{procedure_and_direction, MessageDirection, Procedure};
use crate::OwnedMessage;

/// Largest canonical response produced by this boundary, in octets.
///
/// The bound is a TEID-present 12-octet header plus a 10-octet Cause IE with
/// the four-octet offending-IE identity.
pub const MAX_GTPV2C_ERROR_RESPONSE_WIRE_LEN: usize = 22;

const VERSION_NOT_SUPPORTED_WIRE_LEN: usize = HEADER_LEN_WITHOUT_TEID;
const ECHO_RESPONSE_WIRE_LEN: usize = HEADER_LEN_WITHOUT_TEID + 5;
const ORDINARY_CAUSE_RESPONSE_WIRE_LEN: usize = HEADER_LEN_WITH_TEID + 6;
const ORDINARY_OFFENDING_IE_RESPONSE_WIRE_LEN: usize = HEADER_LEN_WITH_TEID + 10;

fn spec_ref() -> SpecRef {
    SpecRef::new("3gpp", "TS29274", "7.7")
}

/// Checked 24-bit GTPv2-C sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Gtpv2cSequenceNumber(u32);

impl Gtpv2cSequenceNumber {
    /// Validate and construct a sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`Gtpv2cInvalidSequenceNumber`] when `value` exceeds 24 bits.
    pub const fn new(value: u32) -> Result<Self, Gtpv2cInvalidSequenceNumber> {
        if value <= MAX_SEQUENCE_NUMBER {
            Ok(Self(value))
        } else {
            Err(Gtpv2cInvalidSequenceNumber { value })
        }
    }

    const fn from_wire(value: u32) -> Self {
        Self(value & MAX_SEQUENCE_NUMBER)
    }

    /// Return the 24-bit value as a `u32`.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Error returned for a sequence number wider than 24 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtpv2cInvalidSequenceNumber {
    value: u32,
}

impl Gtpv2cInvalidSequenceNumber {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        "gtpv2c_sequence_number_out_of_range"
    }

    /// Return the rejected value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.value
    }
}

impl fmt::Display for Gtpv2cInvalidSequenceNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for Gtpv2cInvalidSequenceNumber {}

/// Reply-safe classification of the TEID carried by a received header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Gtpv2cReceivedTeid {
    /// No TEID field is present, as required for Echo.
    Absent,
    /// A TEID field is present and contains zero.
    Zero,
    /// A non-zero TEID field is present.
    NonZero(NonZeroU32),
}

impl Gtpv2cReceivedTeid {
    /// Return the received TEID value, when a TEID field was present.
    ///
    /// The exact value is intentionally omitted from `Debug` output.
    #[must_use]
    pub const fn value(self) -> Option<u32> {
        match self {
            Self::Absent => None,
            Self::Zero => Some(0),
            Self::NonZero(value) => Some(value.get()),
        }
    }

    /// Return `true` when the received header carried a zero TEID.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        matches!(self, Self::Zero)
    }
}

impl fmt::Debug for Gtpv2cReceivedTeid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => formatter.write_str("Absent"),
            Self::Zero => formatter.write_str("Zero"),
            Self::NonZero(_) => formatter.write_str("NonZero(<redacted>)"),
        }
    }
}

/// Fixed request metadata proven safe for error-response correlation.
///
/// This envelope contains no packet bytes or subscriber IEs. A non-zero TEID
/// remains available to the caller for its own context lookup, but every
/// `Debug` path redacts its value.
#[derive(Clone, PartialEq, Eq)]
pub struct Gtpv2cRequestEnvelope {
    version: u8,
    message_type: MessageType,
    procedure: Procedure,
    sequence_number: Gtpv2cSequenceNumber,
    received_teid: Gtpv2cReceivedTeid,
    message_priority: Option<MessagePriority>,
    declared_total_len: usize,
    actual_len: usize,
}

impl Gtpv2cRequestEnvelope {
    /// Protocol version recovered from the header.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Typed request message.
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// S2b procedure mapped from the request message type.
    #[must_use]
    pub const fn procedure(&self) -> Procedure {
        self.procedure
    }

    /// Request sequence number used by ordinary and Echo responses.
    #[must_use]
    pub const fn sequence_number(&self) -> Gtpv2cSequenceNumber {
        self.sequence_number
    }

    /// TEID presence/value classification from the received header.
    #[must_use]
    pub const fn received_teid(&self) -> Gtpv2cReceivedTeid {
        self.received_teid
    }

    /// Relative message priority, when the request carried one.
    #[must_use]
    pub const fn message_priority(&self) -> Option<MessagePriority> {
        self.message_priority
    }

    /// Total datagram length declared by the GTPv2-C Length field.
    #[must_use]
    pub const fn declared_total_len(&self) -> usize {
        self.declared_total_len
    }

    /// Actual input datagram length supplied to inspection.
    #[must_use]
    pub const fn actual_len(&self) -> usize {
        self.actual_len
    }

    /// Return `true` when the declared and actual datagram lengths match.
    #[must_use]
    pub const fn length_matches(&self) -> bool {
        self.declared_total_len == self.actual_len
    }
}

impl fmt::Debug for Gtpv2cRequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Gtpv2cRequestEnvelope")
            .field("version", &self.version)
            .field("message_type", &self.message_type)
            .field("procedure", &self.procedure)
            .field("sequence_number", &self.sequence_number)
            .field("received_teid", &self.received_teid)
            .field("message_priority", &self.message_priority)
            .field("declared_total_len", &self.declared_total_len)
            .field("actual_len", &self.actual_len)
            .finish()
    }
}

/// Minimum metadata recovered from a complete unsupported-version header.
///
/// The received sequence number is intentionally not retained: message type 3
/// uses a locally supplied sequence and receivers ignore it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Gtpv2cUnsupportedVersionEnvelope {
    version: u8,
    received_teid: Gtpv2cReceivedTeid,
    declared_total_len: usize,
    actual_len: usize,
}

impl Gtpv2cUnsupportedVersionEnvelope {
    /// Unsupported received version, always greater than two.
    #[must_use]
    pub const fn version(self) -> u8 {
        self.version
    }

    /// TEID presence/value classification recovered for diagnostics.
    #[must_use]
    pub const fn received_teid(self) -> Gtpv2cReceivedTeid {
        self.received_teid
    }

    /// Total datagram length declared by the unsupported-version header.
    #[must_use]
    pub const fn declared_total_len(self) -> usize {
        self.declared_total_len
    }

    /// Actual inspected datagram length.
    #[must_use]
    pub const fn actual_len(self) -> usize {
        self.actual_len
    }
}

impl fmt::Debug for Gtpv2cUnsupportedVersionEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Gtpv2cUnsupportedVersionEnvelope")
            .field("version", &self.version)
            .field("received_teid", &self.received_teid)
            .field("declared_total_len", &self.declared_total_len)
            .field("actual_len", &self.actual_len)
            .finish()
    }
}

/// Standards-based reason an inspected datagram must not receive a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gtpv2cUnanswerableReason {
    /// Fewer bytes were present than the header shape requires.
    TooShortForHeader,
    /// Version zero or one is silently discarded by a GTPv2-only endpoint.
    UnsupportedLowerVersion,
    /// Piggyback length/error recovery is outside this bounded boundary.
    PiggybackedMessage,
    /// The message type is unknown and must be silently discarded.
    UnknownMessageType,
    /// The input is a response or Version Not Supported indication.
    NotARequest,
    /// The TEID flag contradicts the fixed Echo/EPC request header shape.
    InvalidRequestHeaderShape,
    /// Echo length mismatches do not receive Cause-bearing error responses.
    EchoLengthMismatch,
    /// Unknown-TEID failure was supplied for a no-TEID Echo request.
    UnknownTeidForEcho,
    /// Unknown-TEID failure requires a received non-zero tunnel identifier.
    UnknownTeidRequiresNonZeroReceivedTeid,
    /// Invalid-message-length was requested although lengths match.
    MessageLengthMatches,
    /// Unknown-TEID and invalid-length classifications conflict.
    ConflictingLengthAndTeidFailure,
}

impl Gtpv2cUnanswerableReason {
    /// Stable machine-readable reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TooShortForHeader => "gtpv2c_error_response_too_short",
            Self::UnsupportedLowerVersion => "gtpv2c_error_response_lower_version_discard",
            Self::PiggybackedMessage => "gtpv2c_error_response_piggyback_discard",
            Self::UnknownMessageType => "gtpv2c_error_response_unknown_message_discard",
            Self::NotARequest => "gtpv2c_error_response_non_request_discard",
            Self::InvalidRequestHeaderShape => "gtpv2c_error_response_invalid_request_header_shape",
            Self::EchoLengthMismatch => "gtpv2c_error_response_echo_length_discard",
            Self::UnknownTeidForEcho => "gtpv2c_error_response_echo_has_no_teid",
            Self::UnknownTeidRequiresNonZeroReceivedTeid => {
                "gtpv2c_error_response_unknown_teid_requires_nonzero_received_teid"
            }
            Self::MessageLengthMatches => "gtpv2c_error_response_length_matches",
            Self::ConflictingLengthAndTeidFailure => "gtpv2c_error_response_length_teid_conflict",
        }
    }
}

/// Result of fixed-header request inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gtpv2cRequestInspection {
    /// The standard requires silent discard or the header proof is incomplete.
    Unanswerable(Gtpv2cUnanswerableReason),
    /// A complete higher-version header permits message type 3.
    UnsupportedVersion(Gtpv2cUnsupportedVersionEnvelope),
    /// A complete, known request header permits typed error planning.
    Request(Gtpv2cRequestEnvelope),
}

/// Inspect only the fixed bytes needed to prove an answerable request class.
///
/// Inspection performs no allocation and does not decode the IE region. It
/// requires all eight bytes of a no-TEID header or all twelve bytes of a
/// TEID-present header before returning either answerable envelope.
#[must_use]
pub fn inspect_gtpv2c_request(input: &[u8]) -> Gtpv2cRequestInspection {
    if input.len() < 4 {
        return Gtpv2cRequestInspection::Unanswerable(Gtpv2cUnanswerableReason::TooShortForHeader);
    }

    let flags = input[0];
    let version = (flags >> 5) & 0x07;
    let piggybacking = (flags & 0x10) != 0;
    let teid_flag = (flags & 0x08) != 0;
    let message_priority_flag = teid_flag && (flags & 0x04) != 0;
    let header_len = if teid_flag {
        HEADER_LEN_WITH_TEID
    } else {
        HEADER_LEN_WITHOUT_TEID
    };
    if input.len() < header_len {
        return Gtpv2cRequestInspection::Unanswerable(Gtpv2cUnanswerableReason::TooShortForHeader);
    }

    let declared_total_len = 4usize + u16::from_be_bytes([input[2], input[3]]) as usize;
    let (received_teid, sequence_offset) = if teid_flag {
        let value = u32::from_be_bytes([input[4], input[5], input[6], input[7]]);
        let classified = match NonZeroU32::new(value) {
            Some(non_zero) => Gtpv2cReceivedTeid::NonZero(non_zero),
            None => Gtpv2cReceivedTeid::Zero,
        };
        (classified, 8usize)
    } else {
        (Gtpv2cReceivedTeid::Absent, 4usize)
    };

    if version > GTPV2C_VERSION {
        return Gtpv2cRequestInspection::UnsupportedVersion(Gtpv2cUnsupportedVersionEnvelope {
            version,
            received_teid,
            declared_total_len,
            actual_len: input.len(),
        });
    }
    if version < GTPV2C_VERSION {
        return Gtpv2cRequestInspection::Unanswerable(
            Gtpv2cUnanswerableReason::UnsupportedLowerVersion,
        );
    }
    if piggybacking {
        return Gtpv2cRequestInspection::Unanswerable(Gtpv2cUnanswerableReason::PiggybackedMessage);
    }

    let message_type = MessageType::from_u8(input[1]);
    let Some((procedure, direction)) = procedure_and_direction(message_type) else {
        return Gtpv2cRequestInspection::Unanswerable(
            if matches!(message_type, MessageType::Unknown(_)) {
                Gtpv2cUnanswerableReason::UnknownMessageType
            } else {
                Gtpv2cUnanswerableReason::NotARequest
            },
        );
    };
    if direction != MessageDirection::Request {
        return Gtpv2cRequestInspection::Unanswerable(Gtpv2cUnanswerableReason::NotARequest);
    }
    let is_echo = procedure == Procedure::Echo;
    if is_echo == teid_flag {
        return Gtpv2cRequestInspection::Unanswerable(
            Gtpv2cUnanswerableReason::InvalidRequestHeaderShape,
        );
    }

    let sequence_number = ((input[sequence_offset] as u32) << 16)
        | ((input[sequence_offset + 1] as u32) << 8)
        | input[sequence_offset + 2] as u32;
    let message_priority = if message_priority_flag {
        MessagePriority::new(input[sequence_offset + 3] >> 4).ok()
    } else {
        None
    };

    Gtpv2cRequestInspection::Request(Gtpv2cRequestEnvelope {
        version,
        message_type,
        procedure,
        sequence_number: Gtpv2cSequenceNumber::from_wire(sequence_number),
        received_teid,
        message_priority,
        declared_total_len,
        actual_len: input.len(),
    })
}

/// Type and four-bit instance of a mandatory or verifiable conditional IE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gtpv2cOffendingIe {
    ie_type: u8,
    instance: u8,
}

impl Gtpv2cOffendingIe {
    /// Validate and construct an offending-IE identity.
    ///
    /// # Errors
    ///
    /// Returns [`Gtpv2cInvalidOffendingIeInstance`] when `instance` is wider
    /// than the four-bit GTPv2-C IE Instance field.
    pub const fn new(ie_type: u8, instance: u8) -> Result<Self, Gtpv2cInvalidOffendingIeInstance> {
        if instance <= 0x0f {
            Ok(Self { ie_type, instance })
        } else {
            Err(Gtpv2cInvalidOffendingIeInstance { instance })
        }
    }

    /// IE Type octet.
    #[must_use]
    pub const fn ie_type(self) -> u8 {
        self.ie_type
    }

    /// Four-bit IE Instance.
    #[must_use]
    pub const fn instance(self) -> u8 {
        self.instance
    }

    const fn cause_field(self) -> [u8; 4] {
        [self.ie_type, 0, 0, self.instance]
    }
}

/// Error returned for an offending-IE instance wider than four bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtpv2cInvalidOffendingIeInstance {
    instance: u8,
}

impl Gtpv2cInvalidOffendingIeInstance {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        "gtpv2c_offending_ie_instance_out_of_range"
    }

    /// Return the rejected instance.
    #[must_use]
    pub const fn instance(self) -> u8 {
        self.instance
    }
}

impl fmt::Display for Gtpv2cInvalidOffendingIeInstance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for Gtpv2cInvalidOffendingIeInstance {}

/// Clause 5.5.2 TEID decision for a protocol-error response.
///
/// Context Not Found is deliberately not represented here. That cause uses
/// [`Gtpv2cRequestFailure::UnknownReceivedTeid`], which always selects zero.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Gtpv2cProtocolErrorResponseTeid {
    /// Remote peer TEID returned by a caller-owned context lookup.
    Remote(NonZeroU32),
    /// Optional no-lookup path: use TEID zero with the protocol-error Cause.
    NoLookup,
}

impl Gtpv2cProtocolErrorResponseTeid {
    const fn wire_value(self) -> u32 {
        match self {
            Self::Remote(value) => value.get(),
            Self::NoLookup => 0,
        }
    }

    /// Return `true` for the optional no-lookup TEID-zero path.
    #[must_use]
    pub const fn uses_zero(self) -> bool {
        matches!(self, Self::NoLookup)
    }
}

impl fmt::Debug for Gtpv2cProtocolErrorResponseTeid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Remote(_) => formatter.write_str("Remote(<redacted>)"),
            Self::NoLookup => formatter.write_str("NoLookup"),
        }
    }
}

/// Protocol-error classification mapped to a TS 29.274 Cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gtpv2cProtocolErrorKind {
    /// Datagram length does not match the common-header Length field.
    InvalidMessageLength,
    /// Mandatory IE is absent.
    MissingMandatoryIe(Gtpv2cOffendingIe),
    /// Verifiable conditional IE is absent.
    MissingConditionalIe(Gtpv2cOffendingIe),
    /// Mandatory or verifiable conditional IE has invalid length.
    InvalidIeLength(Gtpv2cOffendingIe),
    /// Mandatory or verifiable conditional IE has invalid semantics.
    IncorrectIe(Gtpv2cOffendingIe),
}

impl Gtpv2cProtocolErrorKind {
    /// Cause value required for this protocol error.
    #[must_use]
    pub const fn cause(self) -> CauseValue {
        match self {
            Self::InvalidMessageLength | Self::InvalidIeLength(_) => CauseValue::InvalidLength,
            Self::MissingMandatoryIe(_) => CauseValue::MandatoryIeMissing,
            Self::MissingConditionalIe(_) => CauseValue::ConditionalIeMissing,
            Self::IncorrectIe(_) => CauseValue::MandatoryIeIncorrect,
        }
    }

    /// Offending mandatory/conditional IE, when required by the Cause IE.
    #[must_use]
    pub const fn offending_ie(self) -> Option<Gtpv2cOffendingIe> {
        match self {
            Self::InvalidMessageLength => None,
            Self::MissingMandatoryIe(ie)
            | Self::MissingConditionalIe(ie)
            | Self::InvalidIeLength(ie)
            | Self::IncorrectIe(ie) => Some(ie),
        }
    }
}

/// Protocol failure plus the explicit clause 5.5.2 TEID decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtpv2cProtocolError {
    kind: Gtpv2cProtocolErrorKind,
    response_teid: Gtpv2cProtocolErrorResponseTeid,
}

impl Gtpv2cProtocolError {
    /// Construct a protocol error using an explicit remote/no-lookup TEID path.
    #[must_use]
    pub const fn new(
        kind: Gtpv2cProtocolErrorKind,
        response_teid: Gtpv2cProtocolErrorResponseTeid,
    ) -> Self {
        Self {
            kind,
            response_teid,
        }
    }

    /// Protocol error kind.
    #[must_use]
    pub const fn kind(self) -> Gtpv2cProtocolErrorKind {
        self.kind
    }

    /// Explicit clause 5.5.2 TEID decision.
    #[must_use]
    pub const fn response_teid(self) -> Gtpv2cProtocolErrorResponseTeid {
        self.response_teid
    }
}

/// Caller-supplied failure after fixed-header inspection or full decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gtpv2cRequestFailure {
    /// Received non-zero session TEID is unknown.
    ///
    /// The planner rejects this failure for a zero-TEID initial request rather
    /// than treating the intentional absence of a peer TEID as a failed
    /// context lookup. A valid unknown-TEID response is Context Not Found with
    /// response TEID zero.
    UnknownReceivedTeid,
    /// Structural or semantic request error with explicit response TEID policy.
    Protocol(Gtpv2cProtocolError),
}

/// Stateless configuration for error-response planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtpv2cErrorResponsePlanner {
    version_not_supported_sequence: Gtpv2cSequenceNumber,
    echo_recovery: Recovery,
}

impl Gtpv2cErrorResponsePlanner {
    /// Construct a stateless planner.
    ///
    /// `version_not_supported_sequence` must be locally generated/supplied;
    /// the unsupported packet's sequence is never retained as correlation.
    #[must_use]
    pub const fn new(
        version_not_supported_sequence: Gtpv2cSequenceNumber,
        echo_recovery: Recovery,
    ) -> Self {
        Self {
            version_not_supported_sequence,
            echo_recovery,
        }
    }

    /// Inspect `input` and produce either no response or a bounded typed plan.
    ///
    /// Higher unsupported versions take priority and always use message type 3.
    /// The `failure` is used only for a version-2 request; callers that inspect
    /// first can use [`Self::plan_unsupported_version`] without fabricating
    /// failure evidence. For a version-2 request, the supplied failure remains
    /// caller-owned decode/session evidence. A datagram length mismatch takes
    /// priority over other protocol-error kinds, while a conflicting
    /// unknown-TEID report is rejected as unanswerable rather than guessed.
    #[must_use]
    pub fn plan(&self, input: &[u8], failure: Gtpv2cRequestFailure) -> Gtpv2cErrorResponseDecision {
        match inspect_gtpv2c_request(input) {
            Gtpv2cRequestInspection::Unanswerable(reason) => {
                Gtpv2cErrorResponseDecision::Unanswerable(reason)
            }
            Gtpv2cRequestInspection::UnsupportedVersion(envelope) => {
                Gtpv2cErrorResponseDecision::Respond(self.plan_unsupported_version(envelope))
            }
            Gtpv2cRequestInspection::Request(envelope) => {
                self.plan_request_failure(envelope, failure)
            }
        }
    }

    /// Build message type 3 from a proven higher-version envelope.
    ///
    /// This entry point deliberately takes no request-failure argument. The
    /// unsupported version is complete response evidence by itself, and the
    /// response uses the planner's locally supplied sequence rather than any
    /// received value.
    #[must_use]
    pub fn plan_unsupported_version(
        &self,
        envelope: Gtpv2cUnsupportedVersionEnvelope,
    ) -> Gtpv2cErrorResponsePlan {
        Gtpv2cErrorResponsePlan::version_not_supported(
            envelope,
            self.version_not_supported_sequence,
        )
    }

    /// Plan a response for a proven version-2 request envelope and failure.
    ///
    /// This is the typed continuation after [`inspect_gtpv2c_request`]. It
    /// avoids inspecting or retaining the datagram again after the caller has
    /// completed its full decode or session lookup.
    #[must_use]
    pub fn plan_request_failure(
        &self,
        envelope: Gtpv2cRequestEnvelope,
        failure: Gtpv2cRequestFailure,
    ) -> Gtpv2cErrorResponseDecision {
        if envelope.procedure == Procedure::Echo {
            if !envelope.length_matches() {
                return Gtpv2cErrorResponseDecision::Unanswerable(
                    Gtpv2cUnanswerableReason::EchoLengthMismatch,
                );
            }
            return match failure {
                Gtpv2cRequestFailure::UnknownReceivedTeid => {
                    Gtpv2cErrorResponseDecision::Unanswerable(
                        Gtpv2cUnanswerableReason::UnknownTeidForEcho,
                    )
                }
                Gtpv2cRequestFailure::Protocol(error)
                    if error.kind == Gtpv2cProtocolErrorKind::InvalidMessageLength =>
                {
                    Gtpv2cErrorResponseDecision::Unanswerable(
                        Gtpv2cUnanswerableReason::MessageLengthMatches,
                    )
                }
                Gtpv2cRequestFailure::Protocol(_) => Gtpv2cErrorResponseDecision::Respond(
                    Gtpv2cErrorResponsePlan::echo(envelope, self.echo_recovery),
                ),
            };
        }

        if matches!(failure, Gtpv2cRequestFailure::UnknownReceivedTeid)
            && !matches!(envelope.received_teid, Gtpv2cReceivedTeid::NonZero(_))
        {
            return Gtpv2cErrorResponseDecision::Unanswerable(
                Gtpv2cUnanswerableReason::UnknownTeidRequiresNonZeroReceivedTeid,
            );
        }

        if !envelope.length_matches() {
            return match failure {
                Gtpv2cRequestFailure::UnknownReceivedTeid => {
                    Gtpv2cErrorResponseDecision::Unanswerable(
                        Gtpv2cUnanswerableReason::ConflictingLengthAndTeidFailure,
                    )
                }
                Gtpv2cRequestFailure::Protocol(error) => {
                    let length_error = Gtpv2cProtocolError::new(
                        Gtpv2cProtocolErrorKind::InvalidMessageLength,
                        error.response_teid,
                    );
                    Gtpv2cErrorResponseDecision::Respond(Gtpv2cErrorResponsePlan::ordinary(
                        envelope,
                        CauseValue::InvalidLength,
                        None,
                        length_error.response_teid,
                    ))
                }
            };
        }

        match failure {
            Gtpv2cRequestFailure::UnknownReceivedTeid => Gtpv2cErrorResponseDecision::Respond(
                Gtpv2cErrorResponsePlan::ordinary_unknown(envelope),
            ),
            Gtpv2cRequestFailure::Protocol(error) => {
                if error.kind == Gtpv2cProtocolErrorKind::InvalidMessageLength {
                    return Gtpv2cErrorResponseDecision::Unanswerable(
                        Gtpv2cUnanswerableReason::MessageLengthMatches,
                    );
                }
                Gtpv2cErrorResponseDecision::Respond(Gtpv2cErrorResponsePlan::ordinary(
                    envelope,
                    error.kind.cause(),
                    error.kind.offending_ie(),
                    error.response_teid,
                ))
            }
        }
    }
}

/// High-level response kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gtpv2cErrorResponseKind {
    /// Header-only message type 3.
    VersionNotSupported,
    /// Echo Response with local Recovery IE and no Cause.
    Echo,
    /// Corresponding S2b response with a Cause IE.
    Ordinary,
}

#[derive(Clone, PartialEq, Eq)]
enum PlanBody {
    VersionNotSupported {
        sequence_number: Gtpv2cSequenceNumber,
    },
    Echo {
        sequence_number: Gtpv2cSequenceNumber,
        recovery: Recovery,
    },
    Ordinary {
        response_message_type: MessageType,
        sequence_number: Gtpv2cSequenceNumber,
        response_teid: u32,
        message_priority: Option<MessagePriority>,
        cause: CauseValue,
        offending_ie: Option<Gtpv2cOffendingIe>,
    },
}

/// Bounded, redaction-safe protocol-error response plan.
#[derive(Clone, PartialEq, Eq)]
pub struct Gtpv2cErrorResponsePlan {
    input_len: usize,
    body: PlanBody,
}

impl Gtpv2cErrorResponsePlan {
    fn version_not_supported(
        envelope: Gtpv2cUnsupportedVersionEnvelope,
        sequence_number: Gtpv2cSequenceNumber,
    ) -> Self {
        Self {
            input_len: envelope.actual_len,
            body: PlanBody::VersionNotSupported { sequence_number },
        }
    }

    fn echo(envelope: Gtpv2cRequestEnvelope, recovery: Recovery) -> Self {
        Self {
            input_len: envelope.actual_len,
            body: PlanBody::Echo {
                sequence_number: envelope.sequence_number,
                recovery,
            },
        }
    }

    fn ordinary_unknown(envelope: Gtpv2cRequestEnvelope) -> Self {
        Self::ordinary_inner(envelope, CauseValue::ContextNotFound, None, 0)
    }

    fn ordinary(
        envelope: Gtpv2cRequestEnvelope,
        cause: CauseValue,
        offending_ie: Option<Gtpv2cOffendingIe>,
        response_teid: Gtpv2cProtocolErrorResponseTeid,
    ) -> Self {
        Self::ordinary_inner(envelope, cause, offending_ie, response_teid.wire_value())
    }

    fn ordinary_inner(
        envelope: Gtpv2cRequestEnvelope,
        cause: CauseValue,
        offending_ie: Option<Gtpv2cOffendingIe>,
        response_teid: u32,
    ) -> Self {
        Self {
            input_len: envelope.actual_len,
            body: PlanBody::Ordinary {
                response_message_type: envelope.procedure.response_message_type(),
                sequence_number: envelope.sequence_number,
                response_teid,
                message_priority: envelope.message_priority,
                cause,
                offending_ie,
            },
        }
    }

    /// High-level response kind.
    #[must_use]
    pub const fn kind(&self) -> Gtpv2cErrorResponseKind {
        match self.body {
            PlanBody::VersionNotSupported { .. } => Gtpv2cErrorResponseKind::VersionNotSupported,
            PlanBody::Echo { .. } => Gtpv2cErrorResponseKind::Echo,
            PlanBody::Ordinary { .. } => Gtpv2cErrorResponseKind::Ordinary,
        }
    }

    /// Planned typed response message type.
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        match self.body {
            PlanBody::VersionNotSupported { .. } => MessageType::VersionNotSupportedIndication,
            PlanBody::Echo { .. } => MessageType::EchoResponse,
            PlanBody::Ordinary {
                response_message_type,
                ..
            } => response_message_type,
        }
    }

    /// Sequence number carried by the planned response.
    #[must_use]
    pub const fn sequence_number(&self) -> Gtpv2cSequenceNumber {
        match self.body {
            PlanBody::VersionNotSupported {
                sequence_number, ..
            }
            | PlanBody::Echo {
                sequence_number, ..
            }
            | PlanBody::Ordinary {
                sequence_number, ..
            } => sequence_number,
        }
    }

    /// Planned Cause value for an ordinary response.
    #[must_use]
    pub const fn cause(&self) -> Option<CauseValue> {
        match self.body {
            PlanBody::Ordinary { cause, .. } => Some(cause),
            PlanBody::VersionNotSupported { .. } | PlanBody::Echo { .. } => None,
        }
    }

    /// Offending IE identity included in the Cause IE, when applicable.
    #[must_use]
    pub const fn offending_ie(&self) -> Option<Gtpv2cOffendingIe> {
        match self.body {
            PlanBody::Ordinary { offending_ie, .. } => offending_ie,
            PlanBody::VersionNotSupported { .. } | PlanBody::Echo { .. } => None,
        }
    }

    /// Return `true` when the planned ordinary response uses TEID zero.
    #[must_use]
    pub const fn uses_zero_teid(&self) -> bool {
        match self.body {
            PlanBody::Ordinary { response_teid, .. } => response_teid == 0,
            PlanBody::VersionNotSupported { .. } | PlanBody::Echo { .. } => false,
        }
    }

    /// Input datagram length used for amplification accounting.
    #[must_use]
    pub const fn input_len(&self) -> usize {
        self.input_len
    }

    /// Exact canonical output length available before encoding.
    #[must_use]
    pub const fn planned_output_len(&self) -> usize {
        match self.body {
            PlanBody::VersionNotSupported { .. } => VERSION_NOT_SUPPORTED_WIRE_LEN,
            PlanBody::Echo { .. } => ECHO_RESPONSE_WIRE_LEN,
            PlanBody::Ordinary {
                offending_ie: Some(_),
                ..
            } => ORDINARY_OFFENDING_IE_RESPONSE_WIRE_LEN,
            PlanBody::Ordinary {
                offending_ie: None, ..
            } => ORDINARY_CAUSE_RESPONSE_WIRE_LEN,
        }
    }

    /// Return redaction-safe input/output sizing and TEID-zero metadata.
    #[must_use]
    pub const fn amplification_metadata(&self) -> Gtpv2cAmplificationMetadata {
        Gtpv2cAmplificationMetadata {
            input_len: self.input_len,
            planned_output_len: self.planned_output_len(),
            uses_zero_teid: self.uses_zero_teid(),
        }
    }

    /// Build the canonical owned response under an explicit encode bound.
    ///
    /// # Errors
    ///
    /// Returns an encode error if `ctx.max_message_len` is smaller than the
    /// exact planned output or if an invariant in the typed IE/header encoder
    /// fails closed.
    pub fn to_owned_message(&self, ctx: EncodeContext) -> Result<OwnedMessage, EncodeError> {
        ctx.check_capacity(self.planned_output_len())?;
        let (header, raw_ies) = match self.body {
            PlanBody::VersionNotSupported { sequence_number } => (
                Header::without_teid(
                    MessageType::VersionNotSupportedIndication.as_u8(),
                    sequence_number.get(),
                ),
                Bytes::new(),
            ),
            PlanBody::Echo {
                sequence_number,
                recovery,
            } => {
                let raw_ies = encode_plan_ies(
                    &[TypedIe {
                        instance: 0,
                        value: TypedIeValue::Recovery(recovery),
                    }],
                    ctx,
                )?;
                (
                    Header::without_teid(MessageType::EchoResponse.as_u8(), sequence_number.get()),
                    raw_ies,
                )
            }
            PlanBody::Ordinary {
                response_message_type,
                sequence_number,
                response_teid,
                message_priority,
                cause,
                offending_ie,
            } => {
                let offending_ie = offending_ie
                    .map(Gtpv2cOffendingIe::cause_field)
                    .map_or_else(Vec::new, |bytes| bytes.to_vec());
                let raw_ies = encode_plan_ies(
                    &[TypedIe {
                        instance: 0,
                        value: TypedIeValue::Cause(Cause {
                            value: cause,
                            flags_octet: 0,
                            offending_ie,
                        }),
                    }],
                    ctx,
                )?;
                (
                    Header::with_teid(
                        response_message_type.as_u8(),
                        response_teid,
                        sequence_number.get(),
                    )
                    .with_optional_message_priority(message_priority),
                    raw_ies,
                )
            }
        };
        let message = OwnedMessage { header, raw_ies };
        let actual = message.wire_len(ctx)?;
        if actual != self.planned_output_len() {
            return Err(EncodeError::new(EncodeErrorCode::Structural {
                reason: "GTPv2-C error response plan length mismatch",
            })
            .with_spec_ref(spec_ref()));
        }
        Ok(message)
    }

    /// Attach caller-owned receive metadata and reverse it for reply sending.
    #[must_use]
    pub fn with_received_peer<T>(
        self,
        received: Gtpv2cReceivedPeerMetadata<T>,
    ) -> Gtpv2cPlannedSend<T> {
        Gtpv2cPlannedSend {
            plan: self,
            send_tuple: received.into_send_tuple(),
        }
    }
}

impl fmt::Debug for Gtpv2cErrorResponsePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Gtpv2cErrorResponsePlan")
            .field("kind", &self.kind())
            .field("message_type", &self.message_type())
            .field("sequence_number", &self.sequence_number())
            .field("cause", &self.cause())
            .field("offending_ie", &self.offending_ie())
            .field("uses_zero_teid", &self.uses_zero_teid())
            .field("input_len", &self.input_len)
            .field("planned_output_len", &self.planned_output_len())
            .finish()
    }
}

impl Encode for Gtpv2cErrorResponsePlan {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        ctx.check_capacity(self.planned_output_len())?;
        self.to_owned_message(ctx)?.encode(dst, ctx)
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        ctx.check_capacity(self.planned_output_len())?;
        Ok(self.planned_output_len())
    }
}

fn encode_plan_ies(ies: &[TypedIe<'_>], ctx: EncodeContext) -> Result<Bytes, EncodeError> {
    let mut encoded = BytesMut::new();
    encode_typed_ie_sequence(ies, &mut encoded, ctx)?;
    Ok(encoded.freeze())
}

/// Planner result: either a standards-required discard or a typed response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gtpv2cErrorResponseDecision {
    /// No response bytes may be produced.
    Unanswerable(Gtpv2cUnanswerableReason),
    /// A bounded typed response may be encoded and sent subject to product policy.
    Respond(Gtpv2cErrorResponsePlan),
}

/// Redaction-safe amplification accounting metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtpv2cAmplificationMetadata {
    /// Received input datagram length.
    pub input_len: usize,
    /// Exact planned response length.
    pub planned_output_len: usize,
    /// Whether an ordinary response uses TEID zero.
    pub uses_zero_teid: bool,
}

/// Caller-owned metadata for a received datagram.
///
/// Endpoint values are never parsed from the GTP payload and are redacted from
/// `Debug`. `source` is the peer that sent the request; `local_destination` is
/// the local address that received it.
#[derive(Clone, PartialEq, Eq)]
pub struct Gtpv2cReceivedPeerMetadata<T> {
    source: T,
    local_destination: T,
}

impl<T> Gtpv2cReceivedPeerMetadata<T> {
    /// Construct caller-supplied receive metadata.
    pub const fn new(source: T, local_destination: T) -> Self {
        Self {
            source,
            local_destination,
        }
    }

    /// Consume the receive metadata and reverse it for reply sending.
    #[must_use]
    pub fn into_send_tuple(self) -> Gtpv2cSendTuple<T> {
        Gtpv2cSendTuple {
            source: self.local_destination,
            destination: self.source,
        }
    }
}

impl<T> fmt::Debug for Gtpv2cReceivedPeerMetadata<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Gtpv2cReceivedPeerMetadata")
            .field("source", &"<redacted>")
            .field("local_destination", &"<redacted>")
            .finish()
    }
}

/// Caller-owned source/destination tuple for sending a planned response.
#[derive(Clone, PartialEq, Eq)]
pub struct Gtpv2cSendTuple<T> {
    source: T,
    destination: T,
}

impl<T> Gtpv2cSendTuple<T> {
    /// Local source endpoint selected from received destination metadata.
    #[must_use]
    pub const fn source(&self) -> &T {
        &self.source
    }

    /// Remote destination endpoint selected from received source metadata.
    #[must_use]
    pub const fn destination(&self) -> &T {
        &self.destination
    }

    /// Consume the tuple into `(source, destination)`.
    #[must_use]
    pub fn into_parts(self) -> (T, T) {
        (self.source, self.destination)
    }
}

impl<T> fmt::Debug for Gtpv2cSendTuple<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Gtpv2cSendTuple")
            .field("source", &"<redacted>")
            .field("destination", &"<redacted>")
            .finish()
    }
}

/// A typed response plan paired with a caller-supplied reversed send tuple.
#[derive(Clone, PartialEq, Eq)]
pub struct Gtpv2cPlannedSend<T> {
    /// Protocol response plan.
    pub plan: Gtpv2cErrorResponsePlan,
    /// Reversed source/destination metadata for transport sending.
    pub send_tuple: Gtpv2cSendTuple<T>,
}

impl<T> fmt::Debug for Gtpv2cPlannedSend<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Gtpv2cPlannedSend")
            .field("plan", &self.plan)
            .field("send_tuple", &self.send_tuple)
            .finish()
    }
}
