//! IKEv2 request exchange sequencing and responder-SPI binding helper.
//!
//! @spec IETF RFC7296 2.1, 2.2, 3.1
//! @req REQ-IETF-RFC7296-EXCHANGE-STATE-001

use std::{collections::BTreeSet, error::Error, fmt};

use crate::{
    header::{
        Header, EXCHANGE_TYPE_CREATE_CHILD_SA, EXCHANGE_TYPE_IKE_AUTH, EXCHANGE_TYPE_IKE_SA_INIT,
        EXCHANGE_TYPE_INFORMATIONAL,
    },
    message::Message,
};

/// Maximum number of recent request keys retained for retransmission detection.
///
/// IKEv2 permits only one in-flight request per direction, so this window is a
/// defensive cap for long-lived trackers rather than a protocol throughput
/// limit.
pub const IKEV2_EXCHANGE_RETRANSMISSION_WINDOW: usize = 64;

/// Redaction-safe responder SPI value used for exchange-state binding.
///
/// The raw value is available to callers that own IKE SA state, but `Debug`
/// intentionally reports only whether a non-zero value is present.
///
/// @spec IETF RFC7296 3.1
/// @req REQ-IETF-RFC7296-EXCHANGE-STATE-SPI-001
/// @conformance boundary-only
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ikev2ResponderSpi(u64);

impl Ikev2ResponderSpi {
    /// Construct a responder SPI wrapper.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the raw responder SPI value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Return true when this is the zero responder SPI used before binding.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Debug for Ikev2ResponderSpi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2ResponderSpi")
            .field("present", &(!self.is_zero()))
            .finish()
    }
}

/// IKEv2 exchange types tracked by the request-state helper.
///
/// @spec IETF RFC7296 3.1
/// @req REQ-IETF-RFC7296-EXCHANGE-STATE-KIND-001
/// @conformance boundary-only
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ikev2ExchangeKind {
    /// IKE_SA_INIT exchange.
    IkeSaInit,
    /// IKE_AUTH exchange.
    IkeAuth,
    /// CREATE_CHILD_SA exchange.
    CreateChildSa,
    /// INFORMATIONAL exchange.
    Informational,
}

impl Ikev2ExchangeKind {
    /// Convert a decoded IKEv2 exchange type value to a tracked kind.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            EXCHANGE_TYPE_IKE_SA_INIT => Some(Self::IkeSaInit),
            EXCHANGE_TYPE_IKE_AUTH => Some(Self::IkeAuth),
            EXCHANGE_TYPE_CREATE_CHILD_SA => Some(Self::CreateChildSa),
            EXCHANGE_TYPE_INFORMATIONAL => Some(Self::Informational),
            _ => None,
        }
    }

    /// Return the wire exchange type value.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::IkeSaInit => EXCHANGE_TYPE_IKE_SA_INIT,
            Self::IkeAuth => EXCHANGE_TYPE_IKE_AUTH,
            Self::CreateChildSa => EXCHANGE_TYPE_CREATE_CHILD_SA,
            Self::Informational => EXCHANGE_TYPE_INFORMATIONAL,
        }
    }

    /// Stable machine-readable exchange name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IkeSaInit => "ike_sa_init",
            Self::IkeAuth => "ike_auth",
            Self::CreateChildSa => "create_child_sa",
            Self::Informational => "informational",
        }
    }
}

impl From<Ikev2ExchangeKind> for u8 {
    fn from(value: Ikev2ExchangeKind) -> Self {
        value.as_u8()
    }
}

/// One locally initiated IKEv2 request allocation.
///
/// The value is redaction-safe and contains only the exchange kind and Message
/// ID needed for header construction and response matching.
///
/// @spec IETF RFC7296 2.3
/// @conformance boundary-only
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2InitiatorMessageIdAllocation {
    /// Exchange kind for the locally initiated request.
    pub exchange: Ikev2ExchangeKind,
    /// Message ID assigned to the locally initiated request.
    pub message_id: u32,
}

/// Error returned by the initiator Message-ID window helper.
///
/// @spec IETF RFC7296 2.3
/// @conformance boundary-only
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2InitiatorMessageIdError {
    /// The exchange type is not one of the tracked IKEv2 exchanges.
    UnsupportedExchangeType,
    /// A request is already outstanding in this direction.
    RequestOutstanding,
    /// The next Message ID cannot be safely allocated.
    MessageIdExhausted,
    /// A response was observed while no local request was outstanding.
    NoOutstandingRequest,
    /// The supplied response header did not carry the response flag.
    ResponseFlagMissing,
    /// The response exchange type did not match the outstanding request.
    ResponseExchangeMismatch,
    /// The response Message ID did not match the outstanding request.
    ResponseMessageIdMismatch,
}

impl Ikev2InitiatorMessageIdError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedExchangeType => "initiator_message_id_unsupported_exchange_type",
            Self::RequestOutstanding => "initiator_message_id_request_outstanding",
            Self::MessageIdExhausted => "initiator_message_id_exhausted",
            Self::NoOutstandingRequest => "initiator_message_id_no_outstanding_request",
            Self::ResponseFlagMissing => "initiator_message_id_response_flag_missing",
            Self::ResponseExchangeMismatch => "initiator_message_id_response_exchange_mismatch",
            Self::ResponseMessageIdMismatch => "initiator_message_id_response_id_mismatch",
        }
    }
}

impl fmt::Display for Ikev2InitiatorMessageIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2InitiatorMessageIdError {}

/// Snapshot of an initiator Message-ID window helper.
///
/// @spec IETF RFC7296 2.3
/// @conformance boundary-only
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2InitiatorMessageIdSnapshot {
    /// Next Message ID that will be assigned when there is no outstanding request.
    pub next_message_id: u32,
    /// Currently outstanding locally initiated request, if any.
    pub outstanding: Option<Ikev2InitiatorMessageIdAllocation>,
}

/// Initiator-side Message-ID allocator and single-request window helper.
///
/// This helper tracks only the local request direction for an established IKE
/// SA. It allocates one Message ID at a time, rejects a second outstanding
/// request, and clears the outstanding slot only when the matching response is
/// observed. Retransmission timers, timeout policy, and IKE SA teardown remain
/// product-owned.
///
/// @spec IETF RFC7296 2.3
/// @conformance boundary-only
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ikev2InitiatorMessageIdWindow {
    next_message_id: u32,
    outstanding: Option<Ikev2InitiatorMessageIdAllocation>,
}

impl Ikev2InitiatorMessageIdWindow {
    /// Create a window with the next Message ID set to zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a window with a caller-supplied next Message ID.
    pub const fn with_next_message_id(next_message_id: u32) -> Self {
        Self {
            next_message_id,
            outstanding: None,
        }
    }

    /// Return the next Message ID that will be assigned.
    pub const fn next_message_id(&self) -> u32 {
        self.next_message_id
    }

    /// Return the currently outstanding allocation, if present.
    pub const fn outstanding(&self) -> Option<Ikev2InitiatorMessageIdAllocation> {
        self.outstanding
    }

    /// Return a redaction-safe snapshot.
    pub const fn snapshot(&self) -> Ikev2InitiatorMessageIdSnapshot {
        Ikev2InitiatorMessageIdSnapshot {
            next_message_id: self.next_message_id,
            outstanding: self.outstanding,
        }
    }

    /// Allocate the next Message ID for a locally initiated exchange.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2InitiatorMessageIdError`] if a request is already
    /// outstanding or the Message ID counter is exhausted.
    pub fn allocate(
        &mut self,
        exchange: Ikev2ExchangeKind,
    ) -> Result<Ikev2InitiatorMessageIdAllocation, Ikev2InitiatorMessageIdError> {
        if self.outstanding.is_some() {
            return Err(Ikev2InitiatorMessageIdError::RequestOutstanding);
        }
        if self.next_message_id == u32::MAX {
            return Err(Ikev2InitiatorMessageIdError::MessageIdExhausted);
        }

        let allocation = Ikev2InitiatorMessageIdAllocation {
            exchange,
            message_id: self.next_message_id,
        };
        self.outstanding = Some(allocation);
        Ok(allocation)
    }

    /// Match and complete a response by exchange kind and Message ID.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2InitiatorMessageIdError`] when no request is outstanding
    /// or the response metadata does not match the outstanding request.
    pub fn complete_response(
        &mut self,
        exchange: Ikev2ExchangeKind,
        message_id: u32,
    ) -> Result<Ikev2InitiatorMessageIdAllocation, Ikev2InitiatorMessageIdError> {
        let outstanding = self
            .outstanding
            .ok_or(Ikev2InitiatorMessageIdError::NoOutstandingRequest)?;
        if outstanding.exchange != exchange {
            return Err(Ikev2InitiatorMessageIdError::ResponseExchangeMismatch);
        }
        if outstanding.message_id != message_id {
            return Err(Ikev2InitiatorMessageIdError::ResponseMessageIdMismatch);
        }

        self.outstanding = None;
        self.next_message_id = outstanding
            .message_id
            .checked_add(1)
            .ok_or(Ikev2InitiatorMessageIdError::MessageIdExhausted)?;
        Ok(outstanding)
    }

    /// Match and complete a decoded IKEv2 response header.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2InitiatorMessageIdError`] if the header is not a
    /// response, has an unsupported exchange type, or does not match the
    /// outstanding request.
    pub fn complete_response_header(
        &mut self,
        header: &Header,
    ) -> Result<Ikev2InitiatorMessageIdAllocation, Ikev2InitiatorMessageIdError> {
        if !header.flags.response() {
            return Err(Ikev2InitiatorMessageIdError::ResponseFlagMissing);
        }
        let exchange = Ikev2ExchangeKind::from_u8(header.exchange_type)
            .ok_or(Ikev2InitiatorMessageIdError::UnsupportedExchangeType)?;
        self.complete_response(exchange, header.message_id)
    }

    /// Match and complete a decoded IKEv2 response message.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2InitiatorMessageIdError`] when the response message does
    /// not match the outstanding request.
    pub fn complete_response_message(
        &mut self,
        message: &Message<'_>,
    ) -> Result<Ikev2InitiatorMessageIdAllocation, Ikev2InitiatorMessageIdError> {
        self.complete_response_header(&message.header)
    }
}

/// Redaction-safe key for identifying same-request retransmissions.
///
/// @spec IETF RFC7296 2.1, 2.2
/// @req REQ-IETF-RFC7296-EXCHANGE-STATE-KEY-001
/// @conformance boundary-only
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ikev2ExchangeRequestKey {
    /// IKEv2 request exchange kind.
    pub exchange: Ikev2ExchangeKind,
    /// IKEv2 request Message ID.
    pub message_id: u32,
    /// Responder SPI carried by the request.
    pub responder_spi: Ikev2ResponderSpi,
}

impl fmt::Debug for Ikev2ExchangeRequestKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2ExchangeRequestKey")
            .field("exchange", &self.exchange)
            .field("message_id", &self.message_id)
            .field("responder_spi", &self.responder_spi)
            .finish()
    }
}

/// Decoded IKEv2 request observation accepted by the exchange-state helper.
///
/// @spec IETF RFC7296 2.1, 2.2, 3.1
/// @req REQ-IETF-RFC7296-EXCHANGE-STATE-REQUEST-001
/// @conformance boundary-only
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2ExchangeRequest {
    /// IKEv2 request exchange kind.
    pub exchange: Ikev2ExchangeKind,
    /// IKEv2 request Message ID.
    pub message_id: u32,
    /// Responder SPI carried by the request.
    pub responder_spi: Ikev2ResponderSpi,
}

impl Ikev2ExchangeRequest {
    /// Build a request observation from a decoded IKEv2 header.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2ExchangeInvalidReason`] when the header is a response or
    /// has an exchange type outside the helper's tracked request set.
    pub fn from_header(header: &Header) -> Result<Self, Ikev2ExchangeInvalidReason> {
        if header.flags.response() {
            return Err(Ikev2ExchangeInvalidReason::ResponseFlagSet);
        }
        let exchange = Ikev2ExchangeKind::from_u8(header.exchange_type)
            .ok_or(Ikev2ExchangeInvalidReason::UnsupportedExchangeType)?;
        Ok(Self {
            exchange,
            message_id: header.message_id,
            responder_spi: Ikev2ResponderSpi::new(header.responder_spi),
        })
    }

    fn key(self) -> Ikev2ExchangeRequestKey {
        Ikev2ExchangeRequestKey {
            exchange: self.exchange,
            message_id: self.message_id,
            responder_spi: self.responder_spi,
        }
    }
}

/// Stable exchange-state decision produced for one request observation.
///
/// @spec IETF RFC7296 2.1, 2.2
/// @req REQ-IETF-RFC7296-EXCHANGE-STATE-DECISION-001
/// @conformance boundary-only
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2ExchangeDecision {
    /// First observation of a valid request that did not newly bind responder SPI.
    NewRequest,
    /// Exact same request key has already been observed and is idempotent.
    Retransmission,
    /// First valid post-SA-init request bound the responder SPI.
    ResponderSpiBound,
    /// A post-bind request attempted to use a different responder SPI.
    ResponderSpiMismatch,
    /// Request ordering or structural request metadata is invalid.
    InvalidSequence,
}

impl Ikev2ExchangeDecision {
    /// Stable machine-readable decision name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NewRequest => "new_request",
            Self::Retransmission => "retransmission",
            Self::ResponderSpiBound => "responder_spi_bound",
            Self::ResponderSpiMismatch => "responder_spi_mismatch",
            Self::InvalidSequence => "invalid_sequence",
        }
    }
}

/// Stable invalid-sequence reason.
///
/// @spec IETF RFC7296 2.1, 2.2, 3.1
/// @req REQ-IETF-RFC7296-EXCHANGE-STATE-INVALID-001
/// @conformance boundary-only
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2ExchangeInvalidReason {
    /// A response header was supplied to the request-state helper.
    ResponseFlagSet,
    /// The exchange type is not one of the tracked IKEv2 request exchanges.
    UnsupportedExchangeType,
    /// IKE_SA_INIT request Message ID was not zero.
    SaInitMessageIdNonZero,
    /// IKE_SA_INIT request carried a non-zero responder SPI.
    SaInitResponderSpiNonZero,
    /// A post-SA-init request arrived before IKE_SA_INIT was observed.
    PostSaInitBeforeSaInit,
    /// The first post-SA-init request did not use Message ID 1.
    FirstPostSaInitMessageIdNotOne,
    /// A Message ID was reused for a different request key.
    MessageIdReusedForDifferentRequest,
    /// A Message ID moved backwards.
    MessageIdWentBackwards,
    /// A Message ID skipped at least one request number.
    MessageIdGap,
    /// A post-SA-init request did not carry a non-zero responder SPI.
    ResponderSpiMissing,
    /// A post-bind request used a different responder SPI.
    ResponderSpiMismatch,
    /// The tracker was already in a terminal invalid state.
    AlreadyInvalid,
}

impl Ikev2ExchangeInvalidReason {
    /// Stable machine-readable invalid reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResponseFlagSet => "response_flag_set",
            Self::UnsupportedExchangeType => "unsupported_exchange_type",
            Self::SaInitMessageIdNonZero => "sa_init_message_id_non_zero",
            Self::SaInitResponderSpiNonZero => "sa_init_responder_spi_non_zero",
            Self::PostSaInitBeforeSaInit => "post_sa_init_before_sa_init",
            Self::FirstPostSaInitMessageIdNotOne => "first_post_sa_init_message_id_not_one",
            Self::MessageIdReusedForDifferentRequest => "message_id_reused_for_different_request",
            Self::MessageIdWentBackwards => "message_id_went_backwards",
            Self::MessageIdGap => "message_id_gap",
            Self::ResponderSpiMissing => "responder_spi_missing",
            Self::ResponderSpiMismatch => "responder_spi_mismatch",
            Self::AlreadyInvalid => "already_invalid",
        }
    }
}

/// Redaction-safe IKEv2 exchange boundary state.
///
/// This is not an established IKE SA claim. It tracks only request ordering
/// and responder-SPI binding facts visible from decoded IKE headers.
///
/// @spec IETF RFC7296 2.1, 2.2
/// @req REQ-IETF-RFC7296-EXCHANGE-STATE-STATE-001
/// @conformance boundary-only
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Ikev2ExchangeBoundaryState {
    /// No IKE_SA_INIT request has been observed.
    #[default]
    NoSaInit,
    /// IKE_SA_INIT was observed and the exchange is half-open.
    SaInitObserved,
    /// A post-SA-init request has bound a non-zero responder SPI.
    ResponderSpiBound,
    /// Request order, Message ID sequence, or responder-SPI binding is invalid.
    SequenceInvalid,
}

impl Ikev2ExchangeBoundaryState {
    /// Stable machine-readable state name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoSaInit => "no_sa_init",
            Self::SaInitObserved => "sa_init_observed",
            Self::ResponderSpiBound => "responder_spi_bound",
            Self::SequenceInvalid => "sequence_invalid",
        }
    }
}

/// Redaction-safe projection after observing an IKEv2 request.
///
/// @spec IETF RFC7296 2.1, 2.2
/// @req REQ-IETF-RFC7296-EXCHANGE-STATE-PROJECTION-001
/// @conformance boundary-only
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2ExchangeProjection {
    /// Primary decision for the observation.
    pub decision: Ikev2ExchangeDecision,
    /// Current boundary state after the observation.
    pub state: Ikev2ExchangeBoundaryState,
    /// True when the tracker remains sequence-valid.
    pub sequence_valid: bool,
    /// True when this observation was an exact same-request retransmission.
    pub retransmission: bool,
    /// True when a non-zero responder SPI is currently bound.
    pub responder_spi_bound: bool,
    /// True when this observation attempted responder-SPI rebinding.
    pub responder_spi_mismatch: bool,
    /// Highest request Message ID accepted or recorded for gap evidence.
    pub highest_message_id: Option<u32>,
    /// Number of unique request keys observed by this tracker.
    pub observed_request_count: usize,
    /// Total exact same-request retransmissions observed by this tracker.
    pub retransmission_count: usize,
    /// Total invalid-sequence observations recorded by this tracker.
    pub invalid_sequence_count: usize,
    /// Total responder-SPI mismatches recorded by this tracker.
    pub responder_spi_mismatch_count: usize,
    /// Stable invalid reason when the decision is invalid.
    pub invalid_reason: Option<Ikev2ExchangeInvalidReason>,
}

impl fmt::Debug for Ikev2ExchangeProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2ExchangeProjection")
            .field("decision", &self.decision)
            .field("state", &self.state)
            .field("sequence_valid", &self.sequence_valid)
            .field("retransmission", &self.retransmission)
            .field("responder_spi_bound", &self.responder_spi_bound)
            .field("responder_spi_mismatch", &self.responder_spi_mismatch)
            .field("highest_message_id", &self.highest_message_id)
            .field("observed_request_count", &self.observed_request_count)
            .field("retransmission_count", &self.retransmission_count)
            .field("invalid_sequence_count", &self.invalid_sequence_count)
            .field(
                "responder_spi_mismatch_count",
                &self.responder_spi_mismatch_count,
            )
            .field("invalid_reason", &self.invalid_reason)
            .finish()
    }
}

/// Redaction-safe snapshot of an IKEv2 exchange tracker.
///
/// @spec IETF RFC7296 2.1, 2.2
/// @req REQ-IETF-RFC7296-EXCHANGE-STATE-SNAPSHOT-001
/// @conformance boundary-only
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2ExchangeSnapshot {
    /// Current boundary state.
    pub state: Ikev2ExchangeBoundaryState,
    /// Bound responder SPI, when a post-SA-init request has bound one.
    pub responder_spi: Option<Ikev2ResponderSpi>,
    /// Highest request Message ID accepted or recorded for gap evidence.
    pub highest_message_id: Option<u32>,
    /// Number of unique request keys observed by this tracker.
    pub observed_request_count: usize,
    /// Total exact same-request retransmissions observed by this tracker.
    pub retransmission_count: usize,
    /// Total invalid-sequence observations recorded by this tracker.
    pub invalid_sequence_count: usize,
    /// Total responder-SPI mismatches recorded by this tracker.
    pub responder_spi_mismatch_count: usize,
    /// Last decision produced by this tracker.
    pub last_decision: Option<Ikev2ExchangeDecision>,
    /// Last invalid reason produced by this tracker.
    pub last_invalid_reason: Option<Ikev2ExchangeInvalidReason>,
}

/// Transport-neutral IKEv2 request exchange-state tracker.
///
/// The tracker consumes decoded IKEv2 request headers. It does not authenticate
/// payloads, manage crypto transforms, install Child SAs, or choose product
/// routing policy.
///
/// @spec IETF RFC7296 2.1, 2.2, 3.1
/// @req REQ-IETF-RFC7296-EXCHANGE-STATE-TRACKER-001
/// @conformance boundary-only
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ikev2ExchangeTracker {
    state: Ikev2ExchangeBoundaryState,
    sa_init_observed: bool,
    responder_spi: Option<Ikev2ResponderSpi>,
    highest_message_id: Option<u32>,
    observed_requests: BTreeSet<Ikev2ExchangeRequestKey>,
    retransmission_count: usize,
    invalid_sequence_count: usize,
    responder_spi_mismatch_count: usize,
    last_decision: Option<Ikev2ExchangeDecision>,
    last_invalid_reason: Option<Ikev2ExchangeInvalidReason>,
}

impl Ikev2ExchangeTracker {
    /// Create an empty exchange tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the current boundary state.
    pub const fn state(&self) -> Ikev2ExchangeBoundaryState {
        self.state
    }

    /// Return the bound responder SPI, when present.
    pub const fn responder_spi(&self) -> Option<Ikev2ResponderSpi> {
        self.responder_spi
    }

    /// Observe a decoded IKEv2 message header.
    pub fn observe_header(&mut self, header: &Header) -> Ikev2ExchangeProjection {
        match Ikev2ExchangeRequest::from_header(header) {
            Ok(request) => self.observe_request(request),
            Err(reason) => self.mark_invalid(Ikev2ExchangeDecision::InvalidSequence, reason),
        }
    }

    /// Observe a decoded IKEv2 message.
    pub fn observe_message(&mut self, message: &Message<'_>) -> Ikev2ExchangeProjection {
        self.observe_header(&message.header)
    }

    /// Observe a pre-built IKEv2 request.
    pub fn observe_request(&mut self, request: Ikev2ExchangeRequest) -> Ikev2ExchangeProjection {
        if self.state == Ikev2ExchangeBoundaryState::SequenceInvalid {
            return self.mark_invalid(
                Ikev2ExchangeDecision::InvalidSequence,
                Ikev2ExchangeInvalidReason::AlreadyInvalid,
            );
        }

        if !self.observed_requests.insert(request.key()) {
            self.retransmission_count = self.retransmission_count.saturating_add(1);
            return self.project(Ikev2ExchangeDecision::Retransmission, None);
        }
        self.bound_observed_requests();

        match request.exchange {
            Ikev2ExchangeKind::IkeSaInit => self.observe_sa_init(request),
            Ikev2ExchangeKind::IkeAuth
            | Ikev2ExchangeKind::CreateChildSa
            | Ikev2ExchangeKind::Informational => self.observe_post_sa_init(request),
        }
    }

    fn bound_observed_requests(&mut self) {
        while self.observed_requests.len() > IKEV2_EXCHANGE_RETRANSMISSION_WINDOW {
            let Some(oldest) = self.observed_requests.iter().next().copied() else {
                break;
            };
            self.observed_requests.remove(&oldest);
        }
    }

    /// Return a redaction-safe snapshot of the tracker.
    pub fn snapshot(&self) -> Ikev2ExchangeSnapshot {
        Ikev2ExchangeSnapshot {
            state: self.state,
            responder_spi: self.responder_spi,
            highest_message_id: self.highest_message_id,
            observed_request_count: self.observed_requests.len(),
            retransmission_count: self.retransmission_count,
            invalid_sequence_count: self.invalid_sequence_count,
            responder_spi_mismatch_count: self.responder_spi_mismatch_count,
            last_decision: self.last_decision,
            last_invalid_reason: self.last_invalid_reason,
        }
    }

    fn observe_sa_init(&mut self, request: Ikev2ExchangeRequest) -> Ikev2ExchangeProjection {
        if request.message_id != 0 {
            return self.mark_invalid(
                Ikev2ExchangeDecision::InvalidSequence,
                Ikev2ExchangeInvalidReason::SaInitMessageIdNonZero,
            );
        }
        if !request.responder_spi.is_zero() {
            return self.mark_invalid(
                Ikev2ExchangeDecision::InvalidSequence,
                Ikev2ExchangeInvalidReason::SaInitResponderSpiNonZero,
            );
        }

        self.sa_init_observed = true;
        self.highest_message_id = Some(0);
        self.set_state_if_less_specific(Ikev2ExchangeBoundaryState::SaInitObserved);
        self.project(Ikev2ExchangeDecision::NewRequest, None)
    }

    fn observe_post_sa_init(&mut self, request: Ikev2ExchangeRequest) -> Ikev2ExchangeProjection {
        if !self.sa_init_observed {
            return self.mark_invalid(
                Ikev2ExchangeDecision::InvalidSequence,
                Ikev2ExchangeInvalidReason::PostSaInitBeforeSaInit,
            );
        }
        if request.responder_spi.is_zero() {
            return self.mark_invalid(
                Ikev2ExchangeDecision::InvalidSequence,
                Ikev2ExchangeInvalidReason::ResponderSpiMissing,
            );
        }

        if let Some(reason) = self.sequence_error(request.message_id) {
            if matches!(reason, Ikev2ExchangeInvalidReason::MessageIdGap) {
                self.highest_message_id = Some(request.message_id);
            }
            return self.mark_invalid(Ikev2ExchangeDecision::InvalidSequence, reason);
        }

        let decision = match self.responder_spi {
            Some(bound) if bound != request.responder_spi => {
                self.responder_spi_mismatch_count =
                    self.responder_spi_mismatch_count.saturating_add(1);
                return self.mark_invalid(
                    Ikev2ExchangeDecision::ResponderSpiMismatch,
                    Ikev2ExchangeInvalidReason::ResponderSpiMismatch,
                );
            }
            Some(_) => Ikev2ExchangeDecision::NewRequest,
            None => {
                self.responder_spi = Some(request.responder_spi);
                Ikev2ExchangeDecision::ResponderSpiBound
            }
        };

        self.highest_message_id = Some(request.message_id);
        self.set_state_if_less_specific(Ikev2ExchangeBoundaryState::ResponderSpiBound);
        self.project(decision, None)
    }

    fn sequence_error(&self, message_id: u32) -> Option<Ikev2ExchangeInvalidReason> {
        match self.highest_message_id {
            Some(highest) if message_id < highest => {
                Some(Ikev2ExchangeInvalidReason::MessageIdWentBackwards)
            }
            Some(highest) if message_id == highest => {
                Some(Ikev2ExchangeInvalidReason::MessageIdReusedForDifferentRequest)
            }
            Some(highest) if message_id > highest.saturating_add(1) => {
                Some(Ikev2ExchangeInvalidReason::MessageIdGap)
            }
            Some(_) => None,
            None if message_id != 1 => {
                Some(Ikev2ExchangeInvalidReason::FirstPostSaInitMessageIdNotOne)
            }
            None => None,
        }
    }

    fn mark_invalid(
        &mut self,
        decision: Ikev2ExchangeDecision,
        reason: Ikev2ExchangeInvalidReason,
    ) -> Ikev2ExchangeProjection {
        self.invalid_sequence_count = self.invalid_sequence_count.saturating_add(1);
        self.state = Ikev2ExchangeBoundaryState::SequenceInvalid;
        self.project(decision, Some(reason))
    }

    fn set_state_if_less_specific(&mut self, state: Ikev2ExchangeBoundaryState) {
        if self.state == Ikev2ExchangeBoundaryState::SequenceInvalid {
            return;
        }
        if state_rank(state) > state_rank(self.state) {
            self.state = state;
        }
    }

    fn project(
        &mut self,
        decision: Ikev2ExchangeDecision,
        invalid_reason: Option<Ikev2ExchangeInvalidReason>,
    ) -> Ikev2ExchangeProjection {
        self.last_decision = Some(decision);
        self.last_invalid_reason = invalid_reason;
        Ikev2ExchangeProjection {
            decision,
            state: self.state,
            sequence_valid: self.state != Ikev2ExchangeBoundaryState::SequenceInvalid,
            retransmission: decision == Ikev2ExchangeDecision::Retransmission,
            responder_spi_bound: self.responder_spi.is_some(),
            responder_spi_mismatch: decision == Ikev2ExchangeDecision::ResponderSpiMismatch,
            highest_message_id: self.highest_message_id,
            observed_request_count: self.observed_requests.len(),
            retransmission_count: self.retransmission_count,
            invalid_sequence_count: self.invalid_sequence_count,
            responder_spi_mismatch_count: self.responder_spi_mismatch_count,
            invalid_reason,
        }
    }
}

const fn state_rank(state: Ikev2ExchangeBoundaryState) -> u8 {
    match state {
        Ikev2ExchangeBoundaryState::NoSaInit => 0,
        Ikev2ExchangeBoundaryState::SaInitObserved => 1,
        Ikev2ExchangeBoundaryState::ResponderSpiBound => 2,
        Ikev2ExchangeBoundaryState::SequenceInvalid => 3,
    }
}
