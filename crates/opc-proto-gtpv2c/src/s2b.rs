//! S2b-oriented GTPv2-C message views.
//!
//! The S2b surface in this crate is intentionally a typed subset: it decodes
//! Echo plus Create/Modify/Delete/Update Session-oriented GTPv2-C messages,
//! exposes mandatory S2b IE examples through typed values, and keeps
//! unsupported IEs as raw-preserving fallbacks. It is not a full ePDG or PGW
//! control-plane implementation.
//!
//! @spec 3GPP TS29274 R18 S2b procedure use
//! @req REQ-3GPP-TS29274-R18-S2B-001

use core::fmt;

use bytes::BytesMut;
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, Encode, EncodeContext,
    EncodeError, EncodeErrorCode, SpecRef, ValidationLevel,
};

use crate::header::Header;
pub use crate::header::MessageType;
use crate::ie::{
    decode_typed_ie_sequence, CauseValue, EpsBearerId, FullyQualifiedTeid, TypedIe, TypedIeValue,
    IE_TYPE_APN, IE_TYPE_BEARER_CONTEXT, IE_TYPE_CAUSE, IE_TYPE_EBI, IE_TYPE_F_TEID, IE_TYPE_IMSI,
    IE_TYPE_PAA, IE_TYPE_PDN_TYPE, IE_TYPE_RAT_TYPE, IE_TYPE_RECOVERY, IE_TYPE_SELECTION_MODE,
    IE_TYPE_SERVING_NETWORK,
};
use crate::Message;

/// Echo Request message type.
pub const ECHO_REQUEST: u8 = 1;

/// Echo Response message type.
pub const ECHO_RESPONSE: u8 = 2;

/// Create Session Request message type.
pub const CREATE_SESSION_REQUEST: u8 = 32;

/// Create Session Response message type.
pub const CREATE_SESSION_RESPONSE: u8 = 33;

/// Modify Bearer Request message type used by the S2b Modify Session view.
pub const MODIFY_BEARER_REQUEST: u8 = 34;

/// Modify Bearer Response message type used by the S2b Modify Session view.
pub const MODIFY_BEARER_RESPONSE: u8 = 35;

/// Delete Session Request message type.
pub const DELETE_SESSION_REQUEST: u8 = 36;

/// Delete Session Response message type.
pub const DELETE_SESSION_RESPONSE: u8 = 37;

/// Update Bearer Request message type used by the S2b Update Session view.
pub const UPDATE_BEARER_REQUEST: u8 = 97;

/// Update Bearer Response message type used by the S2b Update Session view.
pub const UPDATE_BEARER_RESPONSE: u8 = 98;

/// Accepted Create Session Response projection.
///
/// This projection is intentionally strict: it is only returned for Cause 16
/// (`RequestAccepted`) and includes the accepted-bearer fields that products
/// need to derive an established bearer context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSessionAcceptedResponseSummary {
    /// TEID carried in the Create Session Response common header.
    pub response_teid: u32,
    /// GTPv2-C sequence number from the Create Session Response header.
    pub sequence_number: u32,
    /// Cause value from the Cause IE.
    pub cause: CauseValue,
    /// Top-level Sender F-TEID at instance 0.
    pub sender_f_teid: FullyQualifiedTeid,
    /// Linked bearer EBI from the first Bearer Context IE.
    pub bearer_ebi: EpsBearerId,
}

/// Rejected Create Session Response projection.
///
/// Rejected responses do not require accepted-bearer-only fields such as
/// Sender F-TEID or Bearer Context EBI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSessionRejectedResponseSummary {
    /// TEID carried in the Create Session Response common header.
    pub response_teid: u32,
    /// GTPv2-C sequence number from the Create Session Response header.
    pub sequence_number: u32,
    /// Cause value from the Cause IE.
    pub cause: CauseValue,
}

/// Create Session Response projection split by bearer-establishment outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateSessionResponseSummary {
    /// Cause 16 response with accepted-bearer fields present.
    Accepted(CreateSessionAcceptedResponseSummary),
    /// Non-Cause-16 response with Cause, response TEID, and sequence only.
    Rejected(CreateSessionRejectedResponseSummary),
}

/// Stable redaction-safe error returned while projecting a Create Session Response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateSessionResponseSummaryError {
    /// Message bytes could not be decoded into a single typed GTPv2-C response.
    MalformedResponse,
    /// Decoded message was not an S2b Create Session Response.
    NotCreateSessionResponse,
    /// Create Session Response did not include a Cause IE.
    MissingCause,
    /// Create Session Response did not carry a response-header TEID.
    MissingResponseTeid,
    /// Accepted Create Session Response did not include Sender F-TEID instance 0.
    AcceptedResponseMissingSenderFTeid,
    /// Accepted Create Session Response did not include a Bearer Context IE.
    AcceptedResponseMissingBearerContext,
    /// Accepted Create Session Response Bearer Context did not include an EBI IE.
    AcceptedResponseMissingBearerEbi,
}

impl CreateSessionResponseSummaryError {
    /// Return the stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedResponse => "s2b_create_session_response_malformed",
            Self::NotCreateSessionResponse => {
                "s2b_create_session_response_not_create_session_response"
            }
            Self::MissingCause => "s2b_create_session_response_missing_cause",
            Self::MissingResponseTeid => "s2b_create_session_response_missing_teid",
            Self::AcceptedResponseMissingSenderFTeid => {
                "s2b_create_session_response_missing_sender_f_teid"
            }
            Self::AcceptedResponseMissingBearerContext => {
                "s2b_create_session_response_missing_bearer_context"
            }
            Self::AcceptedResponseMissingBearerEbi => {
                "s2b_create_session_response_missing_bearer_ebi"
            }
        }
    }
}

impl fmt::Display for CreateSessionResponseSummaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for CreateSessionResponseSummaryError {}

/// Decoded Echo Request/Response evidence used by GTPv2-C peer control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoMessageEvidence {
    /// Echo request/response direction.
    pub direction: MessageDirection,
    /// 24-bit GTPv2-C sequence number.
    pub sequence_number: u32,
    /// Recovery restart counter from the mandatory Recovery IE.
    pub restart_counter: u8,
}

impl EchoMessageEvidence {
    /// Project a typed S2b procedure view into Echo evidence.
    ///
    /// # Errors
    ///
    /// Returns [`EchoMessageEvidenceError`] when the view is not an Echo
    /// message or does not contain a typed Recovery IE.
    pub fn from_view(view: &S2bProcedureMessage<'_>) -> Result<Self, EchoMessageEvidenceError> {
        if view.procedure != Procedure::Echo {
            return Err(EchoMessageEvidenceError::NotEchoMessage);
        }
        let restart_counter = find_recovery_restart_counter(&view.ies)
            .ok_or(EchoMessageEvidenceError::MissingRecovery)?;
        Ok(Self {
            direction: view.direction,
            sequence_number: view.header.sequence_number,
            restart_counter,
        })
    }
}

/// Stable redaction-safe error returned while extracting Echo evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoMessageEvidenceError {
    /// Message bytes could not be decoded into a typed S2b message.
    MalformedMessage,
    /// Message bytes contained trailing data after the decoded message.
    TrailingBytes,
    /// Decoded message was not an Echo Request or Echo Response.
    NotEchoMessage,
    /// Echo message did not contain a typed Recovery IE.
    MissingRecovery,
}

impl EchoMessageEvidenceError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedMessage => "gtpv2c_echo_message_malformed",
            Self::TrailingBytes => "gtpv2c_echo_message_trailing_bytes",
            Self::NotEchoMessage => "gtpv2c_echo_message_not_echo",
            Self::MissingRecovery => "gtpv2c_echo_message_missing_recovery",
        }
    }
}

impl fmt::Display for EchoMessageEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for EchoMessageEvidenceError {}

/// Decode one S2b Echo message and extract Recovery evidence.
///
/// # Errors
///
/// Returns [`EchoMessageEvidenceError`] when bytes are malformed, contain
/// trailing data after the message, decode to another message type, or lack a
/// typed Recovery IE.
pub fn decode_echo_message_evidence(
    input: &[u8],
    ctx: DecodeContext,
) -> Result<EchoMessageEvidence, EchoMessageEvidenceError> {
    let (tail, message) =
        S2bMessage::decode(input, ctx).map_err(|_| EchoMessageEvidenceError::MalformedMessage)?;
    if !tail.is_empty() {
        return Err(EchoMessageEvidenceError::TrailingBytes);
    }
    let view = message
        .as_view()
        .ok_or(EchoMessageEvidenceError::NotEchoMessage)?;
    EchoMessageEvidence::from_view(view)
}

/// Policy for the GTPv2-C Echo peer state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtpv2cEchoPeerPolicy {
    /// Consecutive missing Echo Response threshold. Values below one are
    /// treated as one by the state machine.
    pub missed_response_threshold: usize,
    /// Whether a changed peer Recovery restart counter blocks traffic until
    /// the caller explicitly marks restart reconciliation complete.
    pub require_restart_reconciliation: bool,
}

impl Default for Gtpv2cEchoPeerPolicy {
    fn default() -> Self {
        Self {
            missed_response_threshold: 3,
            require_restart_reconciliation: true,
        }
    }
}

impl Gtpv2cEchoPeerPolicy {
    /// Return a copy with a custom missing-response threshold.
    #[must_use]
    pub fn with_missed_response_threshold(mut self, threshold: usize) -> Self {
        self.missed_response_threshold = threshold.max(1);
        self
    }

    /// Return a copy that treats restart-counter changes as reachable but not
    /// traffic-blocking.
    #[must_use]
    pub const fn without_restart_reconciliation(mut self) -> Self {
        self.require_restart_reconciliation = false;
        self
    }
}

/// Transport-neutral GTPv2-C Echo peer-control state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gtpv2cEchoPeerState {
    /// No Echo evidence has been observed.
    Idle,
    /// Echo Request was sent and Echo Response is pending.
    AwaitingResponse,
    /// Peer is reachable and continuity evidence is safe.
    Reachable,
    /// Peer liveness evidence is weak but has not failed the threshold.
    Degraded,
    /// Peer failed the Echo liveness threshold.
    Failed,
    /// Peer Recovery restart counter changed and reconciliation is required.
    ReconciliationRequired,
}

impl Gtpv2cEchoPeerState {
    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::AwaitingResponse => "awaiting_response",
            Self::Reachable => "reachable",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }
}

/// Transport-neutral GTPv2-C Echo peer-control event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gtpv2cEchoPeerEvent {
    /// Echo Request was sent.
    EchoRequestSent,
    /// Echo Request was received.
    EchoRequestReceived,
    /// Echo Response was accepted.
    EchoResponseAccepted,
    /// Echo Response sequence did not match the outstanding request.
    EchoResponseSequenceMismatch,
    /// Echo Response was missing for the outstanding request.
    EchoResponseMissing,
    /// Peer Recovery restart counter changed.
    PeerRestartObserved,
    /// Caller marked restart reconciliation complete.
    RestartReconciled,
    /// Caller failed the peer explicitly.
    Failure,
}

impl Gtpv2cEchoPeerEvent {
    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EchoRequestSent => "echo_request_sent",
            Self::EchoRequestReceived => "echo_request_received",
            Self::EchoResponseAccepted => "echo_response_accepted",
            Self::EchoResponseSequenceMismatch => "echo_response_sequence_mismatch",
            Self::EchoResponseMissing => "echo_response_missing",
            Self::PeerRestartObserved => "peer_restart_observed",
            Self::RestartReconciled => "restart_reconciled",
            Self::Failure => "failure",
        }
    }
}

/// Stable redaction-safe blocker emitted by the Echo peer helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gtpv2cEchoPeerBlocker {
    /// Echo Response has not arrived for the outstanding request.
    EchoResponsePending,
    /// Echo Response was missing for the outstanding request.
    EchoResponseMissing,
    /// Echo Response sequence did not match the outstanding request.
    EchoResponseSequenceMismatch,
    /// Peer Recovery restart counter changed.
    PeerRestartCounterChanged,
    /// Peer failed the liveness threshold.
    PeerUnreachable,
    /// Caller must reconcile sessions after a peer restart.
    RestartReconciliationRequired,
}

impl Gtpv2cEchoPeerBlocker {
    /// Stable machine-readable blocker code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EchoResponsePending => "gtpv2c_echo_response_pending",
            Self::EchoResponseMissing => "gtpv2c_echo_response_missing",
            Self::EchoResponseSequenceMismatch => "gtpv2c_echo_response_sequence_mismatch",
            Self::PeerRestartCounterChanged => "gtpv2c_peer_restart_counter_changed",
            Self::PeerUnreachable => "gtpv2c_peer_unreachable",
            Self::RestartReconciliationRequired => "gtpv2c_restart_reconciliation_required",
        }
    }
}

/// Redaction-safe readiness projection for one Echo peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtpv2cEchoPeerReadiness {
    /// Current peer-control state.
    pub state: Gtpv2cEchoPeerState,
    /// Whether peer liveness is currently proven.
    pub reachable: bool,
    /// Whether a response is pending.
    pub awaiting_response: bool,
    /// Whether liveness is degraded but not failed.
    pub degraded: bool,
    /// Whether the peer failed the liveness threshold.
    pub failed: bool,
    /// Whether restart reconciliation is required.
    pub restart_reconciliation_required: bool,
    /// Whether product traffic can safely use this peer.
    pub traffic_ready: bool,
    /// Stable blockers in evaluation order.
    pub blockers: Vec<Gtpv2cEchoPeerBlocker>,
}

/// Projection from one Echo observation into peer liveness and continuity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtpv2cEchoPeerProjection {
    /// Whether an Echo Response was observed for the current exchange.
    pub response_observed: bool,
    /// Whether the peer is reachable.
    pub peer_reachable: bool,
    /// Whether the Recovery restart counter changed from the previous value.
    pub restart_counter_changed: bool,
    /// Whether existing session continuity is safe.
    pub continuity_safe: bool,
    /// Last observed peer Recovery restart counter.
    pub restart_counter: Option<u8>,
    /// Current in-flight sequence number, if any.
    pub in_flight_sequence_number: Option<u32>,
    /// Consecutive missed Echo Responses.
    pub missed_responses: usize,
    /// Stable blockers in evaluation order.
    pub blockers: Vec<Gtpv2cEchoPeerBlocker>,
}

/// One emitted transition from the Echo peer helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtpv2cEchoPeerTransition {
    /// Event that caused the transition.
    pub event: Gtpv2cEchoPeerEvent,
    /// State before the event.
    pub previous_state: Gtpv2cEchoPeerState,
    /// State after the event.
    pub state: Gtpv2cEchoPeerState,
    /// Readiness after the event.
    pub readiness: Gtpv2cEchoPeerReadiness,
    /// Observation projection after the event.
    pub projection: Gtpv2cEchoPeerProjection,
}

/// Redaction-safe snapshot of the Echo peer helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtpv2cEchoPeerSnapshot {
    /// Current peer-control state.
    pub state: Gtpv2cEchoPeerState,
    /// Current readiness projection.
    pub readiness: Gtpv2cEchoPeerReadiness,
    /// Last observed peer Recovery restart counter.
    pub last_restart_counter: Option<u8>,
    /// Current in-flight sequence number, if any.
    pub in_flight_sequence_number: Option<u32>,
    /// Echo Requests sent by this helper.
    pub echo_requests_sent: usize,
    /// Echo Requests received by this helper.
    pub echo_requests_received: usize,
    /// Echo Responses accepted by this helper.
    pub echo_responses_observed: usize,
    /// Echo Responses rejected due to sequence mismatch.
    pub echo_response_sequence_mismatches: usize,
    /// Consecutive missed Echo Responses.
    pub missed_responses: usize,
    /// Peer Recovery restart-counter changes observed.
    pub restart_counter_changes: usize,
}

/// GTPv2-C Echo peer state-machine error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gtpv2cEchoPeerError {
    /// Operation is not valid in the current state.
    InvalidTransition {
        /// Operation attempted.
        operation: &'static str,
        /// Current state.
        state: Gtpv2cEchoPeerState,
    },
    /// Echo evidence had the wrong request/response direction.
    UnexpectedDirection {
        /// Expected direction.
        expected: MessageDirection,
        /// Actual direction.
        actual: MessageDirection,
    },
}

impl Gtpv2cEchoPeerError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidTransition { .. } => "gtpv2c_echo_peer_invalid_transition",
            Self::UnexpectedDirection { .. } => "gtpv2c_echo_peer_unexpected_direction",
        }
    }
}

impl fmt::Display for Gtpv2cEchoPeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { operation, state } => write!(
                f,
                "gtpv2c_echo_peer_invalid_transition: operation {operation}, state {}",
                state.as_str()
            ),
            Self::UnexpectedDirection { expected, actual } => write!(
                f,
                "gtpv2c_echo_peer_unexpected_direction: expected {}, actual {}",
                expected.as_str(),
                actual.as_str()
            ),
        }
    }
}

impl std::error::Error for Gtpv2cEchoPeerError {}

/// Transport-neutral GTPv2-C Echo peer-control state machine.
#[derive(Debug, Clone)]
pub struct Gtpv2cEchoPeer {
    policy: Gtpv2cEchoPeerPolicy,
    state: Gtpv2cEchoPeerState,
    last_restart_counter: Option<u8>,
    in_flight_sequence_number: Option<u32>,
    missed_responses: usize,
    echo_requests_sent: usize,
    echo_requests_received: usize,
    echo_responses_observed: usize,
    echo_response_sequence_mismatches: usize,
    restart_counter_changes: usize,
    last_blockers: Vec<Gtpv2cEchoPeerBlocker>,
}

impl Gtpv2cEchoPeer {
    /// Create an Echo peer helper with default policy.
    #[must_use]
    pub fn new() -> Self {
        Self::with_policy(Gtpv2cEchoPeerPolicy::default())
    }

    /// Create an Echo peer helper with explicit policy.
    #[must_use]
    pub fn with_policy(policy: Gtpv2cEchoPeerPolicy) -> Self {
        Self {
            policy,
            state: Gtpv2cEchoPeerState::Idle,
            last_restart_counter: None,
            in_flight_sequence_number: None,
            missed_responses: 0,
            echo_requests_sent: 0,
            echo_requests_received: 0,
            echo_responses_observed: 0,
            echo_response_sequence_mismatches: 0,
            restart_counter_changes: 0,
            last_blockers: Vec::new(),
        }
    }

    /// Return the current state.
    #[must_use]
    pub const fn state(&self) -> Gtpv2cEchoPeerState {
        self.state
    }

    /// Return the peer policy.
    #[must_use]
    pub const fn policy(&self) -> Gtpv2cEchoPeerPolicy {
        self.policy
    }

    /// Mark an Echo Request as sent.
    #[must_use]
    pub fn echo_request_sent(&mut self, sequence_number: u32) -> Gtpv2cEchoPeerTransition {
        let previous = self.state;
        self.echo_requests_sent = self.echo_requests_sent.saturating_add(1);
        self.in_flight_sequence_number = Some(sequence_number);
        self.state = Gtpv2cEchoPeerState::AwaitingResponse;
        self.last_blockers = vec![Gtpv2cEchoPeerBlocker::EchoResponsePending];
        self.transition(Gtpv2cEchoPeerEvent::EchoRequestSent, previous, false, false)
    }

    /// Observe a decoded Echo Request from the peer.
    ///
    /// # Errors
    ///
    /// Returns [`Gtpv2cEchoPeerError`] when the evidence is not an Echo
    /// Request.
    pub fn observe_echo_request(
        &mut self,
        evidence: EchoMessageEvidence,
    ) -> Result<Gtpv2cEchoPeerTransition, Gtpv2cEchoPeerError> {
        if evidence.direction != MessageDirection::Request {
            return Err(Gtpv2cEchoPeerError::UnexpectedDirection {
                expected: MessageDirection::Request,
                actual: evidence.direction,
            });
        }
        let previous = self.state;
        self.echo_requests_received = self.echo_requests_received.saturating_add(1);
        let restart_counter_changed = self.observe_restart_counter(evidence.restart_counter);
        let event = if restart_counter_changed {
            Gtpv2cEchoPeerEvent::PeerRestartObserved
        } else {
            Gtpv2cEchoPeerEvent::EchoRequestReceived
        };
        if restart_counter_changed && self.policy.require_restart_reconciliation {
            self.state = Gtpv2cEchoPeerState::ReconciliationRequired;
            self.last_blockers = vec![
                Gtpv2cEchoPeerBlocker::PeerRestartCounterChanged,
                Gtpv2cEchoPeerBlocker::RestartReconciliationRequired,
            ];
        }
        Ok(self.transition(event, previous, false, restart_counter_changed))
    }

    /// Observe a decoded Echo Response from the peer.
    ///
    /// # Errors
    ///
    /// Returns [`Gtpv2cEchoPeerError`] when the evidence is not an Echo
    /// Response or when no Echo Request is in flight.
    pub fn observe_echo_response(
        &mut self,
        evidence: EchoMessageEvidence,
    ) -> Result<Gtpv2cEchoPeerTransition, Gtpv2cEchoPeerError> {
        if evidence.direction != MessageDirection::Response {
            return Err(Gtpv2cEchoPeerError::UnexpectedDirection {
                expected: MessageDirection::Response,
                actual: evidence.direction,
            });
        }
        let Some(expected_sequence) = self.in_flight_sequence_number else {
            return Err(Gtpv2cEchoPeerError::InvalidTransition {
                operation: "observe_echo_response",
                state: self.state,
            });
        };
        let previous = self.state;
        if evidence.sequence_number != expected_sequence {
            self.echo_response_sequence_mismatches =
                self.echo_response_sequence_mismatches.saturating_add(1);
            self.state = Gtpv2cEchoPeerState::Degraded;
            self.last_blockers = vec![Gtpv2cEchoPeerBlocker::EchoResponseSequenceMismatch];
            return Ok(self.transition(
                Gtpv2cEchoPeerEvent::EchoResponseSequenceMismatch,
                previous,
                false,
                false,
            ));
        }

        self.echo_responses_observed = self.echo_responses_observed.saturating_add(1);
        self.in_flight_sequence_number = None;
        self.missed_responses = 0;
        let restart_counter_changed = self.observe_restart_counter(evidence.restart_counter);
        if restart_counter_changed && self.policy.require_restart_reconciliation {
            self.state = Gtpv2cEchoPeerState::ReconciliationRequired;
            self.last_blockers = vec![
                Gtpv2cEchoPeerBlocker::PeerRestartCounterChanged,
                Gtpv2cEchoPeerBlocker::RestartReconciliationRequired,
            ];
            return Ok(self.transition(
                Gtpv2cEchoPeerEvent::PeerRestartObserved,
                previous,
                true,
                true,
            ));
        }

        self.state = Gtpv2cEchoPeerState::Reachable;
        self.last_blockers.clear();
        Ok(self.transition(
            Gtpv2cEchoPeerEvent::EchoResponseAccepted,
            previous,
            true,
            restart_counter_changed,
        ))
    }

    /// Record one missing Echo Response timer event.
    ///
    /// # Errors
    ///
    /// Returns [`Gtpv2cEchoPeerError`] when no Echo Request is in flight.
    pub fn echo_response_missing(
        &mut self,
    ) -> Result<Gtpv2cEchoPeerTransition, Gtpv2cEchoPeerError> {
        if self.in_flight_sequence_number.is_none() {
            return Err(Gtpv2cEchoPeerError::InvalidTransition {
                operation: "echo_response_missing",
                state: self.state,
            });
        }
        let previous = self.state;
        self.missed_responses = self.missed_responses.saturating_add(1);
        self.in_flight_sequence_number = None;
        let threshold = self.policy.missed_response_threshold.max(1);
        if self.missed_responses >= threshold {
            self.state = Gtpv2cEchoPeerState::Failed;
            self.last_blockers = vec![
                Gtpv2cEchoPeerBlocker::EchoResponseMissing,
                Gtpv2cEchoPeerBlocker::PeerUnreachable,
            ];
        } else {
            self.state = Gtpv2cEchoPeerState::Degraded;
            self.last_blockers = vec![Gtpv2cEchoPeerBlocker::EchoResponseMissing];
        }
        Ok(self.transition(
            Gtpv2cEchoPeerEvent::EchoResponseMissing,
            previous,
            false,
            false,
        ))
    }

    /// Mark restart reconciliation complete after a restart-counter change.
    ///
    /// # Errors
    ///
    /// Returns [`Gtpv2cEchoPeerError`] when the peer is not waiting for
    /// restart reconciliation.
    pub fn restart_reconciled(&mut self) -> Result<Gtpv2cEchoPeerTransition, Gtpv2cEchoPeerError> {
        if self.state != Gtpv2cEchoPeerState::ReconciliationRequired {
            return Err(Gtpv2cEchoPeerError::InvalidTransition {
                operation: "restart_reconciled",
                state: self.state,
            });
        }
        let previous = self.state;
        self.state = Gtpv2cEchoPeerState::Reachable;
        self.last_blockers.clear();
        Ok(self.transition(
            Gtpv2cEchoPeerEvent::RestartReconciled,
            previous,
            false,
            false,
        ))
    }

    /// Fail the peer as unreachable.
    #[must_use]
    pub fn fail_unreachable(&mut self) -> Gtpv2cEchoPeerTransition {
        let previous = self.state;
        self.state = Gtpv2cEchoPeerState::Failed;
        self.in_flight_sequence_number = None;
        self.last_blockers = vec![Gtpv2cEchoPeerBlocker::PeerUnreachable];
        self.transition(Gtpv2cEchoPeerEvent::Failure, previous, false, false)
    }

    /// Return the current redaction-safe readiness projection.
    #[must_use]
    pub fn readiness(&self) -> Gtpv2cEchoPeerReadiness {
        let blockers = self.readiness_blockers();
        Gtpv2cEchoPeerReadiness {
            state: self.state,
            reachable: self.state == Gtpv2cEchoPeerState::Reachable,
            awaiting_response: self.state == Gtpv2cEchoPeerState::AwaitingResponse,
            degraded: self.state == Gtpv2cEchoPeerState::Degraded,
            failed: self.state == Gtpv2cEchoPeerState::Failed,
            restart_reconciliation_required: self.state
                == Gtpv2cEchoPeerState::ReconciliationRequired,
            traffic_ready: self.state == Gtpv2cEchoPeerState::Reachable,
            blockers,
        }
    }

    /// Return a redaction-safe snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Gtpv2cEchoPeerSnapshot {
        Gtpv2cEchoPeerSnapshot {
            state: self.state,
            readiness: self.readiness(),
            last_restart_counter: self.last_restart_counter,
            in_flight_sequence_number: self.in_flight_sequence_number,
            echo_requests_sent: self.echo_requests_sent,
            echo_requests_received: self.echo_requests_received,
            echo_responses_observed: self.echo_responses_observed,
            echo_response_sequence_mismatches: self.echo_response_sequence_mismatches,
            missed_responses: self.missed_responses,
            restart_counter_changes: self.restart_counter_changes,
        }
    }

    fn observe_restart_counter(&mut self, restart_counter: u8) -> bool {
        let changed = self
            .last_restart_counter
            .map(|previous| previous != restart_counter)
            .unwrap_or(false);
        if changed {
            self.restart_counter_changes = self.restart_counter_changes.saturating_add(1);
        }
        self.last_restart_counter = Some(restart_counter);
        changed
    }

    fn transition(
        &self,
        event: Gtpv2cEchoPeerEvent,
        previous_state: Gtpv2cEchoPeerState,
        response_observed: bool,
        restart_counter_changed: bool,
    ) -> Gtpv2cEchoPeerTransition {
        Gtpv2cEchoPeerTransition {
            event,
            previous_state,
            state: self.state,
            readiness: self.readiness(),
            projection: self.projection(response_observed, restart_counter_changed),
        }
    }

    fn projection(
        &self,
        response_observed: bool,
        restart_counter_changed: bool,
    ) -> Gtpv2cEchoPeerProjection {
        let blockers = self.readiness_blockers();
        Gtpv2cEchoPeerProjection {
            response_observed,
            peer_reachable: self.state == Gtpv2cEchoPeerState::Reachable,
            restart_counter_changed,
            continuity_safe: self.state == Gtpv2cEchoPeerState::Reachable,
            restart_counter: self.last_restart_counter,
            in_flight_sequence_number: self.in_flight_sequence_number,
            missed_responses: self.missed_responses,
            blockers,
        }
    }

    fn readiness_blockers(&self) -> Vec<Gtpv2cEchoPeerBlocker> {
        match self.state {
            Gtpv2cEchoPeerState::Idle | Gtpv2cEchoPeerState::Reachable => Vec::new(),
            Gtpv2cEchoPeerState::AwaitingResponse => {
                vec![Gtpv2cEchoPeerBlocker::EchoResponsePending]
            }
            Gtpv2cEchoPeerState::Degraded | Gtpv2cEchoPeerState::Failed => {
                self.last_blockers.clone()
            }
            Gtpv2cEchoPeerState::ReconciliationRequired => vec![
                Gtpv2cEchoPeerBlocker::PeerRestartCounterChanged,
                Gtpv2cEchoPeerBlocker::RestartReconciliationRequired,
            ],
        }
    }
}

impl Default for Gtpv2cEchoPeer {
    fn default() -> Self {
        Self::new()
    }
}

fn spec_ref() -> SpecRef {
    SpecRef::new("3gpp", "TS29274", "S2b")
}

fn is_procedure_aware(level: ValidationLevel) -> bool {
    matches!(level, ValidationLevel::ProcedureAware)
}

/// Request/response direction for an S2b procedure view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageDirection {
    /// Request message.
    Request,
    /// Response message.
    Response,
}

impl MessageDirection {
    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

/// S2b procedure markers with typed support in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Procedure {
    /// Echo request/response exchange.
    Echo,
    /// Create Session request/response exchange.
    CreateSession,
    /// Modify Bearer request/response exchange, exposed as the S2b Modify Session view.
    ModifyBearer,
    /// Delete Session request/response exchange.
    DeleteSession,
    /// Update Bearer request/response exchange, exposed as the S2b Update Session view.
    UpdateSession,
}

impl Procedure {
    /// Return the GTPv2-C request message type for this procedure.
    pub const fn request_type(self) -> u8 {
        match self {
            Self::Echo => ECHO_REQUEST,
            Self::CreateSession => CREATE_SESSION_REQUEST,
            Self::ModifyBearer => MODIFY_BEARER_REQUEST,
            Self::DeleteSession => DELETE_SESSION_REQUEST,
            Self::UpdateSession => UPDATE_BEARER_REQUEST,
        }
    }

    /// Return the GTPv2-C response message type for this procedure.
    pub const fn response_type(self) -> u8 {
        match self {
            Self::Echo => ECHO_RESPONSE,
            Self::CreateSession => CREATE_SESSION_RESPONSE,
            Self::ModifyBearer => MODIFY_BEARER_RESPONSE,
            Self::DeleteSession => DELETE_SESSION_RESPONSE,
            Self::UpdateSession => UPDATE_BEARER_RESPONSE,
        }
    }

    /// Return the typed GTPv2-C request message type for this procedure.
    pub const fn request_message_type(self) -> MessageType {
        MessageType::from_u8(self.request_type())
    }

    /// Return the typed GTPv2-C response message type for this procedure.
    pub const fn response_message_type(self) -> MessageType {
        MessageType::from_u8(self.response_type())
    }
}

/// Return `true` when `message_type` belongs to the S2b typed subset.
pub const fn is_s2b_message_type(message_type: u8) -> bool {
    MessageType::from_u8(message_type).is_s2b()
}

fn procedure_and_direction(message_type: MessageType) -> Option<(Procedure, MessageDirection)> {
    match message_type {
        MessageType::EchoRequest => Some((Procedure::Echo, MessageDirection::Request)),
        MessageType::EchoResponse => Some((Procedure::Echo, MessageDirection::Response)),
        MessageType::CreateSessionRequest => {
            Some((Procedure::CreateSession, MessageDirection::Request))
        }
        MessageType::CreateSessionResponse => {
            Some((Procedure::CreateSession, MessageDirection::Response))
        }
        MessageType::ModifyBearerRequest => {
            Some((Procedure::ModifyBearer, MessageDirection::Request))
        }
        MessageType::ModifyBearerResponse => {
            Some((Procedure::ModifyBearer, MessageDirection::Response))
        }
        MessageType::DeleteSessionRequest => {
            Some((Procedure::DeleteSession, MessageDirection::Request))
        }
        MessageType::DeleteSessionResponse => {
            Some((Procedure::DeleteSession, MessageDirection::Response))
        }
        MessageType::UpdateBearerRequest => {
            Some((Procedure::UpdateSession, MessageDirection::Request))
        }
        MessageType::UpdateBearerResponse => {
            Some((Procedure::UpdateSession, MessageDirection::Response))
        }
        MessageType::Unknown(_) => None,
    }
}

/// A typed S2b GTPv2-C procedure message view.
///
/// `raw_ies` is retained for byte-exact raw-preserving encoding of decoded
/// messages. Canonical encoding emits the typed IE sequence and preserves any
/// unsupported IEs through [`TypedIeValue::Raw`].
///
/// @spec 3GPP TS29274 R18 S2b
/// @req REQ-3GPP-TS29274-R18-S2B-MESSAGE-001
#[derive(Clone, PartialEq, Eq)]
pub struct S2bProcedureMessage<'a> {
    /// Parsed GTPv2-C common header.
    pub header: Header,
    /// S2b procedure represented by this view.
    pub procedure: Procedure,
    /// Request or response direction.
    pub direction: MessageDirection,
    /// Typed IE sequence, with raw fallback for unsupported IEs.
    pub ies: Vec<TypedIe<'a>>,
    /// Original raw IE bytes from a decoded message.
    pub raw_ies: &'a [u8],
    /// Bytes beyond the decoded message boundary.
    pub tail: &'a [u8],
}

impl<'a> S2bProcedureMessage<'a> {
    /// Return this view's typed GTPv2-C message type.
    pub fn message_type(&self) -> MessageType {
        self.header.typed_message_type()
    }

    /// Return `true` if a top-level IE with `ie_type` is present.
    pub fn has_ie(&self, ie_type: u8) -> bool {
        contains_ie(&self.ies, ie_type)
    }

    /// Project this view as an accepted or rejected Create Session Response.
    ///
    /// # Errors
    ///
    /// Returns [`CreateSessionResponseSummaryError`] when the view is not a
    /// Create Session Response, lacks Cause/response TEID, or represents an
    /// accepted response without accepted-bearer fields.
    pub fn create_session_response_summary(
        &self,
    ) -> Result<CreateSessionResponseSummary, CreateSessionResponseSummaryError> {
        project_create_session_response(self)
    }

    fn encoded_raw_ies(&self, ctx: EncodeContext) -> Result<BytesMut, EncodeError> {
        if ctx.raw_preserving && !self.raw_ies.is_empty() {
            return Ok(BytesMut::from(self.raw_ies));
        }

        let mut raw_ies = BytesMut::new();
        for ie in &self.ies {
            ie.encode(&mut raw_ies, ctx)?;
        }
        Ok(raw_ies)
    }

    fn encoded_lens(&self, ctx: EncodeContext) -> Result<(usize, u16), EncodeError> {
        let raw_ie_len = if ctx.raw_preserving && !self.raw_ies.is_empty() {
            self.raw_ies.len()
        } else {
            self.ies.iter().try_fold(0usize, |acc, ie| {
                let len = ie.wire_len(ctx)?;
                acc.checked_add(len)
                    .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec_ref()))
            })?
        };
        let total_len = self
            .header
            .wire_len()
            .checked_add(raw_ie_len)
            .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec_ref()))?;
        let body_len = total_len.checked_sub(4).ok_or_else(|| {
            EncodeError::new(EncodeErrorCode::Structural {
                reason: "message length underflow",
            })
            .with_spec_ref(spec_ref())
        })?;
        let body_len_u16 = u16::try_from(body_len)
            .map_err(|_| EncodeError::length_overflow().with_spec_ref(spec_ref()))?;
        Ok((total_len, body_len_u16))
    }
}

impl fmt::Debug for S2bProcedureMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S2bProcedureMessage")
            .field("header", &self.header)
            .field("procedure", &self.procedure)
            .field("direction", &self.direction)
            .field("ies", &self.ies)
            .field("raw_ies_len", &self.raw_ies.len())
            .field("tail_len", &self.tail.len())
            .finish()
    }
}

impl Encode for S2bProcedureMessage<'_> {
    /// Encode this S2b view as a GTPv2-C message.
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let (total_len, _) = self.encoded_lens(ctx)?;
        ctx.check_capacity(total_len)?;
        let raw_ies = self.encoded_raw_ies(ctx)?;
        let message = Message {
            header: self.header.clone(),
            raw_ies: &raw_ies,
            tail: &[],
        };
        message.encode(dst, ctx)
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        let (total_len, _) = self.encoded_lens(ctx)?;
        Ok(total_len)
    }
}

/// Typed S2b message view with raw fallback for non-S2b GTPv2-C messages.
///
/// @spec 3GPP TS29274 R18 S2b
/// @req REQ-3GPP-TS29274-R18-S2B-MESSAGE-002
#[derive(Clone, PartialEq, Eq)]
pub enum S2bMessage<'a> {
    /// Echo Request view.
    EchoRequest(S2bProcedureMessage<'a>),
    /// Echo Response view.
    EchoResponse(S2bProcedureMessage<'a>),
    /// Create Session Request view.
    CreateSessionRequest(S2bProcedureMessage<'a>),
    /// Create Session Response view.
    CreateSessionResponse(S2bProcedureMessage<'a>),
    /// Modify Bearer / S2b Modify Session Request view.
    ModifySessionRequest(S2bProcedureMessage<'a>),
    /// Modify Bearer / S2b Modify Session Response view.
    ModifySessionResponse(S2bProcedureMessage<'a>),
    /// Delete Session Request view.
    DeleteSessionRequest(S2bProcedureMessage<'a>),
    /// Delete Session Response view.
    DeleteSessionResponse(S2bProcedureMessage<'a>),
    /// Update Bearer / S2b Update Session Request view.
    UpdateSessionRequest(S2bProcedureMessage<'a>),
    /// Update Bearer / S2b Update Session Response view.
    UpdateSessionResponse(S2bProcedureMessage<'a>),
    /// Non-S2b or unsupported message preserved as the raw shell.
    Raw(Message<'a>),
}

impl fmt::Debug for S2bMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EchoRequest(view) => f.debug_tuple("EchoRequest").field(view).finish(),
            Self::EchoResponse(view) => f.debug_tuple("EchoResponse").field(view).finish(),
            Self::CreateSessionRequest(view) => {
                f.debug_tuple("CreateSessionRequest").field(view).finish()
            }
            Self::CreateSessionResponse(view) => {
                f.debug_tuple("CreateSessionResponse").field(view).finish()
            }
            Self::ModifySessionRequest(view) => {
                f.debug_tuple("ModifySessionRequest").field(view).finish()
            }
            Self::ModifySessionResponse(view) => {
                f.debug_tuple("ModifySessionResponse").field(view).finish()
            }
            Self::DeleteSessionRequest(view) => {
                f.debug_tuple("DeleteSessionRequest").field(view).finish()
            }
            Self::DeleteSessionResponse(view) => {
                f.debug_tuple("DeleteSessionResponse").field(view).finish()
            }
            Self::UpdateSessionRequest(view) => {
                f.debug_tuple("UpdateSessionRequest").field(view).finish()
            }
            Self::UpdateSessionResponse(view) => {
                f.debug_tuple("UpdateSessionResponse").field(view).finish()
            }
            Self::Raw(message) => f
                .debug_struct("Raw")
                .field("header", &message.header)
                .field("raw_ies_len", &message.raw_ies.len())
                .field("tail_len", &message.tail.len())
                .finish(),
        }
    }
}

impl<'a> S2bMessage<'a> {
    /// Decode a typed S2b view from a GTPv2-C byte slice.
    pub fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        <Self as BorrowDecode<'a>>::decode(input, ctx)
    }

    /// Convert a decoded raw [`Message`] into a typed S2b view when possible.
    pub fn from_message(message: Message<'a>, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let message_type = message.message_type();
        let Some((procedure, direction)) = procedure_and_direction(message_type) else {
            return Ok(Self::Raw(message));
        };

        let ies = decode_typed_ie_sequence(message.raw_ies, ctx, 0)?;
        let view = S2bProcedureMessage {
            header: message.header,
            procedure,
            direction,
            ies,
            raw_ies: message.raw_ies,
            tail: message.tail,
        };
        validate_required_ies(&view, ctx)?;

        Ok(match (procedure, direction) {
            (Procedure::Echo, MessageDirection::Request) => Self::EchoRequest(view),
            (Procedure::Echo, MessageDirection::Response) => Self::EchoResponse(view),
            (Procedure::CreateSession, MessageDirection::Request) => {
                Self::CreateSessionRequest(view)
            }
            (Procedure::CreateSession, MessageDirection::Response) => {
                Self::CreateSessionResponse(view)
            }
            (Procedure::ModifyBearer, MessageDirection::Request) => {
                Self::ModifySessionRequest(view)
            }
            (Procedure::ModifyBearer, MessageDirection::Response) => {
                Self::ModifySessionResponse(view)
            }
            (Procedure::DeleteSession, MessageDirection::Request) => {
                Self::DeleteSessionRequest(view)
            }
            (Procedure::DeleteSession, MessageDirection::Response) => {
                Self::DeleteSessionResponse(view)
            }
            (Procedure::UpdateSession, MessageDirection::Request) => {
                Self::UpdateSessionRequest(view)
            }
            (Procedure::UpdateSession, MessageDirection::Response) => {
                Self::UpdateSessionResponse(view)
            }
        })
    }

    /// Return the typed procedure view, or `None` for raw fallback messages.
    pub fn as_view(&self) -> Option<&S2bProcedureMessage<'a>> {
        match self {
            Self::EchoRequest(view)
            | Self::EchoResponse(view)
            | Self::CreateSessionRequest(view)
            | Self::CreateSessionResponse(view)
            | Self::ModifySessionRequest(view)
            | Self::ModifySessionResponse(view)
            | Self::DeleteSessionRequest(view)
            | Self::DeleteSessionResponse(view)
            | Self::UpdateSessionRequest(view)
            | Self::UpdateSessionResponse(view) => Some(view),
            Self::Raw(_) => None,
        }
    }

    /// Return the raw fallback message, or `None` when this is a typed S2b view.
    pub fn as_raw(&self) -> Option<&Message<'a>> {
        match self {
            Self::Raw(message) => Some(message),
            _ => None,
        }
    }

    /// Project this message as an accepted or rejected Create Session Response.
    ///
    /// # Errors
    ///
    /// Returns [`CreateSessionResponseSummaryError`] when this is not a Create
    /// Session Response, lacks Cause/response TEID, or represents an accepted
    /// response without accepted-bearer fields.
    pub fn create_session_response_summary(
        &self,
    ) -> Result<CreateSessionResponseSummary, CreateSessionResponseSummaryError> {
        let Self::CreateSessionResponse(view) = self else {
            return Err(CreateSessionResponseSummaryError::NotCreateSessionResponse);
        };
        view.create_session_response_summary()
    }

    /// Return this message's typed GTPv2-C message type, including unknown raw fallbacks.
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::EchoRequest(view)
            | Self::EchoResponse(view)
            | Self::CreateSessionRequest(view)
            | Self::CreateSessionResponse(view)
            | Self::ModifySessionRequest(view)
            | Self::ModifySessionResponse(view)
            | Self::DeleteSessionRequest(view)
            | Self::DeleteSessionResponse(view)
            | Self::UpdateSessionRequest(view)
            | Self::UpdateSessionResponse(view) => view.message_type(),
            Self::Raw(message) => message.message_type(),
        }
    }
}

/// Decode and project one S2b Create Session Response datagram.
///
/// This helper preserves decode limits from `ctx` but performs the final
/// Create Session Response checks through [`CreateSessionResponseSummaryError`]
/// so callers receive stable error codes for missing Cause, missing response
/// TEID, and accepted responses with incomplete accepted-bearer fields.
///
/// # Errors
///
/// Returns [`CreateSessionResponseSummaryError`] when bytes are malformed,
/// contain trailing data after the message, decode to another message type, or
/// fail Create Session Response projection.
pub fn decode_create_session_response_summary(
    input: &[u8],
    ctx: DecodeContext,
) -> Result<CreateSessionResponseSummary, CreateSessionResponseSummaryError> {
    let projection_ctx = create_session_response_projection_context(ctx);
    let (tail, message) = S2bMessage::decode(input, projection_ctx)
        .map_err(|_| CreateSessionResponseSummaryError::MalformedResponse)?;
    if !tail.is_empty() {
        return Err(CreateSessionResponseSummaryError::MalformedResponse);
    }
    message.create_session_response_summary()
}

impl<'a> BorrowDecode<'a> for S2bMessage<'a> {
    /// Decode a typed S2b message view, preserving raw fallback messages.
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        let (tail, message) = Message::decode(input, ctx)?;
        let view = Self::from_message(message, ctx)?;
        Ok((tail, view))
    }
}

impl Encode for S2bMessage<'_> {
    /// Encode this S2b view or raw fallback message.
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        match self {
            Self::EchoRequest(view)
            | Self::EchoResponse(view)
            | Self::CreateSessionRequest(view)
            | Self::CreateSessionResponse(view)
            | Self::ModifySessionRequest(view)
            | Self::ModifySessionResponse(view)
            | Self::DeleteSessionRequest(view)
            | Self::DeleteSessionResponse(view)
            | Self::UpdateSessionRequest(view)
            | Self::UpdateSessionResponse(view) => view.encode(dst, ctx),
            Self::Raw(message) => message.encode(dst, ctx),
        }
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        match self {
            Self::EchoRequest(view)
            | Self::EchoResponse(view)
            | Self::CreateSessionRequest(view)
            | Self::CreateSessionResponse(view)
            | Self::ModifySessionRequest(view)
            | Self::ModifySessionResponse(view)
            | Self::DeleteSessionRequest(view)
            | Self::DeleteSessionResponse(view)
            | Self::UpdateSessionRequest(view)
            | Self::UpdateSessionResponse(view) => view.wire_len(ctx),
            Self::Raw(message) => message.wire_len(ctx),
        }
    }
}

fn create_session_response_projection_context(mut ctx: DecodeContext) -> DecodeContext {
    if ctx.validation_level == ValidationLevel::ProcedureAware {
        ctx.validation_level = ValidationLevel::Strict;
    }
    ctx
}

fn contains_ie(ies: &[TypedIe<'_>], ie_type: u8) -> bool {
    ies.iter().any(|ie| ie.ie_type() == ie_type)
}

fn contains_ie_instance(ies: &[TypedIe<'_>], ie_type: u8, instance: u8) -> bool {
    ies.iter()
        .any(|ie| ie.ie_type() == ie_type && ie.instance == instance)
}

fn contains_bearer_context_with_ebi(ies: &[TypedIe<'_>]) -> bool {
    ies.iter().any(|ie| match &ie.value {
        TypedIeValue::BearerContext(context) => contains_ie(&context.members, IE_TYPE_EBI),
        _ => false,
    })
}

fn find_cause_value(ies: &[TypedIe<'_>]) -> Option<CauseValue> {
    ies.iter().find_map(|ie| match &ie.value {
        TypedIeValue::Cause(cause) => Some(cause.value),
        _ => None,
    })
}

fn find_recovery_restart_counter(ies: &[TypedIe<'_>]) -> Option<u8> {
    ies.iter().find_map(|ie| match &ie.value {
        TypedIeValue::Recovery(recovery) => Some(recovery.restart_counter),
        _ => None,
    })
}

fn find_sender_f_teid(ies: &[TypedIe<'_>]) -> Option<FullyQualifiedTeid> {
    ies.iter().find_map(|ie| match &ie.value {
        TypedIeValue::FullyQualifiedTeid(f_teid)
            if ie.ie_type() == IE_TYPE_F_TEID && ie.instance == 0 =>
        {
            Some(f_teid.clone())
        }
        _ => None,
    })
}

fn find_bearer_context_ebi(
    ies: &[TypedIe<'_>],
) -> Result<EpsBearerId, CreateSessionResponseSummaryError> {
    let Some(context) = ies.iter().find_map(|ie| match &ie.value {
        TypedIeValue::BearerContext(context) if ie.ie_type() == IE_TYPE_BEARER_CONTEXT => {
            Some(context)
        }
        _ => None,
    }) else {
        return Err(CreateSessionResponseSummaryError::AcceptedResponseMissingBearerContext);
    };

    context
        .members
        .iter()
        .find_map(|ie| match &ie.value {
            TypedIeValue::EpsBearerId(ebi) if ie.ie_type() == IE_TYPE_EBI => Some(*ebi),
            _ => None,
        })
        .ok_or(CreateSessionResponseSummaryError::AcceptedResponseMissingBearerEbi)
}

fn is_accepted_create_session_cause(cause: CauseValue) -> bool {
    cause == CauseValue::RequestAccepted
}

fn project_create_session_response(
    view: &S2bProcedureMessage<'_>,
) -> Result<CreateSessionResponseSummary, CreateSessionResponseSummaryError> {
    if view.procedure != Procedure::CreateSession || view.direction != MessageDirection::Response {
        return Err(CreateSessionResponseSummaryError::NotCreateSessionResponse);
    }

    let response_teid = view
        .header
        .teid
        .ok_or(CreateSessionResponseSummaryError::MissingResponseTeid)?;
    let sequence_number = view.header.sequence_number;
    let cause =
        find_cause_value(&view.ies).ok_or(CreateSessionResponseSummaryError::MissingCause)?;

    if is_accepted_create_session_cause(cause) {
        let sender_f_teid = find_sender_f_teid(&view.ies)
            .ok_or(CreateSessionResponseSummaryError::AcceptedResponseMissingSenderFTeid)?;
        let bearer_ebi = find_bearer_context_ebi(&view.ies)?;

        Ok(CreateSessionResponseSummary::Accepted(
            CreateSessionAcceptedResponseSummary {
                response_teid,
                sequence_number,
                cause,
                sender_f_teid,
                bearer_ebi,
            },
        ))
    } else {
        Ok(CreateSessionResponseSummary::Rejected(
            CreateSessionRejectedResponseSummary {
                response_teid,
                sequence_number,
                cause,
            },
        ))
    }
}

fn missing_ie_error(reason: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, 0).with_spec_ref(spec_ref())
}

fn require_ie(ies: &[TypedIe<'_>], ie_type: u8, reason: &'static str) -> Result<(), DecodeError> {
    if contains_ie(ies, ie_type) {
        Ok(())
    } else {
        Err(missing_ie_error(reason))
    }
}

fn require_ie_instance(
    ies: &[TypedIe<'_>],
    ie_type: u8,
    instance: u8,
    reason: &'static str,
) -> Result<(), DecodeError> {
    if contains_ie_instance(ies, ie_type, instance) {
        Ok(())
    } else {
        Err(missing_ie_error(reason))
    }
}

fn validate_required_ies(
    view: &S2bProcedureMessage<'_>,
    ctx: DecodeContext,
) -> Result<(), DecodeError> {
    if !is_procedure_aware(ctx.validation_level) {
        return Ok(());
    }

    match (view.procedure, view.direction) {
        (Procedure::Echo, MessageDirection::Request) => require_ie(
            &view.ies,
            IE_TYPE_RECOVERY,
            "Echo Request requires Recovery IE",
        ),
        (Procedure::Echo, MessageDirection::Response) => require_ie(
            &view.ies,
            IE_TYPE_RECOVERY,
            "Echo Response requires Recovery IE",
        ),
        (Procedure::CreateSession, MessageDirection::Request) => {
            require_ie(
                &view.ies,
                IE_TYPE_IMSI,
                "Create Session Request requires IMSI IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_RAT_TYPE,
                "Create Session Request requires RAT Type IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_SERVING_NETWORK,
                "Create Session Request requires Serving Network IE",
            )?;
            require_ie_instance(
                &view.ies,
                IE_TYPE_F_TEID,
                0,
                "Create Session Request requires Sender F-TEID IE at instance 0",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_APN,
                "Create Session Request requires APN IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_SELECTION_MODE,
                "Create Session Request requires Selection Mode IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_PDN_TYPE,
                "Create Session Request requires PDN Type IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_PAA,
                "Create Session Request requires PAA IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_BEARER_CONTEXT,
                "Create Session Request requires Bearer Context IE",
            )?;
            if contains_bearer_context_with_ebi(&view.ies) {
                Ok(())
            } else {
                Err(missing_ie_error(
                    "Create Session Request Bearer Context requires EBI IE",
                ))
            }
        }
        (Procedure::CreateSession, MessageDirection::Response) => {
            let cause = find_cause_value(&view.ies)
                .ok_or_else(|| missing_ie_error("Create Session Response requires Cause IE"))?;
            if !is_accepted_create_session_cause(cause) {
                return Ok(());
            }
            require_ie_instance(
                &view.ies,
                IE_TYPE_F_TEID,
                0,
                "Create Session Response requires Sender F-TEID IE at instance 0",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_BEARER_CONTEXT,
                "Create Session Response requires Bearer Context IE",
            )?;
            if contains_bearer_context_with_ebi(&view.ies) {
                Ok(())
            } else {
                Err(missing_ie_error(
                    "Create Session Response Bearer Context requires EBI IE",
                ))
            }
        }
        (Procedure::ModifyBearer, MessageDirection::Request) => require_ie(
            &view.ies,
            IE_TYPE_BEARER_CONTEXT,
            "Modify Bearer Request requires Bearer Context IE",
        ),
        (Procedure::ModifyBearer, MessageDirection::Response) => require_ie(
            &view.ies,
            IE_TYPE_CAUSE,
            "Modify Bearer Response requires Cause IE",
        ),
        (Procedure::DeleteSession, MessageDirection::Request) => require_ie(
            &view.ies,
            IE_TYPE_EBI,
            "Delete Session Request requires linked EBI IE",
        ),
        (Procedure::DeleteSession, MessageDirection::Response) => require_ie(
            &view.ies,
            IE_TYPE_CAUSE,
            "Delete Session Response requires Cause IE",
        ),
        (Procedure::UpdateSession, MessageDirection::Request) => require_ie(
            &view.ies,
            IE_TYPE_BEARER_CONTEXT,
            "Update Bearer Request requires Bearer Context IE",
        ),
        (Procedure::UpdateSession, MessageDirection::Response) => require_ie(
            &view.ies,
            IE_TYPE_CAUSE,
            "Update Bearer Response requires Cause IE",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ie::Recovery;
    use opc_protocol::{DecodeContext, Encode, EncodeContext};

    fn echo_view(
        direction: MessageDirection,
        sequence_number: u32,
        restart_counter: u8,
    ) -> S2bProcedureMessage<'static> {
        let message_type = match direction {
            MessageDirection::Request => ECHO_REQUEST,
            MessageDirection::Response => ECHO_RESPONSE,
        };
        S2bProcedureMessage {
            header: Header::without_teid(message_type, sequence_number),
            procedure: Procedure::Echo,
            direction,
            ies: vec![TypedIe {
                instance: 0,
                value: TypedIeValue::Recovery(Recovery { restart_counter }),
            }],
            raw_ies: &[],
            tail: &[],
        }
    }

    fn echo_evidence(
        direction: MessageDirection,
        sequence_number: u32,
        restart_counter: u8,
    ) -> EchoMessageEvidence {
        EchoMessageEvidence {
            direction,
            sequence_number,
            restart_counter,
        }
    }

    fn encode_view(view: &S2bProcedureMessage<'_>) -> Vec<u8> {
        let mut encoded = BytesMut::new();
        if let Err(error) = view.encode(&mut encoded, EncodeContext::default()) {
            panic!("Echo view encode failed: {error}");
        }
        encoded.to_vec()
    }

    #[test]
    fn echo_message_evidence_extracts_recovery() {
        let view = echo_view(MessageDirection::Response, 0x0001_0203, 9);

        let evidence = match EchoMessageEvidence::from_view(&view) {
            Ok(evidence) => evidence,
            Err(error) => panic!("Echo evidence projection failed: {error}"),
        };

        assert_eq!(evidence.direction, MessageDirection::Response);
        assert_eq!(evidence.direction.as_str(), "response");
        assert_eq!(evidence.sequence_number, 0x0001_0203);
        assert_eq!(evidence.restart_counter, 9);

        let encoded = encode_view(&view);
        let decoded = match decode_echo_message_evidence(&encoded, DecodeContext::default()) {
            Ok(evidence) => evidence,
            Err(error) => panic!("Echo evidence decode failed: {error}"),
        };
        assert_eq!(decoded, evidence);
        assert_eq!(
            EchoMessageEvidenceError::MissingRecovery.as_str(),
            "gtpv2c_echo_message_missing_recovery"
        );
    }

    #[test]
    fn echo_peer_accepts_matching_response() {
        let mut peer = Gtpv2cEchoPeer::new();

        let transition = peer.echo_request_sent(0x0102_0304);

        assert_eq!(transition.event, Gtpv2cEchoPeerEvent::EchoRequestSent);
        assert_eq!(transition.state, Gtpv2cEchoPeerState::AwaitingResponse);
        assert_eq!(
            transition.readiness.blockers,
            vec![Gtpv2cEchoPeerBlocker::EchoResponsePending]
        );

        let transition = match peer.observe_echo_response(echo_evidence(
            MessageDirection::Response,
            0x0102_0304,
            7,
        )) {
            Ok(transition) => transition,
            Err(error) => panic!("Echo response transition failed: {error}"),
        };

        assert_eq!(transition.event, Gtpv2cEchoPeerEvent::EchoResponseAccepted);
        assert_eq!(transition.state, Gtpv2cEchoPeerState::Reachable);
        assert!(transition.readiness.traffic_ready);
        assert!(transition.projection.response_observed);
        assert!(transition.projection.peer_reachable);
        assert!(transition.projection.continuity_safe);
        assert_eq!(transition.projection.restart_counter, Some(7));
        assert_eq!(transition.projection.in_flight_sequence_number, None);

        let snapshot = peer.snapshot();
        assert_eq!(snapshot.echo_requests_sent, 1);
        assert_eq!(snapshot.echo_responses_observed, 1);
        assert_eq!(snapshot.last_restart_counter, Some(7));
    }

    #[test]
    fn echo_peer_restart_counter_requires_reconciliation() {
        let mut peer = Gtpv2cEchoPeer::new();
        let _transition = peer.echo_request_sent(1);
        match peer.observe_echo_response(echo_evidence(MessageDirection::Response, 1, 9)) {
            Ok(_transition) => {}
            Err(error) => panic!("initial Echo response transition failed: {error}"),
        }

        let _transition = peer.echo_request_sent(2);
        let transition =
            match peer.observe_echo_response(echo_evidence(MessageDirection::Response, 2, 10)) {
                Ok(transition) => transition,
                Err(error) => panic!("restart Echo response transition failed: {error}"),
            };

        assert_eq!(transition.event, Gtpv2cEchoPeerEvent::PeerRestartObserved);
        assert_eq!(
            transition.state,
            Gtpv2cEchoPeerState::ReconciliationRequired
        );
        assert!(!transition.readiness.traffic_ready);
        assert!(transition.projection.restart_counter_changed);
        assert!(!transition.projection.continuity_safe);
        assert_eq!(
            transition.readiness.blockers,
            vec![
                Gtpv2cEchoPeerBlocker::PeerRestartCounterChanged,
                Gtpv2cEchoPeerBlocker::RestartReconciliationRequired,
            ]
        );

        let transition = match peer.restart_reconciled() {
            Ok(transition) => transition,
            Err(error) => panic!("restart reconciliation transition failed: {error}"),
        };
        assert_eq!(transition.event, Gtpv2cEchoPeerEvent::RestartReconciled);
        assert_eq!(transition.state, Gtpv2cEchoPeerState::Reachable);
        assert!(transition.readiness.traffic_ready);
        assert_eq!(peer.snapshot().restart_counter_changes, 1);
    }

    #[test]
    fn echo_peer_missing_response_degrades_then_fails() {
        let policy = Gtpv2cEchoPeerPolicy::default().with_missed_response_threshold(2);
        let mut peer = Gtpv2cEchoPeer::with_policy(policy);
        let _transition = peer.echo_request_sent(1);

        let transition = match peer.echo_response_missing() {
            Ok(transition) => transition,
            Err(error) => panic!("missing Echo response transition failed: {error}"),
        };

        assert_eq!(transition.event, Gtpv2cEchoPeerEvent::EchoResponseMissing);
        assert_eq!(transition.state, Gtpv2cEchoPeerState::Degraded);
        assert_eq!(
            transition.readiness.blockers,
            vec![Gtpv2cEchoPeerBlocker::EchoResponseMissing]
        );
        assert_eq!(transition.projection.missed_responses, 1);

        let _transition = peer.echo_request_sent(2);
        let transition = match peer.echo_response_missing() {
            Ok(transition) => transition,
            Err(error) => panic!("second missing Echo response transition failed: {error}"),
        };

        assert_eq!(transition.state, Gtpv2cEchoPeerState::Failed);
        assert!(transition.readiness.failed);
        assert_eq!(
            transition.readiness.blockers,
            vec![
                Gtpv2cEchoPeerBlocker::EchoResponseMissing,
                Gtpv2cEchoPeerBlocker::PeerUnreachable,
            ]
        );
        assert_eq!(peer.snapshot().missed_responses, 2);
    }

    #[test]
    fn echo_peer_sequence_mismatch_and_errors_are_stable() {
        let mut peer = Gtpv2cEchoPeer::new();
        let _transition = peer.echo_request_sent(7);

        let transition =
            match peer.observe_echo_response(echo_evidence(MessageDirection::Response, 8, 1)) {
                Ok(transition) => transition,
                Err(error) => panic!("mismatch Echo response transition failed: {error}"),
            };

        assert_eq!(
            transition.event,
            Gtpv2cEchoPeerEvent::EchoResponseSequenceMismatch
        );
        assert_eq!(transition.state, Gtpv2cEchoPeerState::Degraded);
        assert_eq!(
            transition.readiness.blockers,
            vec![Gtpv2cEchoPeerBlocker::EchoResponseSequenceMismatch]
        );
        assert_eq!(peer.snapshot().echo_response_sequence_mismatches, 1);

        let error = match peer.observe_echo_response(echo_evidence(MessageDirection::Request, 7, 1))
        {
            Ok(transition) => panic!("unexpected transition: {transition:?}"),
            Err(error) => error,
        };
        assert_eq!(error.as_str(), "gtpv2c_echo_peer_unexpected_direction");
        assert_eq!(
            format!("{error}"),
            "gtpv2c_echo_peer_unexpected_direction: expected response, actual request"
        );

        let mut peer = Gtpv2cEchoPeer::new();
        let error =
            match peer.observe_echo_response(echo_evidence(MessageDirection::Response, 1, 1)) {
                Ok(transition) => panic!("unexpected transition: {transition:?}"),
                Err(error) => error,
            };
        assert_eq!(error.as_str(), "gtpv2c_echo_peer_invalid_transition");
        assert_eq!(
            Gtpv2cEchoPeerBlocker::RestartReconciliationRequired.as_str(),
            "gtpv2c_restart_reconciliation_required"
        );
        assert_eq!(
            Gtpv2cEchoPeerEvent::EchoResponseMissing.as_str(),
            "echo_response_missing"
        );
        assert_eq!(Gtpv2cEchoPeerState::Failed.as_str(), "failed");
    }

    #[test]
    fn procedure_maps_request_and_response_types() {
        assert_eq!(
            Procedure::CreateSession.request_type(),
            CREATE_SESSION_REQUEST
        );
        assert_eq!(
            Procedure::CreateSession.response_type(),
            CREATE_SESSION_RESPONSE
        );
        assert_eq!(
            Procedure::UpdateSession.request_type(),
            UPDATE_BEARER_REQUEST
        );
        assert_eq!(Procedure::Echo.response_type(), ECHO_RESPONSE);
        assert!(is_s2b_message_type(DELETE_SESSION_RESPONSE));
        assert!(is_s2b_message_type(UPDATE_BEARER_RESPONSE));
        assert!(!is_s2b_message_type(3));
    }
}
