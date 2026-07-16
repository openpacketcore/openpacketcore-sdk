//! Bounded inbound transaction handling for PGW-triggered GTPv2-C procedures.
//!
//! The registry is transport-neutral. It owns only bounded request/response
//! bytes and redaction-safe correlation metadata; applications still own
//! bearer policy and side effects. A first request returns
//! [`Gtpv2cTriggeredRequestDisposition::Dispatch`]. An exact retransmission
//! while the application is working returns `Pending`, and one received after
//! commit returns the exact committed response bytes for replay.
//!
//! @spec 3GPP TS29274 R18 7.2.3, 7.2.4, 7.2.9.2, 7.2.10.2

use core::fmt;
use std::collections::HashMap;

use bytes::Bytes;
use opc_protocol::{DecodeContext, DuplicateIePolicy, ValidationLevel};

use crate::header::{MessageType, MAX_SEQUENCE_NUMBER};
use crate::ie::{CauseValue, TypedIeValue, IE_TYPE_CAUSE};
use crate::s2b::{Gtpv2cPeerToken, MessageDirection, Procedure, S2bMessage, S2bProcedureMessage};
use crate::{correlate_create_bearer_response, correlate_delete_bearer_response};

/// Caller-supplied monotonic time used by the triggered-transaction registry.
///
/// The unit is milliseconds. The value need not be wall-clock time and is
/// never logged. Callers must use one non-decreasing clock domain for a
/// registry instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Gtpv2cMonotonicMillis(u64);

impl Gtpv2cMonotonicMillis {
    /// Construct a monotonic timestamp from milliseconds.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the contained millisecond value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn deadline_after(self, duration_millis: u64) -> Self {
        Self(self.0.saturating_add(duration_millis))
    }
}

/// Configuration error for [`Gtpv2cTriggeredTransactionPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gtpv2cTriggeredTransactionPolicyError {
    /// Pending timeout must be non-zero.
    ZeroPendingTimeout,
    /// Committed replay retention must be non-zero.
    ZeroReplayRetention,
    /// Registry capacity must be non-zero.
    ZeroTransactionCapacity,
    /// Request byte limit must be non-zero.
    ZeroRequestByteLimit,
    /// Response byte limit must be non-zero.
    ZeroResponseByteLimit,
}

impl Gtpv2cTriggeredTransactionPolicyError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroPendingTimeout => "gtpv2c_triggered_zero_pending_timeout",
            Self::ZeroReplayRetention => "gtpv2c_triggered_zero_replay_retention",
            Self::ZeroTransactionCapacity => "gtpv2c_triggered_zero_transaction_capacity",
            Self::ZeroRequestByteLimit => "gtpv2c_triggered_zero_request_byte_limit",
            Self::ZeroResponseByteLimit => "gtpv2c_triggered_zero_response_byte_limit",
        }
    }
}

impl fmt::Display for Gtpv2cTriggeredTransactionPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for Gtpv2cTriggeredTransactionPolicyError {}

/// Bounds and retention periods for inbound triggered transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtpv2cTriggeredTransactionPolicy {
    pending_timeout_millis: u64,
    replay_retention_millis: u64,
    max_transactions: usize,
    max_request_bytes: usize,
    max_response_bytes: usize,
}

impl Default for Gtpv2cTriggeredTransactionPolicy {
    fn default() -> Self {
        Self {
            pending_timeout_millis: 30_000,
            replay_retention_millis: 120_000,
            max_transactions: 4_096,
            max_request_bytes: 65_535,
            max_response_bytes: 65_535,
        }
    }
}

impl Gtpv2cTriggeredTransactionPolicy {
    /// Construct an explicitly bounded transaction policy.
    ///
    /// # Errors
    ///
    /// Returns an error when any timeout or bound is zero.
    pub const fn new(
        pending_timeout_millis: u64,
        replay_retention_millis: u64,
        max_transactions: usize,
        max_request_bytes: usize,
        max_response_bytes: usize,
    ) -> Result<Self, Gtpv2cTriggeredTransactionPolicyError> {
        if pending_timeout_millis == 0 {
            return Err(Gtpv2cTriggeredTransactionPolicyError::ZeroPendingTimeout);
        }
        if replay_retention_millis == 0 {
            return Err(Gtpv2cTriggeredTransactionPolicyError::ZeroReplayRetention);
        }
        if max_transactions == 0 {
            return Err(Gtpv2cTriggeredTransactionPolicyError::ZeroTransactionCapacity);
        }
        if max_request_bytes == 0 {
            return Err(Gtpv2cTriggeredTransactionPolicyError::ZeroRequestByteLimit);
        }
        if max_response_bytes == 0 {
            return Err(Gtpv2cTriggeredTransactionPolicyError::ZeroResponseByteLimit);
        }
        Ok(Self {
            pending_timeout_millis,
            replay_retention_millis,
            max_transactions,
            max_request_bytes,
            max_response_bytes,
        })
    }

    /// Pending application timeout in milliseconds.
    #[must_use]
    pub const fn pending_timeout_millis(self) -> u64 {
        self.pending_timeout_millis
    }

    /// Committed response replay-retention period in milliseconds.
    #[must_use]
    pub const fn replay_retention_millis(self) -> u64 {
        self.replay_retention_millis
    }

    /// Maximum number of pending and committed transactions.
    #[must_use]
    pub const fn max_transactions(self) -> usize {
        self.max_transactions
    }

    /// Maximum encoded request length retained by the registry.
    #[must_use]
    pub const fn max_request_bytes(self) -> usize {
        self.max_request_bytes
    }

    /// Maximum encoded response length retained by the registry.
    #[must_use]
    pub const fn max_response_bytes(self) -> usize {
        self.max_response_bytes
    }
}

/// Redaction-safe identity for one inbound triggered transaction.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gtpv2cTriggeredTransactionKey {
    /// Triggered procedure.
    pub procedure: Procedure,
    /// Initial request message type.
    pub request_message_type: MessageType,
    /// 24-bit request sequence number.
    pub sequence_number: u32,
    /// TEID from the received request header.
    pub request_teid: u32,
    /// Caller-owned redaction-safe peer token.
    pub peer: Gtpv2cPeerToken,
}

impl fmt::Debug for Gtpv2cTriggeredTransactionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Gtpv2cTriggeredTransactionKey")
            .field("procedure", &self.procedure)
            .field("request_message_type", &self.request_message_type)
            .field("sequence_number", &self.sequence_number)
            .field("request_teid_present", &true)
            .field("peer", &self.peer)
            .finish()
    }
}

/// Application-declared outcome paired with encoded response bytes.
#[derive(Clone, PartialEq, Eq)]
pub enum Gtpv2cTriggeredCompletion {
    /// Fully accepted response; message-level Cause must be 16.
    Accepted(Bytes),
    /// Partially accepted response; message-level Cause must be 17.
    PartiallyAccepted(Bytes),
    /// Rejected response carrying the declared rejection Cause.
    Rejected {
        /// Protocol Cause expected in the encoded response.
        cause: CauseValue,
        /// Complete encoded GTPv2-C response.
        response: Bytes,
    },
}

impl Gtpv2cTriggeredCompletion {
    /// Return the encoded response bytes.
    #[must_use]
    pub fn response(&self) -> &Bytes {
        match self {
            Self::Accepted(response)
            | Self::PartiallyAccepted(response)
            | Self::Rejected { response, .. } => response,
        }
    }

    fn declared_outcome(&self) -> Result<Gtpv2cTriggeredOutcome, Gtpv2cTriggeredTransactionError> {
        match self {
            Self::Accepted(_) => Ok(Gtpv2cTriggeredOutcome::Accepted),
            Self::PartiallyAccepted(_) => Ok(Gtpv2cTriggeredOutcome::PartiallyAccepted),
            Self::Rejected { cause, .. } if cause.is_rejection() => {
                Ok(Gtpv2cTriggeredOutcome::Rejected(*cause))
            }
            Self::Rejected { .. } => Err(Gtpv2cTriggeredTransactionError::InvalidRejectionCause),
        }
    }
}

impl fmt::Debug for Gtpv2cTriggeredCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted(response) => formatter
                .debug_struct("Accepted")
                .field("response_len", &response.len())
                .finish(),
            Self::PartiallyAccepted(response) => formatter
                .debug_struct("PartiallyAccepted")
                .field("response_len", &response.len())
                .finish(),
            Self::Rejected { cause, response } => formatter
                .debug_struct("Rejected")
                .field("cause", cause)
                .field("response_len", &response.len())
                .finish(),
        }
    }
}

/// Committed application outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gtpv2cTriggeredOutcome {
    /// All requested bearer operations succeeded.
    Accepted,
    /// At least one requested bearer operation succeeded and one failed.
    PartiallyAccepted,
    /// The request was rejected with this protocol Cause.
    Rejected(CauseValue),
}

impl Gtpv2cTriggeredOutcome {
    fn cause(self) -> CauseValue {
        match self {
            Self::Accepted => CauseValue::RequestAccepted,
            Self::PartiallyAccepted => CauseValue::RequestAcceptedPartially,
            Self::Rejected(cause) => cause,
        }
    }
}

/// Result of observing one decoded and validated triggered request.
#[derive(Clone, PartialEq, Eq)]
pub enum Gtpv2cTriggeredRequestDisposition {
    /// First observation; invoke application policy exactly once for this key.
    Dispatch(Gtpv2cTriggeredTransactionKey),
    /// Exact retransmission while the first application invocation is pending.
    Pending(Gtpv2cTriggeredTransactionKey),
    /// Exact retransmission after commit; send these exact response bytes.
    Replay {
        /// Transaction identity.
        key: Gtpv2cTriggeredTransactionKey,
        /// Previously committed complete response bytes.
        response: Bytes,
    },
}

impl fmt::Debug for Gtpv2cTriggeredRequestDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dispatch(key) => formatter.debug_tuple("Dispatch").field(key).finish(),
            Self::Pending(key) => formatter.debug_tuple("Pending").field(key).finish(),
            Self::Replay { key, response } => formatter
                .debug_struct("Replay")
                .field("key", key)
                .field("response_len", &response.len())
                .finish(),
        }
    }
}

/// Result of committing an application response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtpv2cTriggeredCommit {
    /// Committed transaction identity.
    pub key: Gtpv2cTriggeredTransactionKey,
    /// Validated application outcome.
    pub outcome: Gtpv2cTriggeredOutcome,
    /// Encoded response length retained for replay.
    pub response_len: usize,
}

/// Stable, redaction-safe triggered transaction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gtpv2cTriggeredTransactionError {
    /// Request exceeds the configured retained-byte bound.
    RequestTooLarge,
    /// Request did not decode as one complete procedure-aware GTPv2-C message.
    MalformedRequest,
    /// Bytes followed the declared request boundary.
    TrailingRequestBytes,
    /// Request was not a PGW-triggered Create Bearer or Delete Bearer request.
    UnsupportedRequest,
    /// Request header did not carry a TEID.
    MissingRequestTeid,
    /// Registry capacity was reached after expired entries were removed.
    CapacityExceeded,
    /// Same active identity was reused with different bytes or response routing.
    ConflictingRequest,
    /// Completion used an acceptance Cause as a rejection Cause.
    InvalidRejectionCause,
    /// Response exceeds the configured retained-byte bound.
    ResponseTooLarge,
    /// Response did not decode as one complete procedure-aware GTPv2-C message.
    MalformedResponse,
    /// Bytes followed the declared response boundary.
    TrailingResponseBytes,
    /// Response procedure, direction, type, sequence, or TEID did not correlate.
    ResponseMismatch,
    /// Encoded message-level Cause did not match the declared completion.
    CompletionCauseMismatch,
    /// No pending transaction exists for this identity.
    TransactionNotFound,
    /// Pending application deadline elapsed before commit.
    TransactionExpired,
    /// A response was already committed and cannot be replaced.
    ResponseAlreadyCommitted,
}

impl Gtpv2cTriggeredTransactionError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestTooLarge => "gtpv2c_triggered_request_too_large",
            Self::MalformedRequest => "gtpv2c_triggered_request_malformed",
            Self::TrailingRequestBytes => "gtpv2c_triggered_request_trailing_bytes",
            Self::UnsupportedRequest => "gtpv2c_triggered_request_unsupported",
            Self::MissingRequestTeid => "gtpv2c_triggered_request_teid_missing",
            Self::CapacityExceeded => "gtpv2c_triggered_capacity_exceeded",
            Self::ConflictingRequest => "gtpv2c_triggered_request_conflict",
            Self::InvalidRejectionCause => "gtpv2c_triggered_invalid_rejection_cause",
            Self::ResponseTooLarge => "gtpv2c_triggered_response_too_large",
            Self::MalformedResponse => "gtpv2c_triggered_response_malformed",
            Self::TrailingResponseBytes => "gtpv2c_triggered_response_trailing_bytes",
            Self::ResponseMismatch => "gtpv2c_triggered_response_mismatch",
            Self::CompletionCauseMismatch => "gtpv2c_triggered_completion_cause_mismatch",
            Self::TransactionNotFound => "gtpv2c_triggered_transaction_not_found",
            Self::TransactionExpired => "gtpv2c_triggered_transaction_expired",
            Self::ResponseAlreadyCommitted => "gtpv2c_triggered_response_already_committed",
        }
    }
}

impl fmt::Display for Gtpv2cTriggeredTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for Gtpv2cTriggeredTransactionError {}

#[derive(Clone)]
enum TriggeredEntryState {
    Pending,
    Committed {
        response: Bytes,
        outcome: Gtpv2cTriggeredOutcome,
    },
}

impl fmt::Debug for TriggeredEntryState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => formatter.write_str("Pending"),
            Self::Committed { response, outcome } => formatter
                .debug_struct("Committed")
                .field("response_len", &response.len())
                .field("outcome", outcome)
                .finish(),
        }
    }
}

#[derive(Clone)]
struct TriggeredEntry {
    request: Bytes,
    expected_response_teid: Option<u32>,
    expires_at: Gtpv2cMonotonicMillis,
    state: TriggeredEntryState,
}

impl fmt::Debug for TriggeredEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TriggeredEntry")
            .field("request_len", &self.request.len())
            .field(
                "expected_response_teid_present",
                &self.expected_response_teid.is_some(),
            )
            .field("expires_at", &self.expires_at)
            .field("state", &self.state)
            .finish()
    }
}

/// Bounded, transport-neutral registry for inbound triggered transactions.
pub struct Gtpv2cTriggeredTransactions {
    policy: Gtpv2cTriggeredTransactionPolicy,
    entries: HashMap<Gtpv2cTriggeredTransactionKey, TriggeredEntry>,
}

impl fmt::Debug for Gtpv2cTriggeredTransactions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Gtpv2cTriggeredTransactions")
            .field("policy", &self.policy)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl Gtpv2cTriggeredTransactions {
    /// Construct an empty registry using `policy`.
    #[must_use]
    pub fn new(policy: Gtpv2cTriggeredTransactionPolicy) -> Self {
        Self {
            policy,
            entries: HashMap::new(),
        }
    }

    /// Return the configured policy.
    #[must_use]
    pub const fn policy(&self) -> Gtpv2cTriggeredTransactionPolicy {
        self.policy
    }

    /// Return the number of retained pending and committed transactions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` when no transactions are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove expired pending work and replay entries.
    ///
    /// Returns the number of removed entries. Deadlines are fixed at initial
    /// observation or commit; retransmissions do not prolong them.
    pub fn cleanup_expired(&mut self, now: Gtpv2cMonotonicMillis) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| now < entry.expires_at);
        before.saturating_sub(self.entries.len())
    }

    /// Observe one complete encoded Create Bearer or Delete Bearer request.
    ///
    /// `expected_response_teid` is the remote control-plane TEID that the
    /// eventual response must carry. `None` disables that correlation only for
    /// deployments where the remote TEID is genuinely unavailable; procedure,
    /// direction, message type, sequence number, and request identity remain
    /// mandatory.
    ///
    /// # Errors
    ///
    /// Returns a stable error for malformed/unsupported input, exhausted
    /// bounds, or conflicting reuse of an active identity.
    pub fn observe_request(
        &mut self,
        peer: Gtpv2cPeerToken,
        encoded_request: Bytes,
        expected_response_teid: Option<u32>,
        now: Gtpv2cMonotonicMillis,
        ctx: DecodeContext,
    ) -> Result<Gtpv2cTriggeredRequestDisposition, Gtpv2cTriggeredTransactionError> {
        let _expired = self.cleanup_expired(now);
        if encoded_request.len() > self.policy.max_request_bytes {
            return Err(Gtpv2cTriggeredTransactionError::RequestTooLarge);
        }

        let (tail, decoded) = S2bMessage::decode(&encoded_request, procedure_context(ctx))
            .map_err(|_| Gtpv2cTriggeredTransactionError::MalformedRequest)?;
        if !tail.is_empty() {
            return Err(Gtpv2cTriggeredTransactionError::TrailingRequestBytes);
        }
        let view = decoded
            .as_view()
            .ok_or(Gtpv2cTriggeredTransactionError::UnsupportedRequest)?;
        if view.direction != MessageDirection::Request
            || !matches!(
                view.procedure,
                Procedure::CreateBearer | Procedure::DeleteBearer
            )
        {
            return Err(Gtpv2cTriggeredTransactionError::UnsupportedRequest);
        }
        let request_teid = view
            .header
            .teid
            .ok_or(Gtpv2cTriggeredTransactionError::MissingRequestTeid)?;
        let key = Gtpv2cTriggeredTransactionKey {
            procedure: view.procedure,
            request_message_type: view.message_type(),
            sequence_number: view.header.sequence_number,
            request_teid,
            peer,
        };

        if let Some(existing) = self.entries.get(&key) {
            if existing.request != encoded_request
                || existing.expected_response_teid != expected_response_teid
            {
                return Err(Gtpv2cTriggeredTransactionError::ConflictingRequest);
            }
            return Ok(match &existing.state {
                TriggeredEntryState::Pending => Gtpv2cTriggeredRequestDisposition::Pending(key),
                TriggeredEntryState::Committed { response, .. } => {
                    Gtpv2cTriggeredRequestDisposition::Replay {
                        key,
                        response: response.clone(),
                    }
                }
            });
        }

        if self.entries.len() >= self.policy.max_transactions {
            return Err(Gtpv2cTriggeredTransactionError::CapacityExceeded);
        }
        self.entries.insert(
            key,
            TriggeredEntry {
                request: encoded_request,
                expected_response_teid,
                expires_at: now.deadline_after(self.policy.pending_timeout_millis),
                state: TriggeredEntryState::Pending,
            },
        );
        Ok(Gtpv2cTriggeredRequestDisposition::Dispatch(key))
    }

    /// Validate and commit an application response for exact replay.
    ///
    /// Once this succeeds, later exact request retransmissions return the
    /// committed bytes and the response cannot be replaced.
    ///
    /// # Errors
    ///
    /// Returns a stable error if the transaction is absent/expired/already
    /// committed, the response is malformed or mismatched, or its Cause does
    /// not match the explicitly declared completion.
    pub fn commit_response(
        &mut self,
        key: Gtpv2cTriggeredTransactionKey,
        completion: Gtpv2cTriggeredCompletion,
        now: Gtpv2cMonotonicMillis,
        ctx: DecodeContext,
    ) -> Result<Gtpv2cTriggeredCommit, Gtpv2cTriggeredTransactionError> {
        let declared_outcome = completion.declared_outcome()?;
        if completion.response().len() > self.policy.max_response_bytes {
            return Err(Gtpv2cTriggeredTransactionError::ResponseTooLarge);
        }

        let Some(entry) = self.entries.get(&key) else {
            return Err(Gtpv2cTriggeredTransactionError::TransactionNotFound);
        };
        if now >= entry.expires_at {
            self.entries.remove(&key);
            return Err(Gtpv2cTriggeredTransactionError::TransactionExpired);
        }
        if matches!(&entry.state, TriggeredEntryState::Committed { .. }) {
            return Err(Gtpv2cTriggeredTransactionError::ResponseAlreadyCommitted);
        }

        let (tail, decoded) = S2bMessage::decode(completion.response(), procedure_context(ctx))
            .map_err(|_| Gtpv2cTriggeredTransactionError::MalformedResponse)?;
        if !tail.is_empty() {
            return Err(Gtpv2cTriggeredTransactionError::TrailingResponseBytes);
        }
        let view = decoded
            .as_view()
            .ok_or(Gtpv2cTriggeredTransactionError::ResponseMismatch)?;
        if !response_matches(key, entry.expected_response_teid, view) {
            return Err(Gtpv2cTriggeredTransactionError::ResponseMismatch);
        }
        correlate_response_to_request(&entry.request, key, view, ctx)?;
        let encoded_cause =
            message_cause(view).ok_or(Gtpv2cTriggeredTransactionError::MalformedResponse)?;
        if encoded_cause != declared_outcome.cause() {
            return Err(Gtpv2cTriggeredTransactionError::CompletionCauseMismatch);
        }

        let response = completion.response().clone();
        let response_len = response.len();
        let Some(entry) = self.entries.get_mut(&key) else {
            return Err(Gtpv2cTriggeredTransactionError::TransactionNotFound);
        };
        entry.expires_at = now.deadline_after(self.policy.replay_retention_millis);
        entry.state = TriggeredEntryState::Committed {
            response,
            outcome: declared_outcome,
        };
        Ok(Gtpv2cTriggeredCommit {
            key,
            outcome: declared_outcome,
            response_len,
        })
    }

    /// Return the committed outcome, if this key is retained and committed.
    #[must_use]
    pub fn committed_outcome(
        &self,
        key: Gtpv2cTriggeredTransactionKey,
    ) -> Option<Gtpv2cTriggeredOutcome> {
        match self.entries.get(&key).map(|entry| &entry.state) {
            Some(TriggeredEntryState::Committed { outcome, .. }) => Some(*outcome),
            _ => None,
        }
    }
}

impl Default for Gtpv2cTriggeredTransactions {
    fn default() -> Self {
        Self::new(Gtpv2cTriggeredTransactionPolicy::default())
    }
}

fn procedure_context(mut ctx: DecodeContext) -> DecodeContext {
    ctx.validation_level = ValidationLevel::ProcedureAware;
    ctx.duplicate_ie_policy = DuplicateIePolicy::Reject;
    ctx
}

fn response_matches(
    key: Gtpv2cTriggeredTransactionKey,
    expected_response_teid: Option<u32>,
    view: &S2bProcedureMessage<'_>,
) -> bool {
    view.procedure == key.procedure
        && view.direction == MessageDirection::Response
        && view.message_type() == key.procedure.response_message_type()
        && view.header.sequence_number <= MAX_SEQUENCE_NUMBER
        && view.header.sequence_number == key.sequence_number
        && expected_response_teid.is_none_or(|expected| view.header.teid == Some(expected))
}

fn correlate_response_to_request(
    encoded_request: &[u8],
    key: Gtpv2cTriggeredTransactionKey,
    response: &S2bProcedureMessage<'_>,
    ctx: DecodeContext,
) -> Result<(), Gtpv2cTriggeredTransactionError> {
    let (tail, decoded_request) = S2bMessage::decode(encoded_request, procedure_context(ctx))
        .map_err(|_| Gtpv2cTriggeredTransactionError::MalformedRequest)?;
    if !tail.is_empty() {
        return Err(Gtpv2cTriggeredTransactionError::TrailingRequestBytes);
    }
    let request = decoded_request
        .as_view()
        .ok_or(Gtpv2cTriggeredTransactionError::UnsupportedRequest)?;
    match key.procedure {
        Procedure::CreateBearer => {
            let request = request
                .create_bearer_request()
                .map_err(|_| Gtpv2cTriggeredTransactionError::MalformedRequest)?;
            let response = response
                .create_bearer_response()
                .map_err(|_| Gtpv2cTriggeredTransactionError::MalformedResponse)?;
            correlate_create_bearer_response(&request, &response)
                .map_err(|_| Gtpv2cTriggeredTransactionError::ResponseMismatch)
        }
        Procedure::DeleteBearer => {
            let request = request
                .delete_bearer_request()
                .map_err(|_| Gtpv2cTriggeredTransactionError::MalformedRequest)?;
            let response = response
                .delete_bearer_response()
                .map_err(|_| Gtpv2cTriggeredTransactionError::MalformedResponse)?;
            correlate_delete_bearer_response(&request, &response)
                .map_err(|_| Gtpv2cTriggeredTransactionError::ResponseMismatch)
        }
        _ => Err(Gtpv2cTriggeredTransactionError::UnsupportedRequest),
    }
}

fn message_cause(view: &S2bProcedureMessage<'_>) -> Option<CauseValue> {
    view.ies.iter().find_map(|ie| match &ie.value {
        TypedIeValue::Cause(cause) if ie.ie_type() == IE_TYPE_CAUSE && ie.instance == 0 => {
            Some(cause.value)
        }
        _ => None,
    })
}
