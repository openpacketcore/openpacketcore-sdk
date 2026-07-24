//! Loss-safe pending-request failover transactions (RFC 6733 §5.1, §5.5.4).
//!
//! This module provides the reusable [`PendingRequestTable`] /
//! [`DiameterRequestTransaction`] primitive for origin-node request failover.
//! It owns wire correctness, answer correlation across alternate connections,
//! live at-most-once completion, and a stable restored-delivery identity:
//!
//! - The first attempt carries a Hop-by-Hop identifier allocated uniquely on
//!   its connection with the T bit clear. Every failover attempt preserves the
//!   canonical request AVPs byte-for-byte, keeps the exact original End-to-End
//!   identifier and Origin-Host, sets T=1, and draws a fresh Hop-by-Hop
//!   identifier that is unique on the selected alternate connection. All
//!   attempt identifiers are retained so a late answer from either path is
//!   still recognized.
//! - Answers are correlated by (connection, Hop-by-Hop), then validated
//!   against the request's End-to-End identifier, command code, and
//!   application. Exactly one terminal completion is produced while a live
//!   transaction exists; late, duplicated, reordered, or simultaneous answers
//!   only update bounded evidence and never re-deliver a completion.
//! - Write dispositions distinguish failure before write, uncertain or
//!   partial write, successful write followed by transport loss, fixed
//!   `Destination-Host` with no valid alternate, retry exhaustion, and
//!   indeterminate completion.
//! - [`PendingRequestTable::snapshot`] emits a versioned, explicitly
//!   sensitive byte form that a consumer may place in encrypted storage.
//!   Restored pending records retransmit with T=1 and keep a stable
//!   completion token and generation. Restored delivery is at-least-once
//!   unless the consumer adds a durable claim/ack protocol (for example a
//!   compare-and-set on the completion token and generation); see
//!   [`PendingRequestTable::restore`].
//!
//! Attempt limits, deadlines, peer selection, and whether an alternate is
//! routable remain caller policy. Peer discovery, realm routing, load
//! balancing, watchdog timing, unencrypted persistence, consumer-side
//! idempotency, and requests whose application semantics prohibit failover
//! are out of scope. The API is synchronous and executor-neutral: the
//! terminal state transition and the completion hand-off are one atomic
//! `&mut self` call, so dropping a caller-side future can never split the
//! transition from the delivery or re-arm a completed transaction.
//!
//! No `Debug`, error, or evidence representation exposes EAP payloads,
//! User-Name, Session-Id, realm or destination identities, or raw request
//! bytes.
//!
//! @spec IETF RFC6733 3
//! @spec IETF RFC6733 5.1
//! @spec IETF RFC6733 5.5.4
//! @req REQ-IETF-RFC6733-SCAFFOLD-001
//! @conformance scaffold — see CONFORMANCE.md

use std::collections::HashMap;
use std::fmt;
use std::num::{NonZeroU128, NonZeroU64};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use opc_protocol::DecodeContext;
use zeroize::Zeroizing;

use crate::base;
use crate::{
    ApplicationId, CommandCode, CommandFlags, Header, Message, OwnedMessage, DIAMETER_HEADER_LEN,
    MAX_U24,
};

const SNAPSHOT_MAGIC: u32 = 0x4450_5453; // "DPTS"
const SNAPSHOT_VERSION: u16 = 1;
const MAX_SERIALIZED_COUNT: usize = u16::MAX as usize;
const MICROS_SENTINEL_NONE: u64 = u64::MAX;

/// Opaque identity of one transport connection lifetime.
///
/// The caller allocates a process-unique nonzero value whenever a peer
/// connection is established; reconnect and failover must allocate a new
/// token. The value is redacted from diagnostics so it cannot become a
/// high-cardinality connection label.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DiameterConnectionToken(NonZeroU64);

impl DiameterConnectionToken {
    /// Wrap one transport-owned, process-unique connection identity.
    #[must_use]
    pub const fn new(value: NonZeroU64) -> Self {
        Self(value)
    }

    /// Return the raw caller-allocated identity value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Debug for DiameterConnectionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiameterConnectionToken(<redacted>)")
    }
}

/// Caller-supplied durable identity of one pending transaction.
///
/// The value must be unique across every transaction the consumer may track
/// or restore into one table. It is redacted from diagnostics; use
/// [`Self::get`] when storing it durably.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CompletionTokenValue(NonZeroU128);

impl CompletionTokenValue {
    /// Wrap one consumer-allocated nonzero token value.
    #[must_use]
    pub const fn new(value: NonZeroU128) -> Self {
        Self(value)
    }

    /// Return the raw token value for durable storage.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0.get()
    }
}

impl fmt::Debug for CompletionTokenValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompletionTokenValue(<redacted>)")
    }
}

/// Stable completion identity of one transaction across restores.
///
/// The `value` is allocated by the consumer at track time. The `generation`
/// is `0` while the transaction is pending and transitions to `1` exactly
/// once, at the terminal completion. Both are preserved verbatim by
/// snapshot/restore, so a consumer can durably claim delivery with a
/// compare-and-set on `(value, generation)` before applying completion side
/// effects, making restored delivery idempotent.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompletionToken {
    value: CompletionTokenValue,
    generation: u64,
}

impl CompletionToken {
    /// Return the consumer-allocated token value.
    #[must_use]
    pub const fn value(self) -> CompletionTokenValue {
        self.value
    }

    /// Return the completion generation (`0` pending, `1` completed).
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

impl fmt::Debug for CompletionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionToken")
            .field("value", &self.value)
            .field("generation", &self.generation)
            .finish()
    }
}

/// Injectable monotonic clock for attempt timing evidence.
///
/// Implementations return a monotonic [`Duration`] since an opaque epoch.
/// Only differences between two readings of the same clock are meaningful.
/// Deadlines and retransmission timing remain caller policy; the clock is
/// used solely for bounded per-attempt evidence. Test clocks should advance
/// deterministically.
pub trait PendingRequestClock: fmt::Debug + Send + Sync {
    /// Return the current monotonic timestamp since this clock's epoch.
    fn now(&self) -> Duration;
}

/// Monotonic clock anchored at process [`Instant`] creation time.
#[derive(Debug, Clone)]
pub struct MonotonicClock {
    anchor: Instant,
}

impl MonotonicClock {
    /// Anchor the clock at the current monotonic instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            anchor: Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingRequestClock for MonotonicClock {
    fn now(&self) -> Duration {
        self.anchor.elapsed()
    }
}

/// Bounds for one [`PendingRequestTable`].
///
/// Every table is bounded: pending records, retained completed records,
/// attempts per transaction, registered connections, and the accepted
/// canonical request size are all capped here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingRequestTableConfig {
    /// Maximum simultaneously pending transactions. Also the snapshot record
    /// bound; must fit the 16-bit serialized record count.
    pub max_pending_transactions: usize,
    /// Maximum completed transactions retained for late-answer evidence.
    /// Older completions are evicted in completion order beyond this bound.
    pub max_retained_completions: usize,
    /// Maximum attempts (initial plus failover and restored retransmissions)
    /// recorded for one transaction. This bound survives crash recovery, so a
    /// restore-and-retransmit loop cannot grow attempts without limit.
    pub max_attempts_per_transaction: usize,
    /// Maximum simultaneously registered connection lifetimes.
    pub max_connections: usize,
    /// Maximum canonical request size accepted by [`PendingRequestTable::track`].
    pub max_message_len: usize,
}

impl Default for PendingRequestTableConfig {
    fn default() -> Self {
        Self {
            max_pending_transactions: 256,
            max_retained_completions: 256,
            max_attempts_per_transaction: 8,
            max_connections: 64,
            max_message_len: 8192,
        }
    }
}

impl PendingRequestTableConfig {
    fn validate(&self) -> Result<(), PendingRequestConfigError> {
        if self.max_pending_transactions == 0
            || self.max_pending_transactions > MAX_SERIALIZED_COUNT
        {
            return Err(PendingRequestConfigError::PendingBoundOutOfRange);
        }
        if self.max_retained_completions == 0 {
            return Err(PendingRequestConfigError::CompletionBoundOutOfRange);
        }
        if self.max_attempts_per_transaction == 0
            || self.max_attempts_per_transaction > MAX_SERIALIZED_COUNT
        {
            return Err(PendingRequestConfigError::AttemptBoundOutOfRange);
        }
        if self.max_connections == 0 {
            return Err(PendingRequestConfigError::ConnectionBoundOutOfRange);
        }
        if self.max_message_len < DIAMETER_HEADER_LEN || self.max_message_len > MAX_U24 as usize {
            return Err(PendingRequestConfigError::MessageBoundOutOfRange);
        }
        Ok(())
    }
}

/// Stable, redaction-safe table configuration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingRequestConfigError {
    /// The pending-transaction bound is zero or exceeds the serialized bound.
    PendingBoundOutOfRange,
    /// The retained-completion bound is zero.
    CompletionBoundOutOfRange,
    /// The per-transaction attempt bound is zero or exceeds the serialized bound.
    AttemptBoundOutOfRange,
    /// The connection bound is zero.
    ConnectionBoundOutOfRange,
    /// The message bound cannot hold a Diameter header or exceeds 24-bit length.
    MessageBoundOutOfRange,
}

impl PendingRequestConfigError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingBoundOutOfRange => "diameter_pending_config_pending_bound",
            Self::CompletionBoundOutOfRange => "diameter_pending_config_completion_bound",
            Self::AttemptBoundOutOfRange => "diameter_pending_config_attempt_bound",
            Self::ConnectionBoundOutOfRange => "diameter_pending_config_connection_bound",
            Self::MessageBoundOutOfRange => "diameter_pending_config_message_bound",
        }
    }
}

impl fmt::Display for PendingRequestConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for PendingRequestConfigError {}

/// Hop-local identity of one attempt, used for answer correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttemptId {
    connection: DiameterConnectionToken,
    hop_by_hop_identifier: u32,
}

impl AttemptId {
    /// Return the connection lifetime this attempt was written to.
    #[must_use]
    pub const fn connection(self) -> DiameterConnectionToken {
        self.connection
    }

    /// Return the Hop-by-Hop identifier unique on this attempt's connection.
    #[must_use]
    pub const fn hop_by_hop_identifier(self) -> u32 {
        self.hop_by_hop_identifier
    }
}

/// Terminal write/answer disposition of one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttemptDisposition {
    /// The attempt is awaiting its write outcome or answer.
    InFlight,
    /// The transport proved the request was never written.
    FailedBeforeWrite,
    /// The write outcome is unknown or partial; the peer may have received it.
    FailedUncertainWrite,
    /// The complete request was written, then the transport failed before an
    /// answer arrived.
    TransportLostAfterWrite,
    /// A validated answer was correlated to this attempt.
    Answered,
}

impl AttemptDisposition {
    /// Stable machine-readable disposition code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InFlight => "in_flight",
            Self::FailedBeforeWrite => "failed_before_write",
            Self::FailedUncertainWrite => "failed_uncertain_write",
            Self::TransportLostAfterWrite => "transport_lost_after_write",
            Self::Answered => "answered",
        }
    }

    /// Return whether this attempt can still produce an answer.
    #[must_use]
    pub const fn is_in_flight(self) -> bool {
        matches!(self, Self::InFlight)
    }
}

/// Transport-reported failure classification for one attempt.
///
/// The distinction matters for evidence and for the caller's failover
/// policy: after [`Self::BeforeWrite`] the request provably never left, while
/// [`Self::UncertainWrite`] and [`Self::TransportLostAfterWrite`] mean the
/// peer may apply the request, so the eventual completion is potentially a
/// duplicate the server must suppress through End-to-End duplicate
/// detection. Every failover attempt sets T=1 regardless of disposition, as
/// RFC 6733 §5.5.4 requires for forwarded pending requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttemptFailure {
    /// The transport proved the request was never written.
    BeforeWrite,
    /// The write was partial or its disposition is unknown.
    UncertainWrite,
    /// The complete request was written before the transport failed.
    TransportLostAfterWrite,
}

impl AttemptFailure {
    fn disposition(self) -> AttemptDisposition {
        match self {
            Self::BeforeWrite => AttemptDisposition::FailedBeforeWrite,
            Self::UncertainWrite => AttemptDisposition::FailedUncertainWrite,
            Self::TransportLostAfterWrite => AttemptDisposition::TransportLostAfterWrite,
        }
    }
}

/// Bounded evidence for one transmission attempt.
///
/// Timestamps come from the table's injected clock and are meaningful only
/// relative to that clock's epoch. Attempts recorded before a
/// snapshot/restore keep timestamps from the previous clock's epoch.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AttemptEvidence {
    attempt_index: usize,
    connection: DiameterConnectionToken,
    hop_by_hop_identifier: u32,
    retransmission: bool,
    disposition: AttemptDisposition,
    started_at: Duration,
    ended_at: Option<Duration>,
}

impl AttemptEvidence {
    /// Return the zero-based position of this attempt in the transaction.
    #[must_use]
    pub const fn attempt_index(&self) -> usize {
        self.attempt_index
    }

    /// Return the hop-local attempt identity used for correlation.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        AttemptId {
            connection: self.connection,
            hop_by_hop_identifier: self.hop_by_hop_identifier,
        }
    }

    /// Return the connection lifetime this attempt was written to.
    #[must_use]
    pub const fn connection(&self) -> DiameterConnectionToken {
        self.connection
    }

    /// Return the Hop-by-Hop identifier unique on this attempt's connection.
    #[must_use]
    pub const fn hop_by_hop_identifier(&self) -> u32 {
        self.hop_by_hop_identifier
    }

    /// Return whether this attempt carries the RFC 6733 T (potentially
    /// retransmitted) bit. Every attempt after the first sets T=1.
    #[must_use]
    pub const fn is_retransmission(&self) -> bool {
        self.retransmission
    }

    /// Return the current write/answer disposition.
    #[must_use]
    pub const fn disposition(&self) -> AttemptDisposition {
        self.disposition
    }

    /// Return the table-clock timestamp when this attempt was created.
    #[must_use]
    pub const fn started_at(&self) -> Duration {
        self.started_at
    }

    /// Return the table-clock timestamp when this attempt terminated.
    #[must_use]
    pub const fn ended_at(&self) -> Option<Duration> {
        self.ended_at
    }
}

impl fmt::Debug for AttemptEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttemptEvidence")
            .field("attempt_index", &self.attempt_index)
            .field("connection", &self.connection)
            .field("hop_by_hop_identifier", &self.hop_by_hop_identifier)
            .field("retransmission", &self.retransmission)
            .field("disposition", &self.disposition)
            .field("started_at", &self.started_at)
            .field("ended_at", &self.ended_at)
            .finish()
    }
}

/// Caller assertion about whether the selected alternate can serve the
/// request's routing identity.
///
/// Peer selection and alternate routability are caller policy. A request
/// carrying an explicit `Destination-Host` may only be failed over to an
/// alternate the caller asserts can reach that host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlternateRoutability {
    /// The alternate is an ordinary realm-routed agent. Rejected for requests
    /// with an explicit `Destination-Host`.
    RealmRouted,
    /// The caller asserts the alternate can deliver to the request's fixed
    /// `Destination-Host`. Meaningless but harmless when no fixed destination
    /// is present.
    DestinationAsserted,
}

/// Reason a transaction could not be delivered at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UndeliverableReason {
    /// The request pins a `Destination-Host` and no valid alternate exists.
    /// The destination is never silently dropped or rewritten.
    FixedDestinationNoAlternate,
    /// No routable alternate connection is available.
    NoAlternateRoutable,
}

impl UndeliverableReason {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FixedDestinationNoAlternate => "fixed_destination_no_alternate",
            Self::NoAlternateRoutable => "no_alternate_routable",
        }
    }
}

/// Reason a transaction completed without a provable outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndeterminateReason {
    /// The last attempt's write disposition is uncertain and no further
    /// attempt will be made; the peer may or may not have applied the request.
    UncertainWriteDisposition,
    /// The caller stopped waiting for an answer (for example a caller-owned
    /// deadline) without evidence the request arrived.
    CallerWithdrawn,
}

impl IndeterminateReason {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UncertainWriteDisposition => "uncertain_write_disposition",
            Self::CallerWithdrawn => "caller_withdrawn",
        }
    }
}

/// Payload-free classification of a terminal completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompletionKind {
    /// A validated answer was correlated to one attempt.
    Answered,
    /// The request could not be delivered (typed inability-to-deliver).
    Undeliverable,
    /// The caller's retry policy was exhausted.
    Exhausted,
    /// The outcome cannot be proven either way.
    Indeterminate,
}

impl CompletionKind {
    /// Stable machine-readable completion code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::Undeliverable => "undeliverable",
            Self::Exhausted => "exhausted",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// The single terminal completion of one live transaction.
///
/// This value is produced exactly once per transaction: by
/// [`PendingRequestTable::correlate_answer`] for a validated answer, or by
/// one of the `finish_*` methods for a caller-driven terminal outcome. After
/// it is produced, further answers only update bounded evidence. Dropping
/// this value does not re-arm the transaction.
pub enum TransactionCompletion {
    /// A validated answer was correlated to the recorded attempt. The answer
    /// is handed to the application exactly once; its contents are sensitive
    /// and never appear in diagnostics.
    Answered {
        /// Stable completion identity with generation `1`.
        token: CompletionToken,
        /// The answer message as received on the completing connection.
        answer: OwnedMessage,
        /// Evidence of the attempt the answer was correlated to.
        attempt: AttemptEvidence,
    },
    /// The request could not be delivered at all.
    Undeliverable {
        /// Stable completion identity with generation `1`.
        token: CompletionToken,
        /// Typed inability-to-deliver reason.
        reason: UndeliverableReason,
        /// Number of attempts recorded before giving up.
        attempts: usize,
    },
    /// The caller's retry policy was exhausted without an answer.
    Exhausted {
        /// Stable completion identity with generation `1`.
        token: CompletionToken,
        /// Number of attempts recorded before giving up.
        attempts: usize,
    },
    /// The outcome cannot be proven; side effects must be reconciled by the
    /// consumer's own policy.
    Indeterminate {
        /// Stable completion identity with generation `1`.
        token: CompletionToken,
        /// Why no provable outcome exists.
        reason: IndeterminateReason,
        /// Number of attempts recorded before giving up.
        attempts: usize,
    },
}

impl TransactionCompletion {
    /// Return the stable completion identity carried by this outcome.
    #[must_use]
    pub const fn token(&self) -> CompletionToken {
        match self {
            Self::Answered { token, .. }
            | Self::Undeliverable { token, .. }
            | Self::Exhausted { token, .. }
            | Self::Indeterminate { token, .. } => *token,
        }
    }

    /// Return the payload-free classification of this outcome.
    #[must_use]
    pub const fn kind(&self) -> CompletionKind {
        match self {
            Self::Answered { .. } => CompletionKind::Answered,
            Self::Undeliverable { .. } => CompletionKind::Undeliverable,
            Self::Exhausted { .. } => CompletionKind::Exhausted,
            Self::Indeterminate { .. } => CompletionKind::Indeterminate,
        }
    }
}

impl fmt::Debug for TransactionCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = formatter.debug_struct("TransactionCompletion");
        out.field("token", &self.token())
            .field("kind", &self.kind());
        match self {
            Self::Answered { attempt, .. } => {
                out.field("attempt", attempt).field("answer", &"<redacted>");
            }
            Self::Undeliverable {
                reason, attempts, ..
            } => {
                out.field("reason", reason).field("attempts", attempts);
            }
            Self::Exhausted { attempts, .. } => {
                out.field("attempts", attempts);
            }
            Self::Indeterminate {
                reason, attempts, ..
            } => {
                out.field("reason", reason).field("attempts", attempts);
            }
        }
        out.finish()
    }
}

/// Bounded evidence recorded when an answer arrives after completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LateAnswerEvidence {
    /// The attempt the late answer was correlated to.
    pub attempt: AttemptId,
    /// The kind of completion the transaction already delivered.
    pub completion: CompletionKind,
    /// Bounded count of late answers observed for this transaction.
    pub late_answer_count: u32,
}

/// Evidence for an answer that matches no retained attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnmatchedAnswerEvidence {
    /// The connection the answer arrived on.
    pub connection: DiameterConnectionToken,
    /// The answer's Hop-by-Hop identifier.
    pub hop_by_hop_identifier: u32,
}

/// Why an answer that matched a live attempt failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnswerRejectionReason {
    /// The message carries the request (R) bit and is not an answer.
    NotAnAnswer,
    /// The answer's End-to-End identifier differs from the request's.
    EndToEndMismatch,
    /// The answer's command code or application differs from the request's.
    CommandMismatch,
}

impl AnswerRejectionReason {
    /// Stable machine-readable rejection code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAnAnswer => "not_an_answer",
            Self::EndToEndMismatch => "end_to_end_mismatch",
            Self::CommandMismatch => "command_mismatch",
        }
    }
}

/// Bounded evidence for a matched but invalid answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnswerRejection {
    /// The attempt the invalid answer claimed to match.
    pub attempt: AttemptId,
    /// Why the answer was rejected.
    pub reason: AnswerRejectionReason,
    /// Bounded count of rejected answers observed for this transaction.
    pub rejected_answer_count: u32,
}

/// Disposition of one inbound answer after correlation.
///
/// Only [`Self::Completed`] carries a completion, and it is produced at most
/// once per transaction. Every other variant is bounded evidence only: no
/// application callback, no EAP advancement, no second session mutation may
/// be derived from them.
#[derive(Debug)]
pub enum AnswerDisposition {
    /// The transaction reached its single terminal completion.
    Completed(TransactionCompletion),
    /// The answer correlated to a retained attempt but the transaction
    /// already completed. Bounded evidence only.
    LateAnswer(LateAnswerEvidence),
    /// The answer matches no retained attempt on any connection.
    Unmatched(UnmatchedAnswerEvidence),
    /// The answer matched a live attempt but failed validation. The attempt
    /// remains in flight; bounded evidence only.
    Rejected(AnswerRejection),
}

/// Stable, redaction-safe failure of [`PendingRequestTable::track`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackError {
    /// The pending-transaction bound is reached.
    TableFull,
    /// The completion token value is already tracked or retained.
    DuplicateCompletionToken,
    /// Another pending transaction already uses this End-to-End identifier.
    DuplicateEndToEnd,
    /// The connection token is not registered.
    UnknownConnection,
    /// The connection lifetime was closed.
    ConnectionClosed,
    /// The connection's Hop-by-Hop allocation space is exhausted.
    HopByHopSpaceExhausted,
    /// The message is not a Diameter request (R bit clear).
    NotARequest,
    /// The request header or AVP region is malformed, or the message exceeds
    /// the configured size bound.
    MalformedRequest,
    /// The request lacks exactly one non-empty Origin-Host AVP.
    OriginHostInvalid,
}

impl TrackError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TableFull => "diameter_pending_track_table_full",
            Self::DuplicateCompletionToken => "diameter_pending_track_duplicate_token",
            Self::DuplicateEndToEnd => "diameter_pending_track_duplicate_end_to_end",
            Self::UnknownConnection => "diameter_pending_track_unknown_connection",
            Self::ConnectionClosed => "diameter_pending_track_connection_closed",
            Self::HopByHopSpaceExhausted => "diameter_pending_track_hop_by_hop_exhausted",
            Self::NotARequest => "diameter_pending_track_not_a_request",
            Self::MalformedRequest => "diameter_pending_track_malformed_request",
            Self::OriginHostInvalid => "diameter_pending_track_origin_host_invalid",
        }
    }
}

impl fmt::Display for TrackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for TrackError {}

/// Stable, redaction-safe failure of [`PendingRequestTable::failover`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverError {
    /// No transaction with this completion token value exists.
    UnknownTransaction,
    /// The transaction already reached its terminal completion.
    NotPending,
    /// The per-transaction attempt bound is reached. Map this to
    /// [`PendingRequestTable::finish_exhausted`] when the caller's retry
    /// policy is also exhausted.
    AttemptLimitReached,
    /// The alternate connection token is not registered.
    UnknownConnection,
    /// The alternate connection lifetime was closed.
    ConnectionClosed,
    /// The alternate connection's Hop-by-Hop allocation space is exhausted.
    HopByHopSpaceExhausted,
    /// The request pins a `Destination-Host`; the caller must assert the
    /// alternate can reach it ([`AlternateRoutability::DestinationAsserted`])
    /// or finish the transaction as undeliverable.
    FixedDestinationRequiresAssertion,
}

impl FailoverError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownTransaction => "diameter_pending_failover_unknown_transaction",
            Self::NotPending => "diameter_pending_failover_not_pending",
            Self::AttemptLimitReached => "diameter_pending_failover_attempt_limit",
            Self::UnknownConnection => "diameter_pending_failover_unknown_connection",
            Self::ConnectionClosed => "diameter_pending_failover_connection_closed",
            Self::HopByHopSpaceExhausted => "diameter_pending_failover_hop_by_hop_exhausted",
            Self::FixedDestinationRequiresAssertion => {
                "diameter_pending_failover_fixed_destination_requires_assertion"
            }
        }
    }
}

impl fmt::Display for FailoverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for FailoverError {}

/// Stable, redaction-safe failure of connection registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionTableError {
    /// The connection bound is reached.
    TableFull,
    /// The connection token is already registered. Connection tokens must be
    /// unique per transport lifetime; allocate a fresh token after reconnect.
    DuplicateConnection,
    /// The connection token is not registered.
    UnknownConnection,
}

impl ConnectionTableError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TableFull => "diameter_pending_connection_table_full",
            Self::DuplicateConnection => "diameter_pending_connection_duplicate",
            Self::UnknownConnection => "diameter_pending_connection_unknown",
        }
    }
}

impl fmt::Display for ConnectionTableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for ConnectionTableError {}

/// Stable, redaction-safe failure of transaction-scoped operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionAccessError {
    /// No transaction with this completion token value exists.
    UnknownTransaction,
    /// The transaction already reached its terminal completion.
    NotPending,
    /// No attempt with this identity exists on the transaction.
    UnknownAttempt,
    /// The attempt already terminated and cannot change disposition.
    AttemptNotInFlight,
    /// The transaction has no in-flight attempt to produce wire bytes for.
    NoLiveAttempt,
}

impl TransactionAccessError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownTransaction => "diameter_pending_access_unknown_transaction",
            Self::NotPending => "diameter_pending_access_not_pending",
            Self::UnknownAttempt => "diameter_pending_access_unknown_attempt",
            Self::AttemptNotInFlight => "diameter_pending_access_attempt_not_in_flight",
            Self::NoLiveAttempt => "diameter_pending_access_no_live_attempt",
        }
    }
}

impl fmt::Display for TransactionAccessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for TransactionAccessError {}

/// Stable, redaction-safe snapshot restore failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotRestoreError {
    /// The snapshot bytes are truncated, internally inconsistent, or carry
    /// trailing garbage.
    Malformed,
    /// The snapshot version is not supported by this build.
    UnsupportedVersion,
    /// The snapshot exceeds the configured table bounds.
    LimitExceeded,
    /// A record fails request validation or internal consistency checks.
    InvalidRecord,
}

impl SnapshotRestoreError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "diameter_pending_snapshot_malformed",
            Self::UnsupportedVersion => "diameter_pending_snapshot_unsupported_version",
            Self::LimitExceeded => "diameter_pending_snapshot_limit_exceeded",
            Self::InvalidRecord => "diameter_pending_snapshot_invalid_record",
        }
    }
}

impl fmt::Display for SnapshotRestoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for SnapshotRestoreError {}

/// Versioned, explicitly sensitive snapshot of all pending transactions.
///
/// The encoded form contains canonical request bytes, which may carry EAP
/// payloads, User-Name, Session-Id, realm, and destination identities. Store
/// it only in encrypted, integrity-protected storage; this crate deliberately
/// provides no plaintext persistence backend. The value is held in zeroizing
/// memory and its `Debug` representation is redacted.
///
/// Snapshots capture *pending* records only. Completed records are live-only
/// late-answer evidence and are never serialized.
pub struct PendingTableSnapshot {
    encoded: Zeroizing<Vec<u8>>,
}

impl PendingTableSnapshot {
    /// The snapshot format version emitted by this build.
    pub const VERSION: u16 = SNAPSHOT_VERSION;

    /// Borrow the encoded snapshot bytes for encrypted storage.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Return the encoded length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.encoded.len()
    }

    /// Return whether the encoded form is empty (it never is).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.encoded.is_empty()
    }
}

impl fmt::Debug for PendingTableSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingTableSnapshot")
            .field("version", &Self::VERSION)
            .field("len", &self.encoded.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordState {
    Pending,
    Completed { kind: CompletionKind, sequence: u64 },
}

impl RecordState {
    fn is_pending(self) -> bool {
        matches!(self, Self::Pending)
    }
}

struct TransactionRecord {
    token_value: CompletionTokenValue,
    generation: u64,
    command_code: CommandCode,
    application_id: ApplicationId,
    proxiable: bool,
    end_to_end_identifier: u32,
    fixed_destination: bool,
    raw_avps: Bytes,
    attempts: Vec<AttemptEvidence>,
    state: RecordState,
    late_answer_count: u32,
    rejected_answer_count: u32,
}

impl TransactionRecord {
    fn completion_token(&self) -> CompletionToken {
        CompletionToken {
            value: self.token_value,
            generation: self.generation,
        }
    }

    fn wire_message(&self, attempt: &AttemptEvidence) -> OwnedMessage {
        let mut bits = CommandFlags::request(self.proxiable).bits();
        if attempt.retransmission {
            bits |= CommandFlags::POTENTIALLY_RETRANSMITTED;
        }
        // Track-time validation bounds raw_avps to the configured message
        // limit, which never exceeds the 24-bit wire length field.
        let length = (DIAMETER_HEADER_LEN + self.raw_avps.len()) as u32;
        OwnedMessage {
            header: Header::new(
                CommandFlags::from_bits(bits),
                self.command_code,
                self.application_id,
                attempt.hop_by_hop_identifier,
                self.end_to_end_identifier,
            )
            .with_length(length),
            raw_avps: self.raw_avps.clone(),
        }
    }
}

/// Read-only view of one tracked pending-request transaction.
///
/// The view exposes the immutable request identity, the bounded attempt
/// history, and the completion state without exposing sensitive AVP values.
pub struct DiameterRequestTransaction<'a> {
    record: &'a TransactionRecord,
}

impl DiameterRequestTransaction<'_> {
    /// Return the stable completion identity and its current generation.
    #[must_use]
    pub fn completion_token(&self) -> CompletionToken {
        self.record.completion_token()
    }

    /// Return the immutable End-to-End identifier shared by every attempt.
    #[must_use]
    pub const fn end_to_end_identifier(&self) -> u32 {
        self.record.end_to_end_identifier
    }

    /// Return the immutable command code of the canonical request.
    #[must_use]
    pub const fn command_code(&self) -> CommandCode {
        self.record.command_code
    }

    /// Return the immutable application identifier of the canonical request.
    #[must_use]
    pub const fn application_id(&self) -> ApplicationId {
        self.record.application_id
    }

    /// Return whether the canonical request is proxiable (P bit).
    #[must_use]
    pub const fn is_proxiable(&self) -> bool {
        self.record.proxiable
    }

    /// Return whether the canonical request pins an explicit Destination-Host.
    #[must_use]
    pub const fn has_fixed_destination(&self) -> bool {
        self.record.fixed_destination
    }

    /// Return the bounded attempt history in attempt order.
    #[must_use]
    pub fn attempts(&self) -> &[AttemptEvidence] {
        &self.record.attempts
    }

    /// Return the completion classification once the transaction terminated.
    #[must_use]
    pub fn completion_kind(&self) -> Option<CompletionKind> {
        match self.record.state {
            RecordState::Pending => None,
            RecordState::Completed { kind, .. } => Some(kind),
        }
    }

    /// Return the bounded count of late answers observed after completion.
    #[must_use]
    pub const fn late_answer_count(&self) -> u32 {
        self.record.late_answer_count
    }

    /// Return the bounded count of matched-but-invalid answers observed.
    #[must_use]
    pub const fn rejected_answer_count(&self) -> u32 {
        self.record.rejected_answer_count
    }

    /// Return whether an answer for `candidate` matches the immutable
    /// Origin-Host of the canonical request.
    ///
    /// This is an equality oracle only; the Origin-Host value itself never
    /// leaves the transaction through a diagnostic representation.
    #[must_use]
    pub fn has_origin_host(&self, candidate: &str) -> bool {
        origin_host_matches(&self.record.raw_avps, candidate)
    }
}

impl fmt::Debug for DiameterRequestTransaction<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterRequestTransaction")
            .field("completion_token", &self.record.completion_token())
            .field("command_code", &self.record.command_code)
            .field("application_id", &self.record.application_id)
            .field("proxiable", &self.record.proxiable)
            .field("end_to_end_identifier", &self.record.end_to_end_identifier)
            .field("fixed_destination", &self.record.fixed_destination)
            .field("attempts", &self.record.attempts)
            .field("completion_kind", &self.completion_kind())
            .field("late_answer_count", &self.record.late_answer_count)
            .field("rejected_answer_count", &self.record.rejected_answer_count)
            .field("raw_avps", &"<redacted>")
            .finish()
    }
}

struct ConnectionEntry {
    next_hop_by_hop: u32,
    exhausted: bool,
    open: bool,
}

type AttemptKey = (u64, u32);

/// Bounded, cancellation-safe table of loss-safe pending-request failover
/// transactions.
///
/// The table owns RFC 6733 wire correctness for failover: per-connection
/// Hop-by-Hop uniqueness, T-bit handling, immutable End-to-End/Origin-Host
/// identity, answer correlation across every retained attempt, live
/// at-most-once completion, and the versioned sensitive snapshot form.
/// Attempt limits beyond the evidence bound, deadlines, peer selection, and
/// alternate routability remain caller policy.
///
/// Every operation is synchronous and takes `&mut self`; a terminal
/// completion is handed to the caller atomically with the state transition.
/// No future or callback is involved at this layer, so cancelling caller-side
/// work can neither lose the at-most-once guarantee nor re-deliver a
/// completion. After a crash, restored pending records deliver their
/// completion at-least-once unless the consumer durably claims delivery with
/// a compare-and-set on the [`CompletionToken`] before applying side effects.
pub struct PendingRequestTable {
    config: PendingRequestTableConfig,
    clock: Arc<dyn PendingRequestClock>,
    records: HashMap<CompletionTokenValue, TransactionRecord>,
    attempt_index: HashMap<AttemptKey, CompletionTokenValue>,
    pending_end_to_end: HashMap<u32, CompletionTokenValue>,
    connections: HashMap<u64, ConnectionEntry>,
    completion_sequence: u64,
    evicted_completions: u64,
    unmatched_answers: u64,
}

impl fmt::Debug for PendingRequestTable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingRequestTable")
            .field("config", &self.config)
            .field("pending_count", &self.pending_count())
            .field("retained_completed_count", &self.retained_completed_count())
            .field("connection_count", &self.connections.len())
            .field("evicted_completions", &self.evicted_completions)
            .field("unmatched_answers", &self.unmatched_answers)
            .finish()
    }
}

impl PendingRequestTable {
    /// Create an empty bounded table with an injected clock.
    pub fn new(
        config: PendingRequestTableConfig,
        clock: Arc<dyn PendingRequestClock>,
    ) -> Result<Self, PendingRequestConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            clock,
            records: HashMap::new(),
            attempt_index: HashMap::new(),
            pending_end_to_end: HashMap::new(),
            connections: HashMap::new(),
            completion_sequence: 0,
            evicted_completions: 0,
            unmatched_answers: 0,
        })
    }

    /// Register one connection lifetime with its caller-seeded Hop-by-Hop
    /// allocation start.
    ///
    /// The caller owns the Hop-by-Hop space of a connection outside this
    /// table (for example watchdog traffic); `first_hop_by_hop` must start a
    /// partition reserved for pending-request traffic. Within that partition
    /// the table allocates strictly increasing identifiers, which proves
    /// uniqueness on the connection for every attempt it emits.
    pub fn add_connection(
        &mut self,
        token: DiameterConnectionToken,
        first_hop_by_hop: u32,
    ) -> Result<(), ConnectionTableError> {
        if self.connections.contains_key(&token.get()) {
            return Err(ConnectionTableError::DuplicateConnection);
        }
        if self.connections.len() >= self.config.max_connections {
            return Err(ConnectionTableError::TableFull);
        }
        self.connections.insert(
            token.get(),
            ConnectionEntry {
                next_hop_by_hop: first_hop_by_hop,
                exhausted: false,
                open: true,
            },
        );
        Ok(())
    }

    /// Mark a connection lifetime closed. New attempts on it are rejected;
    /// in-flight attempts keep their evidence until the caller classifies
    /// them with [`Self::record_attempt_failure`] or
    /// [`Self::fail_connection_attempts`].
    pub fn close_connection(
        &mut self,
        token: DiameterConnectionToken,
    ) -> Result<(), ConnectionTableError> {
        let entry = self
            .connections
            .get_mut(&token.get())
            .ok_or(ConnectionTableError::UnknownConnection)?;
        entry.open = false;
        Ok(())
    }

    /// Track a canonical request on a registered connection.
    ///
    /// The request must be a Diameter request carrying exactly one non-empty
    /// Origin-Host; its AVP bytes become the immutable canonical form every
    /// attempt reuses. The first attempt is created immediately with T clear
    /// and a connection-unique Hop-by-Hop identifier. The caller-supplied
    /// token value becomes the durable identity of the transaction.
    pub fn track(
        &mut self,
        request: OwnedMessage,
        connection: DiameterConnectionToken,
        token_value: CompletionTokenValue,
    ) -> Result<CompletionToken, TrackError> {
        if self.records.contains_key(&token_value) {
            return Err(TrackError::DuplicateCompletionToken);
        }
        if self.pending_count() >= self.config.max_pending_transactions {
            return Err(TrackError::TableFull);
        }
        let facts = inspect_request(&request, self.decode_context())?;
        if self
            .pending_end_to_end
            .contains_key(&facts.end_to_end_identifier)
        {
            return Err(TrackError::DuplicateEndToEnd);
        }
        let hop_by_hop_identifier = self.allocate_hop_by_hop(connection)?;
        let now = self.clock.now();
        let attempt = AttemptEvidence {
            attempt_index: 0,
            connection,
            hop_by_hop_identifier,
            retransmission: false,
            disposition: AttemptDisposition::InFlight,
            started_at: now,
            ended_at: None,
        };
        let record = TransactionRecord {
            token_value,
            generation: 0,
            command_code: facts.command_code,
            application_id: facts.application_id,
            proxiable: facts.proxiable,
            end_to_end_identifier: facts.end_to_end_identifier,
            fixed_destination: facts.fixed_destination,
            raw_avps: request.raw_avps,
            attempts: vec![attempt],
            state: RecordState::Pending,
            late_answer_count: 0,
            rejected_answer_count: 0,
        };
        self.attempt_index
            .insert((connection.get(), hop_by_hop_identifier), token_value);
        self.pending_end_to_end
            .insert(facts.end_to_end_identifier, token_value);
        self.records.insert(token_value, record);
        Ok(CompletionToken {
            value: token_value,
            generation: 0,
        })
    }

    /// Borrow a read-only view of one tracked transaction.
    #[must_use]
    pub fn transaction(
        &self,
        token: CompletionTokenValue,
    ) -> Option<DiameterRequestTransaction<'_>> {
        self.records
            .get(&token)
            .map(|record| DiameterRequestTransaction { record })
    }

    /// Return the exact wire message for the transaction's latest in-flight
    /// attempt.
    ///
    /// The returned message reuses the canonical AVP bytes unchanged and only
    /// rewrites the header: the attempt's Hop-by-Hop identifier, the T bit for
    /// failover attempts, and the recomputed length. The caller writes these
    /// bytes to the attempt's connection and reports the outcome through
    /// [`Self::record_attempt_failure`].
    pub fn attempt_wire_message(
        &self,
        token: CompletionTokenValue,
    ) -> Result<OwnedMessage, TransactionAccessError> {
        let record = self
            .records
            .get(&token)
            .ok_or(TransactionAccessError::UnknownTransaction)?;
        let attempt = record
            .attempts
            .iter()
            .rev()
            .find(|attempt| attempt.disposition.is_in_flight())
            .ok_or(TransactionAccessError::NoLiveAttempt)?;
        Ok(record.wire_message(attempt))
    }

    /// Return the exact wire message for one recorded attempt, whether or not
    /// it is still in flight.
    ///
    /// This reproduces the bytes of any attempt retained in the bounded
    /// history — for audit, for evidence after completion, or to prove the
    /// canonical request was never rewritten across failover.
    pub fn wire_message_for_attempt(
        &self,
        token: CompletionTokenValue,
        attempt: AttemptId,
    ) -> Result<OwnedMessage, TransactionAccessError> {
        let record = self
            .records
            .get(&token)
            .ok_or(TransactionAccessError::UnknownTransaction)?;
        let attempt = record
            .attempts
            .iter()
            .find(|slot| slot.attempt_id() == attempt)
            .ok_or(TransactionAccessError::UnknownAttempt)?;
        Ok(record.wire_message(attempt))
    }

    /// Record the transport-reported failure classification of one attempt.
    ///
    /// The attempt must still be in flight. This only updates bounded
    /// evidence; whether and where to retransmit remains caller policy.
    pub fn record_attempt_failure(
        &mut self,
        token: CompletionTokenValue,
        attempt: AttemptId,
        failure: AttemptFailure,
    ) -> Result<AttemptEvidence, TransactionAccessError> {
        let record = self
            .records
            .get_mut(&token)
            .ok_or(TransactionAccessError::UnknownTransaction)?;
        let slot = record
            .attempts
            .iter_mut()
            .find(|slot| slot.attempt_id() == attempt)
            .ok_or(TransactionAccessError::UnknownAttempt)?;
        if !slot.disposition.is_in_flight() {
            return Err(TransactionAccessError::AttemptNotInFlight);
        }
        slot.disposition = failure.disposition();
        slot.ended_at = Some(self.clock.now());
        Ok(*slot)
    }

    /// Classify every in-flight attempt on a lost connection at once.
    ///
    /// Returns the number of attempts marked. Use
    /// [`Self::record_attempt_failure`] when the transport knows individual
    /// write outcomes.
    pub fn fail_connection_attempts(
        &mut self,
        connection: DiameterConnectionToken,
        failure: AttemptFailure,
    ) -> usize {
        let now = self.clock.now();
        let mut marked = 0usize;
        for record in self.records.values_mut() {
            for attempt in &mut record.attempts {
                if attempt.connection == connection && attempt.disposition.is_in_flight() {
                    attempt.disposition = failure.disposition();
                    attempt.ended_at = Some(now);
                    marked += 1;
                }
            }
        }
        marked
    }

    /// Start a failover (or restored) retransmission attempt on an alternate
    /// connection.
    ///
    /// The new attempt preserves the canonical request and End-to-End
    /// identifier, always sets T=1, and allocates a Hop-by-Hop identifier
    /// unique on the selected connection. A request pinning a
    /// `Destination-Host` requires
    /// [`AlternateRoutability::DestinationAsserted`]; otherwise the caller
    /// must finish the transaction with
    /// [`UndeliverableReason::FixedDestinationNoAlternate`]. The previous
    /// attempt need not be failed first: parallel in-flight attempts are
    /// legal, and only the first validated answer completes the transaction.
    pub fn failover(
        &mut self,
        token: CompletionTokenValue,
        connection: DiameterConnectionToken,
        routability: AlternateRoutability,
    ) -> Result<AttemptEvidence, FailoverError> {
        let (fixed_destination, attempt_index) = {
            let record = self
                .records
                .get(&token)
                .ok_or(FailoverError::UnknownTransaction)?;
            if !record.state.is_pending() {
                return Err(FailoverError::NotPending);
            }
            if record.attempts.len() >= self.config.max_attempts_per_transaction {
                return Err(FailoverError::AttemptLimitReached);
            }
            (record.fixed_destination, record.attempts.len())
        };
        if fixed_destination && routability == AlternateRoutability::RealmRouted {
            return Err(FailoverError::FixedDestinationRequiresAssertion);
        }
        let hop_by_hop_identifier = self.allocate_hop_by_hop(connection)?;
        let now = self.clock.now();
        let attempt = AttemptEvidence {
            attempt_index,
            connection,
            hop_by_hop_identifier,
            retransmission: true,
            disposition: AttemptDisposition::InFlight,
            started_at: now,
            ended_at: None,
        };
        let record = self
            .records
            .get_mut(&token)
            .ok_or(FailoverError::UnknownTransaction)?;
        record.attempts.push(attempt);
        self.attempt_index
            .insert((connection.get(), hop_by_hop_identifier), token);
        Ok(attempt)
    }

    /// Correlate one inbound answer to its pending transaction.
    ///
    /// The answer is matched by (connection, Hop-by-Hop), then validated
    /// against the request's End-to-End identifier, command code, and
    /// application. The first validated answer produces the transaction's
    /// single terminal completion; every later answer — late, duplicated,
    /// reordered, or arriving on the other connection — is bounded evidence
    /// only and never re-delivers a completion.
    pub fn correlate_answer(
        &mut self,
        connection: DiameterConnectionToken,
        answer: OwnedMessage,
    ) -> AnswerDisposition {
        let attempt_key = (connection.get(), answer.header.hop_by_hop_identifier);
        let Some(token) = self.attempt_index.get(&attempt_key).copied() else {
            self.unmatched_answers = self.unmatched_answers.saturating_add(1);
            return AnswerDisposition::Unmatched(UnmatchedAnswerEvidence {
                connection,
                hop_by_hop_identifier: answer.header.hop_by_hop_identifier,
            });
        };
        let attempt_id = AttemptId {
            connection,
            hop_by_hop_identifier: answer.header.hop_by_hop_identifier,
        };
        let now = self.clock.now();
        let record = match self.records.get_mut(&token) {
            Some(record) => record,
            None => {
                self.unmatched_answers = self.unmatched_answers.saturating_add(1);
                return AnswerDisposition::Unmatched(UnmatchedAnswerEvidence {
                    connection,
                    hop_by_hop_identifier: answer.header.hop_by_hop_identifier,
                });
            }
        };
        let rejection = if answer.header.flags.is_request() {
            Some(AnswerRejectionReason::NotAnAnswer)
        } else if answer.header.end_to_end_identifier != record.end_to_end_identifier {
            Some(AnswerRejectionReason::EndToEndMismatch)
        } else if answer.header.command_code != record.command_code
            || answer.header.application_id != record.application_id
        {
            Some(AnswerRejectionReason::CommandMismatch)
        } else {
            None
        };
        if let Some(reason) = rejection {
            record.rejected_answer_count = record.rejected_answer_count.saturating_add(1);
            return AnswerDisposition::Rejected(AnswerRejection {
                attempt: attempt_id,
                reason,
                rejected_answer_count: record.rejected_answer_count,
            });
        }
        match record.state {
            RecordState::Pending => {
                let attempt_slot = record
                    .attempts
                    .iter_mut()
                    .find(|slot| slot.attempt_id() == attempt_id);
                let Some(slot) = attempt_slot else {
                    self.unmatched_answers = self.unmatched_answers.saturating_add(1);
                    return AnswerDisposition::Unmatched(UnmatchedAnswerEvidence {
                        connection,
                        hop_by_hop_identifier: attempt_id.hop_by_hop_identifier,
                    });
                };
                slot.disposition = AttemptDisposition::Answered;
                slot.ended_at = Some(now);
                let attempt = *slot;
                record.generation = 1;
                let token_with_generation = record.completion_token();
                self.complete(token, CompletionKind::Answered);
                AnswerDisposition::Completed(TransactionCompletion::Answered {
                    token: token_with_generation,
                    answer,
                    attempt,
                })
            }
            RecordState::Completed { kind, .. } => {
                record.late_answer_count = record.late_answer_count.saturating_add(1);
                AnswerDisposition::LateAnswer(LateAnswerEvidence {
                    attempt: attempt_id,
                    completion: kind,
                    late_answer_count: record.late_answer_count,
                })
            }
        }
    }

    /// Terminate the transaction as undeliverable with a typed reason.
    ///
    /// Use [`UndeliverableReason::FixedDestinationNoAlternate`] when the
    /// request pins a `Destination-Host` and no valid alternate exists; the
    /// primitive never silently drops or rewrites the destination.
    pub fn finish_undeliverable(
        &mut self,
        token: CompletionTokenValue,
        reason: UndeliverableReason,
    ) -> Result<TransactionCompletion, TransactionAccessError> {
        let (completion_token, attempts) = self.begin_terminal(token)?;
        self.complete(token, CompletionKind::Undeliverable);
        Ok(TransactionCompletion::Undeliverable {
            token: completion_token,
            reason,
            attempts,
        })
    }

    /// Terminate the transaction because the caller's retry policy is
    /// exhausted.
    pub fn finish_exhausted(
        &mut self,
        token: CompletionTokenValue,
    ) -> Result<TransactionCompletion, TransactionAccessError> {
        let (completion_token, attempts) = self.begin_terminal(token)?;
        self.complete(token, CompletionKind::Exhausted);
        Ok(TransactionCompletion::Exhausted {
            token: completion_token,
            attempts,
        })
    }

    /// Terminate the transaction without a provable outcome.
    pub fn finish_indeterminate(
        &mut self,
        token: CompletionTokenValue,
        reason: IndeterminateReason,
    ) -> Result<TransactionCompletion, TransactionAccessError> {
        let (completion_token, attempts) = self.begin_terminal(token)?;
        self.complete(token, CompletionKind::Indeterminate);
        Ok(TransactionCompletion::Indeterminate {
            token: completion_token,
            reason,
            attempts,
        })
    }

    /// Drop one completed transaction and its attempt correlation evidence.
    ///
    /// Pending transactions cannot be retired; finish them first. Returns
    /// whether a completed record was removed.
    pub fn retire(&mut self, token: CompletionTokenValue) -> bool {
        let Some(record) = self.records.get(&token) else {
            return false;
        };
        if record.state.is_pending() {
            return false;
        }
        self.remove_record(token);
        true
    }

    /// Return the number of pending transactions.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.records
            .values()
            .filter(|record| record.state.is_pending())
            .count()
    }

    /// Return the number of completed transactions retained for late-answer
    /// evidence.
    #[must_use]
    pub fn retained_completed_count(&self) -> usize {
        self.records
            .values()
            .filter(|record| !record.state.is_pending())
            .count()
    }

    /// Return the number of registered connection lifetimes.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Return the bounded count of completed records evicted to hold the
    /// retention bound.
    #[must_use]
    pub const fn evicted_completion_count(&self) -> u64 {
        self.evicted_completions
    }

    /// Return the bounded count of answers that matched no retained attempt.
    #[must_use]
    pub const fn unmatched_answer_count(&self) -> u64 {
        self.unmatched_answers
    }

    /// Encode every pending transaction into the versioned, explicitly
    /// sensitive snapshot form.
    ///
    /// The snapshot contains canonical request bytes and must be stored only
    /// in encrypted, integrity-protected storage. Completed records are
    /// live-only and never serialized. Records are encoded in completion-token
    /// order so identical table states produce identical bytes.
    #[must_use]
    pub fn snapshot(&self) -> PendingTableSnapshot {
        let mut pending: Vec<&TransactionRecord> = self
            .records
            .values()
            .filter(|record| record.state.is_pending())
            .collect();
        pending.sort_by_key(|record| record.token_value);
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&SNAPSHOT_MAGIC.to_be_bytes());
        encoded.extend_from_slice(&SNAPSHOT_VERSION.to_be_bytes());
        push_count(&mut encoded, pending.len());
        for record in pending {
            encoded.extend_from_slice(&record.token_value.get().to_be_bytes());
            encoded.extend_from_slice(&record.generation.to_be_bytes());
            encoded.extend_from_slice(&record.end_to_end_identifier.to_be_bytes());
            encoded.extend_from_slice(&record.command_code.get().to_be_bytes());
            encoded.extend_from_slice(&record.application_id.get().to_be_bytes());
            let mut flags = 0_u8;
            if record.fixed_destination {
                flags |= 0x01;
            }
            if record.proxiable {
                flags |= 0x02;
            }
            encoded.push(flags);
            push_count(&mut encoded, record.attempts.len());
            for attempt in &record.attempts {
                encoded.extend_from_slice(&attempt.connection.get().to_be_bytes());
                encoded.extend_from_slice(&attempt.hop_by_hop_identifier.to_be_bytes());
                encoded.push(attempt.disposition.as_snapshot_code());
                encoded.extend_from_slice(&micros_of(attempt.started_at).to_be_bytes());
                match attempt.ended_at {
                    Some(ended) => {
                        encoded.extend_from_slice(&micros_of(ended).to_be_bytes());
                    }
                    None => {
                        encoded.extend_from_slice(&MICROS_SENTINEL_NONE.to_be_bytes());
                    }
                }
            }
            encoded.extend_from_slice(&(record.raw_avps.len() as u32).to_be_bytes());
            encoded.extend_from_slice(&record.raw_avps);
        }
        PendingTableSnapshot {
            encoded: Zeroizing::new(encoded),
        }
    }

    /// Restore a table from snapshot bytes previously written to durable
    /// (encrypted) storage.
    ///
    /// Malformed, truncated, or trailing-garbage input, unsupported versions,
    /// bound violations, and records that fail request validation are
    /// rejected with typed errors; nothing is partially restored. Restored
    /// records are pending with their full attempt history retained; re-arm
    /// each one with [`Self::failover`] onto a fresh connection, which
    /// retransmits with T=1 while preserving the End-to-End identifier and
    /// canonical request. Restored connection identities are historical
    /// evidence; register fresh connections before retransmitting.
    ///
    /// Delivery of a restored completion is **at-least-once**: the consumer
    /// may already have applied the completion before the crash. To make
    /// restored delivery idempotent, durably claim each completion with a
    /// compare-and-set on its stable [`CompletionToken`] value and generation
    /// before applying side effects, and skip deliveries whose token was
    /// already claimed. Both value and generation are preserved verbatim
    /// across repeated restores.
    pub fn restore(
        bytes: &[u8],
        config: PendingRequestTableConfig,
        clock: Arc<dyn PendingRequestClock>,
    ) -> Result<Self, SnapshotRestoreError> {
        config
            .validate()
            .map_err(|_| SnapshotRestoreError::LimitExceeded)?;
        let mut table = Self {
            config,
            clock,
            records: HashMap::new(),
            attempt_index: HashMap::new(),
            pending_end_to_end: HashMap::new(),
            connections: HashMap::new(),
            completion_sequence: 0,
            evicted_completions: 0,
            unmatched_answers: 0,
        };
        let mut cursor = SnapshotCursor::new(bytes);
        if cursor.u32()? != SNAPSHOT_MAGIC {
            return Err(SnapshotRestoreError::Malformed);
        }
        if cursor.u16()? != SNAPSHOT_VERSION {
            return Err(SnapshotRestoreError::UnsupportedVersion);
        }
        let record_count = cursor.count()?;
        if record_count > config.max_pending_transactions {
            return Err(SnapshotRestoreError::LimitExceeded);
        }
        for _ in 0..record_count {
            let record = table.restore_record(&mut cursor)?;
            table.index_restored_record(record)?;
        }
        if !cursor.is_exhausted() {
            return Err(SnapshotRestoreError::Malformed);
        }
        Ok(table)
    }

    fn decode_context(&self) -> DecodeContext {
        DecodeContext {
            max_message_len: self.config.max_message_len,
            ..DecodeContext::conservative()
        }
    }

    fn allocate_hop_by_hop(
        &mut self,
        connection: DiameterConnectionToken,
    ) -> Result<u32, HopByHopAllocateError> {
        let entry = self
            .connections
            .get_mut(&connection.get())
            .ok_or(HopByHopAllocateError::UnknownConnection)?;
        if !entry.open {
            return Err(HopByHopAllocateError::ConnectionClosed);
        }
        if entry.exhausted {
            return Err(HopByHopAllocateError::Exhausted);
        }
        let allocated = entry.next_hop_by_hop;
        if allocated == u32::MAX {
            entry.exhausted = true;
        } else {
            entry.next_hop_by_hop = allocated + 1;
        }
        Ok(allocated)
    }

    fn begin_terminal(
        &mut self,
        token: CompletionTokenValue,
    ) -> Result<(CompletionToken, usize), TransactionAccessError> {
        let record = self
            .records
            .get_mut(&token)
            .ok_or(TransactionAccessError::UnknownTransaction)?;
        if !record.state.is_pending() {
            return Err(TransactionAccessError::NotPending);
        }
        record.generation = 1;
        Ok((record.completion_token(), record.attempts.len()))
    }

    fn complete(&mut self, token: CompletionTokenValue, kind: CompletionKind) {
        self.completion_sequence = self.completion_sequence.saturating_add(1);
        let sequence = self.completion_sequence;
        if let Some(record) = self.records.get_mut(&token) {
            record.state = RecordState::Completed { kind, sequence };
        }
        if let Some(record) = self.records.get(&token) {
            self.pending_end_to_end
                .remove(&record.end_to_end_identifier);
        }
        while self.retained_completed_count() > self.config.max_retained_completions {
            let Some(oldest) = self
                .records
                .iter()
                .filter_map(|(value, record)| match record.state {
                    RecordState::Completed { sequence, .. } => Some((*value, sequence)),
                    RecordState::Pending => None,
                })
                .min_by_key(|(_, sequence)| *sequence)
                .map(|(value, _)| value)
            else {
                break;
            };
            self.remove_record(oldest);
            self.evicted_completions = self.evicted_completions.saturating_add(1);
        }
    }

    fn remove_record(&mut self, token: CompletionTokenValue) {
        if let Some(record) = self.records.remove(&token) {
            for attempt in &record.attempts {
                self.attempt_index
                    .remove(&(attempt.connection.get(), attempt.hop_by_hop_identifier));
            }
            self.pending_end_to_end
                .remove(&record.end_to_end_identifier);
        }
    }

    fn restore_record(
        &self,
        cursor: &mut SnapshotCursor<'_>,
    ) -> Result<TransactionRecord, SnapshotRestoreError> {
        let token_bits = cursor.u128()?;
        let token_value = CompletionTokenValue::new(
            NonZeroU128::new(token_bits).ok_or(SnapshotRestoreError::InvalidRecord)?,
        );
        let generation = cursor.u64()?;
        if generation != 0 {
            return Err(SnapshotRestoreError::InvalidRecord);
        }
        let end_to_end_identifier = cursor.u32()?;
        let command_code = CommandCode::new(cursor.u32()?);
        if !command_code.fits_wire() {
            return Err(SnapshotRestoreError::InvalidRecord);
        }
        let application_id = ApplicationId::new(cursor.u32()?);
        let flags = cursor.u8()?;
        if flags & !0x03 != 0 {
            return Err(SnapshotRestoreError::InvalidRecord);
        }
        let fixed_destination = flags & 0x01 != 0;
        let proxiable = flags & 0x02 != 0;
        let attempt_count = cursor.count()?;
        if attempt_count == 0 || attempt_count > self.config.max_attempts_per_transaction {
            return Err(SnapshotRestoreError::LimitExceeded);
        }
        let mut attempts = Vec::with_capacity(attempt_count);
        for attempt_index in 0..attempt_count {
            let connection_bits = cursor.u64()?;
            let connection = DiameterConnectionToken::new(
                NonZeroU64::new(connection_bits).ok_or(SnapshotRestoreError::InvalidRecord)?,
            );
            let hop_by_hop_identifier = cursor.u32()?;
            let disposition = AttemptDisposition::from_snapshot_code(cursor.u8()?)?;
            if disposition == AttemptDisposition::Answered {
                return Err(SnapshotRestoreError::InvalidRecord);
            }
            let started_at = Duration::from_micros(cursor.u64()?);
            let ended_bits = cursor.u64()?;
            let ended_at = if ended_bits == MICROS_SENTINEL_NONE {
                None
            } else {
                Some(Duration::from_micros(ended_bits))
            };
            if ended_at.is_none() != disposition.is_in_flight() {
                return Err(SnapshotRestoreError::InvalidRecord);
            }
            attempts.push(AttemptEvidence {
                attempt_index,
                connection,
                hop_by_hop_identifier,
                retransmission: attempt_index > 0,
                disposition,
                started_at,
                ended_at,
            });
        }
        let request_len = cursor.u32()? as usize;
        if request_len > self.config.max_message_len {
            return Err(SnapshotRestoreError::LimitExceeded);
        }
        let raw_avps = Bytes::copy_from_slice(cursor.take(request_len)?);
        let request = OwnedMessage {
            header: Header::new(
                CommandFlags::request(proxiable),
                command_code,
                application_id,
                0,
                end_to_end_identifier,
            ),
            raw_avps,
        };
        let facts = inspect_request(&request, self.decode_context())
            .map_err(|_| SnapshotRestoreError::InvalidRecord)?;
        if facts.fixed_destination != fixed_destination
            || facts.end_to_end_identifier != end_to_end_identifier
            || facts.command_code != command_code
            || facts.application_id != application_id
            || facts.proxiable != proxiable
        {
            return Err(SnapshotRestoreError::InvalidRecord);
        }
        Ok(TransactionRecord {
            token_value,
            generation,
            command_code,
            application_id,
            proxiable,
            end_to_end_identifier,
            fixed_destination,
            raw_avps: request.raw_avps,
            attempts,
            state: RecordState::Pending,
            late_answer_count: 0,
            rejected_answer_count: 0,
        })
    }

    fn index_restored_record(
        &mut self,
        record: TransactionRecord,
    ) -> Result<(), SnapshotRestoreError> {
        if self.records.contains_key(&record.token_value)
            || self
                .pending_end_to_end
                .contains_key(&record.end_to_end_identifier)
        {
            return Err(SnapshotRestoreError::InvalidRecord);
        }
        for attempt in &record.attempts {
            let key = (attempt.connection.get(), attempt.hop_by_hop_identifier);
            if self.attempt_index.contains_key(&key) {
                return Err(SnapshotRestoreError::InvalidRecord);
            }
            self.attempt_index.insert(key, record.token_value);
        }
        self.pending_end_to_end
            .insert(record.end_to_end_identifier, record.token_value);
        self.records.insert(record.token_value, record);
        Ok(())
    }
}

enum HopByHopAllocateError {
    UnknownConnection,
    ConnectionClosed,
    Exhausted,
}

impl From<HopByHopAllocateError> for TrackError {
    fn from(error: HopByHopAllocateError) -> Self {
        match error {
            HopByHopAllocateError::UnknownConnection => Self::UnknownConnection,
            HopByHopAllocateError::ConnectionClosed => Self::ConnectionClosed,
            HopByHopAllocateError::Exhausted => Self::HopByHopSpaceExhausted,
        }
    }
}

impl From<HopByHopAllocateError> for FailoverError {
    fn from(error: HopByHopAllocateError) -> Self {
        match error {
            HopByHopAllocateError::UnknownConnection => Self::UnknownConnection,
            HopByHopAllocateError::ConnectionClosed => Self::ConnectionClosed,
            HopByHopAllocateError::Exhausted => Self::HopByHopSpaceExhausted,
        }
    }
}

impl AttemptDisposition {
    fn as_snapshot_code(self) -> u8 {
        match self {
            Self::InFlight => 0,
            Self::FailedBeforeWrite => 1,
            Self::FailedUncertainWrite => 2,
            Self::TransportLostAfterWrite => 3,
            Self::Answered => 4,
        }
    }

    fn from_snapshot_code(code: u8) -> Result<Self, SnapshotRestoreError> {
        match code {
            0 => Ok(Self::InFlight),
            1 => Ok(Self::FailedBeforeWrite),
            2 => Ok(Self::FailedUncertainWrite),
            3 => Ok(Self::TransportLostAfterWrite),
            4 => Ok(Self::Answered),
            _ => Err(SnapshotRestoreError::InvalidRecord),
        }
    }
}

struct RequestFacts {
    command_code: CommandCode,
    application_id: ApplicationId,
    proxiable: bool,
    end_to_end_identifier: u32,
    fixed_destination: bool,
}

fn inspect_request(request: &OwnedMessage, ctx: DecodeContext) -> Result<RequestFacts, TrackError> {
    let header = &request.header;
    if !header.flags.is_request() {
        return Err(TrackError::NotARequest);
    }
    if header.flags.is_error()
        || header.flags.reserved_bits() != 0
        || !header.command_code.fits_wire()
    {
        return Err(TrackError::MalformedRequest);
    }
    // Duplicate occurrences are classified per-AVP below so an Origin-Host
    // duplication is reported as the identity violation it is, not as a
    // generic framing error.
    let framing_ctx = DecodeContext {
        duplicate_ie_policy: opc_protocol::DuplicateIePolicy::First,
        ..ctx
    };
    let borrowed = Message {
        header: header.clone(),
        raw_avps: &request.raw_avps,
        tail: &[],
    };
    borrowed
        .validate_avps(framing_ctx)
        .map_err(|_| TrackError::MalformedRequest)?;
    let mut origin_host_count = 0usize;
    let mut origin_host_nonempty = false;
    let mut fixed_destination = false;
    for avp in borrowed.avps(framing_ctx) {
        let avp = avp.map_err(|_| TrackError::MalformedRequest)?;
        if avp.header.vendor_id.is_none() && avp.header.code == base::AVP_ORIGIN_HOST {
            origin_host_count += 1;
            origin_host_nonempty = !avp.value.is_empty();
        }
        if avp.header.vendor_id.is_none() && avp.header.code == base::AVP_DESTINATION_HOST {
            fixed_destination = true;
        }
    }
    if origin_host_count != 1 || !origin_host_nonempty {
        return Err(TrackError::OriginHostInvalid);
    }
    if DIAMETER_HEADER_LEN + request.raw_avps.len() > ctx.max_message_len {
        return Err(TrackError::MalformedRequest);
    }
    Ok(RequestFacts {
        command_code: header.command_code,
        application_id: header.application_id,
        proxiable: header.flags.is_proxiable(),
        end_to_end_identifier: header.end_to_end_identifier,
        fixed_destination,
    })
}

fn origin_host_matches(raw_avps: &[u8], candidate: &str) -> bool {
    let ctx = DecodeContext::conservative();
    let message = Message {
        header: Header::new(
            CommandFlags::request(true),
            CommandCode::new(0),
            ApplicationId::new(0),
            0,
            0,
        ),
        raw_avps,
        tail: &[],
    };
    for avp in message.avps(ctx) {
        let Ok(avp) = avp else {
            return false;
        };
        if avp.header.vendor_id.is_none() && avp.header.code == base::AVP_ORIGIN_HOST {
            return avp.value == candidate.as_bytes();
        }
    }
    false
}

fn micros_of(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn push_count(encoded: &mut Vec<u8>, count: usize) {
    // Config validation caps every serialized count at u16::MAX.
    debug_assert!(count <= MAX_SERIALIZED_COUNT);
    encoded.extend_from_slice(&(count as u16).to_be_bytes());
}

struct SnapshotCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_exhausted(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SnapshotRestoreError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(SnapshotRestoreError::Malformed)?;
        if end > self.bytes.len() {
            return Err(SnapshotRestoreError::Malformed);
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, SnapshotRestoreError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SnapshotRestoreError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| SnapshotRestoreError::Malformed)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, SnapshotRestoreError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| SnapshotRestoreError::Malformed)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, SnapshotRestoreError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| SnapshotRestoreError::Malformed)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn u128(&mut self) -> Result<u128, SnapshotRestoreError> {
        let bytes: [u8; 16] = self
            .take(16)?
            .try_into()
            .map_err(|_| SnapshotRestoreError::Malformed)?;
        Ok(u128::from_be_bytes(bytes))
    }

    fn count(&mut self) -> Result<usize, SnapshotRestoreError> {
        Ok(usize::from(self.u16()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use bytes::BytesMut;
    use opc_protocol::{Encode, EncodeContext};

    #[derive(Debug, Default)]
    struct ManualClock(Mutex<Duration>);

    impl ManualClock {
        fn advance(&self, by: Duration) {
            let mut guard = match self.0.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *guard += by;
        }
    }

    impl PendingRequestClock for ManualClock {
        fn now(&self) -> Duration {
            let guard = match self.0.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *guard
        }
    }

    const CONNECTION_A: DiameterConnectionToken = DiameterConnectionToken::new(NonZeroU64::MIN);
    const CONNECTION_B: DiameterConnectionToken =
        DiameterConnectionToken::new(match NonZeroU64::new(2) {
            Some(value) => value,
            None => panic!("nonzero"),
        });
    const COMMAND: CommandCode = CommandCode::new(302);
    const APPLICATION: ApplicationId = ApplicationId::new(100);
    const SESSION_ID: &str = "session;private;unit";
    const ORIGIN_HOST: &str = "epdg.private.example";
    const USER_NAME: &str = "subscriber-private@example.invalid";
    const DESTINATION_HOST: &str = "aaa.private.example";
    const EAP_MARKER: [u8; 4] = [0xE4, 0xA9, 0x00, 0x11];

    fn token(value: u128) -> CompletionTokenValue {
        match NonZeroU128::new(value) {
            Some(value) => CompletionTokenValue::new(value),
            None => panic!("test token must be nonzero"),
        }
    }

    fn table(config: PendingRequestTableConfig) -> PendingRequestTable {
        match PendingRequestTable::new(config, Arc::new(ManualClock::default())) {
            Ok(table) => table,
            Err(error) => panic!("default config must be valid: {error}"),
        }
    }

    fn wire_avp(code: u32, value: &[u8]) -> Vec<u8> {
        let length = 8 + value.len();
        let mut wire = Vec::with_capacity((length + 3) & !3);
        wire.extend_from_slice(&code.to_be_bytes());
        wire.push(0x40);
        wire.extend_from_slice(&(length as u32).to_be_bytes()[1..]);
        wire.extend_from_slice(value);
        wire.resize((length + 3) & !3, 0);
        wire
    }

    const E2E: u32 = 0x0BAD_CAFE;

    fn canonical_request(destination_host: Option<&str>) -> OwnedMessage {
        canonical_request_on(destination_host, E2E)
    }

    fn canonical_request_on(destination_host: Option<&str>, end_to_end: u32) -> OwnedMessage {
        let mut avps = Vec::new();
        avps.extend(wire_avp(263, SESSION_ID.as_bytes()));
        avps.extend(wire_avp(264, ORIGIN_HOST.as_bytes()));
        avps.extend(wire_avp(296, b"private.realm.example"));
        avps.extend(wire_avp(283, b"home.private.example"));
        if let Some(host) = destination_host {
            avps.extend(wire_avp(293, host.as_bytes()));
        }
        avps.extend(wire_avp(1, USER_NAME.as_bytes()));
        avps.extend(wire_avp(462, &EAP_MARKER));
        OwnedMessage {
            header: Header::new(
                CommandFlags::request(true),
                COMMAND,
                APPLICATION,
                0,
                end_to_end,
            ),
            raw_avps: Bytes::copy_from_slice(&avps),
        }
    }

    fn answer_message(hop_by_hop: u32, end_to_end: u32) -> OwnedMessage {
        let mut avps = Vec::new();
        avps.extend(wire_avp(263, SESSION_ID.as_bytes()));
        avps.extend(wire_avp(264, DESTINATION_HOST.as_bytes()));
        avps.extend(wire_avp(296, b"home.private.example"));
        avps.extend(wire_avp(268, &2001_u32.to_be_bytes()));
        OwnedMessage {
            header: Header::new(
                CommandFlags::answer(true, false),
                COMMAND,
                APPLICATION,
                hop_by_hop,
                end_to_end,
            ),
            raw_avps: Bytes::copy_from_slice(&avps),
        }
    }

    fn encode(message: &OwnedMessage) -> BytesMut {
        let mut out = BytesMut::new();
        if let Err(error) = message.encode(&mut out, EncodeContext::default()) {
            panic!("test message must encode: {error}");
        }
        out
    }

    fn err_of<T, E>(result: Result<T, E>) -> E {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(error) => error,
        }
    }

    #[test]
    fn first_attempt_is_canonical_and_connection_unique() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|error| panic!("connection registration: {error}"));
        let first = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|error| panic!("track: {error}"));
        let second = table
            .track(canonical_request_on(None, E2E + 1), CONNECTION_A, token(2))
            .unwrap_or_else(|error| panic!("track: {error}"));
        assert_eq!(first.generation(), 0);
        assert_eq!(second.generation(), 0);

        let first_wire = table
            .attempt_wire_message(first.value())
            .unwrap_or_else(|error| panic!("wire message: {error}"));
        let second_wire = table
            .attempt_wire_message(second.value())
            .unwrap_or_else(|error| panic!("wire message: {error}"));
        assert_eq!(first_wire.header.hop_by_hop_identifier, 100);
        assert_eq!(second_wire.header.hop_by_hop_identifier, 101);
        assert!(!first_wire.header.flags.is_potentially_retransmitted());
        assert!(first_wire.header.flags.is_request());
        assert!(first_wire.header.flags.is_proxiable());
        assert_eq!(first_wire.header.end_to_end_identifier, 0x0BAD_CAFE);
        let canonical = canonical_request(None);
        assert_eq!(first_wire.raw_avps, canonical.raw_avps);
        // The encoded form is a complete, self-consistent Diameter message.
        assert_eq!(
            first_wire.header.length as usize,
            DIAMETER_HEADER_LEN + first_wire.raw_avps.len()
        );
        let encoded = encode(&first_wire);
        assert_eq!(encoded.len(), first_wire.header.length as usize);
    }

    #[test]
    fn failover_sets_t_and_preserves_semantic_identity() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .add_connection(CONNECTION_B, 900)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(
                canonical_request(Some(DESTINATION_HOST)),
                CONNECTION_A,
                token(7),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        let initial = table
            .attempt_wire_message(tracked.value())
            .unwrap_or_else(|e| panic!("{e}"));
        let attempt = table
            .failover(
                tracked.value(),
                CONNECTION_B,
                AlternateRoutability::DestinationAsserted,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(attempt.is_retransmission());
        assert_eq!(attempt.hop_by_hop_identifier(), 900);
        assert_eq!(attempt.attempt_index(), 1);
        let alternate_wire = table
            .attempt_wire_message(tracked.value())
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(alternate_wire.header.flags.is_potentially_retransmitted());
        assert_eq!(
            alternate_wire.header.end_to_end_identifier,
            initial.header.end_to_end_identifier
        );
        assert_eq!(alternate_wire.raw_avps, initial.raw_avps);
        let view = table
            .transaction(tracked.value())
            .unwrap_or_else(|| panic!("transaction view"));
        assert!(view.has_origin_host(ORIGIN_HOST));
        assert!(!view.has_origin_host("other.example"));
        assert!(view.has_fixed_destination());
        assert_eq!(view.attempts().len(), 2);
    }

    #[test]
    fn fixed_destination_requires_caller_assertion() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .add_connection(CONNECTION_B, 900)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(
                canonical_request(Some(DESTINATION_HOST)),
                CONNECTION_A,
                token(8),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        let error = err_of(table.failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        ));
        assert_eq!(error, FailoverError::FixedDestinationRequiresAssertion);
        let completion = table
            .finish_undeliverable(
                tracked.value(),
                UndeliverableReason::FixedDestinationNoAlternate,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(completion.kind(), CompletionKind::Undeliverable);
        assert_eq!(completion.token().generation(), 1);
    }

    #[test]
    fn duplicate_token_and_end_to_end_are_rejected() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            err_of(table.track(canonical_request(None), CONNECTION_A, token(1))),
            TrackError::DuplicateCompletionToken
        );
        assert_eq!(
            err_of(table.track(canonical_request(None), CONNECTION_A, token(2))),
            TrackError::DuplicateEndToEnd
        );
    }

    #[test]
    fn request_validation_rejects_non_requests_and_bad_origin_host() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            err_of(table.track(answer_message(1, 2), CONNECTION_A, token(1))),
            TrackError::NotARequest
        );
        let mut missing_origin = canonical_request(None);
        missing_origin.raw_avps = Bytes::copy_from_slice(&wire_avp(263, b"session"));
        assert_eq!(
            err_of(table.track(missing_origin, CONNECTION_A, token(2))),
            TrackError::OriginHostInvalid
        );
        let mut duplicate_origin = Vec::new();
        duplicate_origin.extend(wire_avp(264, b"a.example"));
        duplicate_origin.extend(wire_avp(264, b"b.example"));
        let duplicate = OwnedMessage {
            header: Header::new(CommandFlags::request(true), COMMAND, APPLICATION, 0, 9),
            raw_avps: Bytes::copy_from_slice(&duplicate_origin),
        };
        assert_eq!(
            err_of(table.track(duplicate, CONNECTION_A, token(3))),
            TrackError::OriginHostInvalid
        );
        let mut error_flagged = canonical_request(None);
        error_flagged.header.flags =
            CommandFlags::from_bits(CommandFlags::request(true).bits() | CommandFlags::ERROR);
        assert_eq!(
            err_of(table.track(error_flagged, CONNECTION_A, token(4))),
            TrackError::MalformedRequest
        );
    }

    #[test]
    fn hop_by_hop_allocation_is_strictly_increasing_per_connection() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, u32::MAX)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            err_of(table.track(canonical_request_on(None, E2E + 1), CONNECTION_A, token(2))),
            TrackError::HopByHopSpaceExhausted
        );
    }

    #[test]
    fn pending_bound_is_enforced() {
        let config = PendingRequestTableConfig {
            max_pending_transactions: 1,
            ..PendingRequestTableConfig::default()
        };
        let mut table = table(config);
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            err_of(table.track(canonical_request(None), CONNECTION_A, token(2))),
            TrackError::TableFull
        );
    }

    #[test]
    fn snapshot_round_trip_preserves_pending_records_and_identity() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .add_connection(CONNECTION_B, 900)
            .unwrap_or_else(|e| panic!("{e}"));
        let first = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        let second = table
            .track(
                canonical_request_on(Some(DESTINATION_HOST), E2E + 1),
                CONNECTION_A,
                token(2),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .failover(
                first.value(),
                CONNECTION_B,
                AlternateRoutability::RealmRouted,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        let first_attempt_id = {
            let view = table
                .transaction(first.value())
                .unwrap_or_else(|| panic!("view"));
            view.attempts()[0].attempt_id()
        };
        table
            .record_attempt_failure(
                first.value(),
                first_attempt_id,
                AttemptFailure::TransportLostAfterWrite,
            )
            .unwrap_or_else(|e| panic!("{e}"));

        let snapshot = table.snapshot();
        let restored = PendingRequestTable::restore(
            snapshot.as_bytes(),
            PendingRequestTableConfig::default(),
            Arc::new(ManualClock::default()),
        )
        .unwrap_or_else(|e| panic!("restore: {e}"));
        assert_eq!(restored.pending_count(), 2);
        let view = restored
            .transaction(first.value())
            .unwrap_or_else(|| panic!("restored view"));
        assert_eq!(view.completion_token(), first);
        assert_eq!(view.attempts().len(), 2);
        assert!(view.attempts()[1].is_retransmission());
        assert_eq!(
            view.attempts()[0].disposition(),
            AttemptDisposition::TransportLostAfterWrite
        );
        let fixed = restored
            .transaction(second.value())
            .unwrap_or_else(|| panic!("restored view"));
        assert!(fixed.has_fixed_destination());
        assert!(fixed.has_origin_host(ORIGIN_HOST));
        // Restored retransmission sets T=1 on a fresh connection.
        let mut restored = restored;
        restored
            .add_connection(
                DiameterConnectionToken::new(NonZeroU64::new(3).unwrap_or_else(|| panic!("nz"))),
                5000,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        let attempt = restored
            .failover(
                first.value(),
                DiameterConnectionToken::new(NonZeroU64::new(3).unwrap_or_else(|| panic!("nz"))),
                AlternateRoutability::RealmRouted,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(attempt.is_retransmission());
        assert_eq!(attempt.hop_by_hop_identifier(), 5000);
        let wire = restored
            .attempt_wire_message(first.value())
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(wire.header.flags.is_potentially_retransmitted());
        assert_eq!(wire.header.end_to_end_identifier, 0x0BAD_CAFE);
        assert_eq!(wire.raw_avps, canonical_request(None).raw_avps);
    }

    #[test]
    fn snapshot_excludes_completed_records() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        let wire = table
            .attempt_wire_message(tracked.value())
            .unwrap_or_else(|e| panic!("{e}"));
        let disposition = table.correlate_answer(
            CONNECTION_A,
            answer_message(wire.header.hop_by_hop_identifier, 0x0BAD_CAFE),
        );
        assert!(matches!(disposition, AnswerDisposition::Completed(_)));
        let snapshot = table.snapshot();
        let restored = PendingRequestTable::restore(
            snapshot.as_bytes(),
            PendingRequestTableConfig::default(),
            Arc::new(ManualClock::default()),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(restored.pending_count(), 0);
    }

    #[test]
    fn restore_rejects_malformed_stale_and_tampered_snapshots() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        let snapshot = table.snapshot();
        let bytes = snapshot.as_bytes().to_vec();

        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 0xFF;
        assert!(matches!(
            PendingRequestTable::restore(
                &bad_magic,
                PendingRequestTableConfig::default(),
                Arc::new(ManualClock::default())
            ),
            Err(SnapshotRestoreError::Malformed)
        ));

        let mut stale = bytes.clone();
        stale[4] = 0xFF;
        stale[5] = 0xFE;
        assert!(matches!(
            PendingRequestTable::restore(
                &stale,
                PendingRequestTableConfig::default(),
                Arc::new(ManualClock::default())
            ),
            Err(SnapshotRestoreError::UnsupportedVersion)
        ));

        for cut in [bytes.len() - 1, bytes.len() / 2, 7] {
            assert!(matches!(
                PendingRequestTable::restore(
                    &bytes[..cut],
                    PendingRequestTableConfig::default(),
                    Arc::new(ManualClock::default())
                ),
                Err(SnapshotRestoreError::Malformed)
                    | Err(SnapshotRestoreError::LimitExceeded)
                    | Err(SnapshotRestoreError::InvalidRecord)
            ));
        }

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            PendingRequestTable::restore(
                &trailing,
                PendingRequestTableConfig::default(),
                Arc::new(ManualClock::default())
            ),
            Err(SnapshotRestoreError::Malformed)
        ));

        // A zero completion token value is invalid.
        let mut zero_token = bytes.clone();
        for byte in &mut zero_token[8..24] {
            *byte = 0;
        }
        assert!(matches!(
            PendingRequestTable::restore(
                &zero_token,
                PendingRequestTableConfig::default(),
                Arc::new(ManualClock::default())
            ),
            Err(SnapshotRestoreError::InvalidRecord)
        ));

        // A pending record must not contain an answered attempt.
        let mut answered = bytes.clone();
        // Layout: magic(4) version(2) count(2) token(16) generation(8) e2e(4)
        // command(4) app(4) flags(1) attempts(2) conn(8) hbh(4) disposition(1)
        let disposition_offset = 8 + 16 + 8 + 4 + 4 + 4 + 1 + 2 + 8 + 4;
        answered[disposition_offset] = 4;
        assert!(matches!(
            PendingRequestTable::restore(
                &answered,
                PendingRequestTableConfig::default(),
                Arc::new(ManualClock::default())
            ),
            Err(SnapshotRestoreError::InvalidRecord)
        ));

        // Restore into a smaller table is a bound violation.
        let tight = PendingRequestTableConfig {
            max_pending_transactions: 0,
            ..PendingRequestTableConfig::default()
        };
        assert!(matches!(
            PendingRequestTable::restore(
                snapshot.as_bytes(),
                tight,
                Arc::new(ManualClock::default())
            ),
            Err(SnapshotRestoreError::LimitExceeded)
        ));
    }

    #[test]
    fn token_and_generation_are_stable_across_repeated_restores() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(42))
            .unwrap_or_else(|e| panic!("{e}"));
        let first_snapshot = table.snapshot();
        let first_restore = PendingRequestTable::restore(
            first_snapshot.as_bytes(),
            PendingRequestTableConfig::default(),
            Arc::new(ManualClock::default()),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let second_snapshot = first_restore.snapshot();
        assert_eq!(first_snapshot.as_bytes(), second_snapshot.as_bytes());
        let second_restore = PendingRequestTable::restore(
            second_snapshot.as_bytes(),
            PendingRequestTableConfig::default(),
            Arc::new(ManualClock::default()),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let view = second_restore
            .transaction(tracked.value())
            .unwrap_or_else(|| panic!("view"));
        assert_eq!(view.completion_token(), tracked);
        assert_eq!(view.completion_token().generation(), 0);
    }

    #[test]
    fn diagnostics_never_disclose_sensitive_values() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(
                canonical_request(Some(DESTINATION_HOST)),
                CONNECTION_A,
                token(1),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        let wire = table
            .attempt_wire_message(tracked.value())
            .unwrap_or_else(|e| panic!("{e}"));
        let snapshot = table.snapshot();
        let completion = match table.correlate_answer(
            CONNECTION_A,
            answer_message(wire.header.hop_by_hop_identifier, E2E),
        ) {
            AnswerDisposition::Completed(completion) => completion,
            other => panic!("expected completion, got {other:?}"),
        };
        let view = table
            .transaction(tracked.value())
            .unwrap_or_else(|| panic!("view"));
        let rendered = format!(
            "{table:?} {view:?} {completion:?} {snapshot:?} {:?} {:?}",
            view.attempts()[0],
            tracked
        );
        for marker in [
            SESSION_ID,
            ORIGIN_HOST,
            USER_NAME,
            DESTINATION_HOST,
            "private.realm.example",
            "home.private.example",
        ] {
            assert!(
                !rendered.contains(marker),
                "diagnostic representation leaked {marker}: {rendered}"
            );
        }
        // Raw request bytes (for example the EAP payload) must never appear
        // as a diagnostic byte sequence either.
        let eap_sequence = format!("{:?}", EAP_MARKER);
        let eap_inner = eap_sequence
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or_else(|| panic!("slice debug shape"));
        assert!(
            !rendered.contains(eap_inner),
            "leaked raw bytes: {rendered}"
        );
        // Snapshot bytes themselves hold the sensitive canonical request; only
        // the Debug representation is redacted.
        assert!(snapshot
            .as_bytes()
            .windows(SESSION_ID.len())
            .any(|window| window == SESSION_ID.as_bytes()));
    }

    #[test]
    fn config_validation_rejects_out_of_range_bounds() {
        for config in [
            PendingRequestTableConfig {
                max_pending_transactions: 0,
                ..PendingRequestTableConfig::default()
            },
            PendingRequestTableConfig {
                max_retained_completions: 0,
                ..PendingRequestTableConfig::default()
            },
            PendingRequestTableConfig {
                max_attempts_per_transaction: 0,
                ..PendingRequestTableConfig::default()
            },
            PendingRequestTableConfig {
                max_connections: 0,
                ..PendingRequestTableConfig::default()
            },
            PendingRequestTableConfig {
                max_message_len: DIAMETER_HEADER_LEN - 1,
                ..PendingRequestTableConfig::default()
            },
        ] {
            assert!(PendingRequestTable::new(config, Arc::new(ManualClock::default())).is_err());
        }
    }

    #[test]
    fn retire_removes_only_completed_records() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(!table.retire(tracked.value()));
        table
            .finish_exhausted(tracked.value())
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(table.retire(tracked.value()));
        assert!(table.transaction(tracked.value()).is_none());
    }

    #[test]
    fn connection_loss_marks_in_flight_attempts_with_typed_disposition() {
        let mut table = table(PendingRequestTableConfig::default());
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .add_connection(CONNECTION_B, 900)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .failover(
                tracked.value(),
                CONNECTION_B,
                AlternateRoutability::RealmRouted,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            table.fail_connection_attempts(CONNECTION_A, AttemptFailure::UncertainWrite),
            1
        );
        let (first_disposition, second_disposition, first_attempt_id) = {
            let view = table
                .transaction(tracked.value())
                .unwrap_or_else(|| panic!("view"));
            (
                view.attempts()[0].disposition(),
                view.attempts()[1].disposition(),
                view.attempts()[0].attempt_id(),
            )
        };
        assert_eq!(first_disposition, AttemptDisposition::FailedUncertainWrite);
        assert!(second_disposition.is_in_flight());
        // Already-terminated attempts are not reclassified.
        assert_eq!(
            table.fail_connection_attempts(CONNECTION_A, AttemptFailure::BeforeWrite),
            0
        );
        let error = match table.record_attempt_failure(
            tracked.value(),
            first_attempt_id,
            AttemptFailure::BeforeWrite,
        ) {
            Ok(_) => panic!("terminated attempt must reject reclassification"),
            Err(error) => error,
        };
        assert_eq!(error, TransactionAccessError::AttemptNotInFlight);
    }

    #[test]
    fn deterministic_clock_drives_attempt_evidence() {
        let clock = Arc::new(ManualClock::default());
        let mut table =
            match PendingRequestTable::new(PendingRequestTableConfig::default(), clock.clone()) {
                Ok(table) => table,
                Err(error) => panic!("{error}"),
            };
        table
            .add_connection(CONNECTION_A, 100)
            .unwrap_or_else(|e| panic!("{e}"));
        table
            .add_connection(CONNECTION_B, 900)
            .unwrap_or_else(|e| panic!("{e}"));
        let tracked = table
            .track(canonical_request(None), CONNECTION_A, token(1))
            .unwrap_or_else(|e| panic!("{e}"));
        clock.advance(Duration::from_millis(25));
        table
            .failover(
                tracked.value(),
                CONNECTION_B,
                AlternateRoutability::RealmRouted,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        clock.advance(Duration::from_millis(10));
        let (first_started, second_started, second_attempt_id) = {
            let view = table
                .transaction(tracked.value())
                .unwrap_or_else(|| panic!("view"));
            (
                view.attempts()[0].started_at(),
                view.attempts()[1].started_at(),
                view.attempts()[1].attempt_id(),
            )
        };
        assert_eq!(first_started, Duration::ZERO);
        assert_eq!(second_started, Duration::from_millis(25));
        let evidence = table
            .record_attempt_failure(
                tracked.value(),
                second_attempt_id,
                AttemptFailure::BeforeWrite,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(evidence.ended_at(), Some(Duration::from_millis(35)));
    }
}
