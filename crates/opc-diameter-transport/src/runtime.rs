//! Bounded full-duplex runtime for an admitted Diameter peer connection.

use std::fmt;
use std::net::Shutdown;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use opc_proto_diameter::base::{
    RESULT_CODE_DIAMETER_SUCCESS, RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY,
};
use opc_proto_diameter::error_answer::{
    build_diameter_error_answer, inspect_diameter_request, DiameterErrorAnswerGrammar,
    DiameterErrorOrigin, DiameterRequestFailure, DiameterRequestInspection,
};
use opc_proto_diameter::parser_error::DiameterParserError;
use opc_proto_diameter::peer::{
    build_device_watchdog_answer, build_device_watchdog_request, build_disconnect_peer_answer,
    build_disconnect_peer_request, parse_device_watchdog_answer,
    parse_device_watchdog_request_with_provenance, parse_disconnect_peer_answer,
    parse_disconnect_peer_request_with_provenance, AnswerDiagnostics, DeviceWatchdogAnswer,
    DeviceWatchdogRequest, DisconnectCause, DisconnectPeerAnswer, DisconnectPeerRequest,
    PeerCommandAdmission, PeerCommandClass, PeerMessageDirection, PeerSession, PeerSessionBlocker,
    PeerSessionGeneration, PeerSessionReadiness, PeerSessionSnapshot, PEER_DICTIONARIES,
};
use opc_proto_diameter::OwnedMessage;
use opc_protocol::{DecodeContext, ValidationLevel};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::time::Instant;

use crate::frame::{borrowed, encoded_bytes, read_runtime_frame, write_wire_frame};
use crate::tls::{retirement_required, DiameterTlsRuntimeParts};
use crate::{DiameterFrameLimits, DiameterTlsConnection, DiameterTlsError, DiameterTlsEvidence};

/// Explicit bounded queues used by a full-duplex Diameter peer runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiameterPeerRuntimeConfig {
    command_queue_capacity: NonZeroUsize,
    control_queue_capacity: NonZeroUsize,
    application_queue_capacity: NonZeroUsize,
    local_origin_state_id: Option<u32>,
    frame_completion_timeout: Duration,
    max_frame_write_duration: Duration,
}

impl DiameterPeerRuntimeConfig {
    /// Default maximum time from the first received header octet through the
    /// complete Diameter frame.
    pub const DEFAULT_FRAME_COMPLETION_TIMEOUT: Duration = Duration::from_secs(10);
    /// Default maximum time one emitted frame may hold the serialized writer.
    pub const DEFAULT_MAX_FRAME_WRITE_DURATION: Duration = Duration::from_secs(5);

    /// Create a runtime configuration. Control replies use a distinct queue so
    /// application backpressure cannot starve DWA or DPA transmission.
    pub const fn new(
        command_queue_capacity: NonZeroUsize,
        control_queue_capacity: NonZeroUsize,
        application_queue_capacity: NonZeroUsize,
        local_origin_state_id: Option<u32>,
    ) -> Result<Self, DiameterPeerRuntimeConfigError> {
        if command_queue_capacity.get() > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(DiameterPeerRuntimeConfigError::CommandQueueTooLarge);
        }
        if control_queue_capacity.get() > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(DiameterPeerRuntimeConfigError::ControlQueueTooLarge);
        }
        if application_queue_capacity.get() > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(DiameterPeerRuntimeConfigError::ApplicationQueueTooLarge);
        }
        Ok(Self {
            command_queue_capacity,
            control_queue_capacity,
            application_queue_capacity,
            local_origin_state_id,
            frame_completion_timeout: Self::DEFAULT_FRAME_COMPLETION_TIMEOUT,
            max_frame_write_duration: Self::DEFAULT_MAX_FRAME_WRITE_DURATION,
        })
    }

    /// Override bounded frame I/O durations. An entirely idle receive waits
    /// for peer activity; once the first octet arrives, `frame_completion`
    /// bounds completion of that frame. `max_frame_write` clamps every caller
    /// deadline so an application frame cannot indefinitely starve DWA/DPA.
    pub fn with_frame_io_timeouts(
        mut self,
        frame_completion: Duration,
        max_frame_write: Duration,
    ) -> Result<Self, DiameterPeerRuntimeConfigError> {
        if frame_completion.is_zero() {
            return Err(DiameterPeerRuntimeConfigError::FrameCompletionTimeoutZero);
        }
        if max_frame_write.is_zero() {
            return Err(DiameterPeerRuntimeConfigError::FrameWriteTimeoutZero);
        }
        let now = Instant::now();
        if now.checked_add(frame_completion).is_none() {
            return Err(DiameterPeerRuntimeConfigError::FrameCompletionTimeoutTooLarge);
        }
        if now.checked_add(max_frame_write).is_none() {
            return Err(DiameterPeerRuntimeConfigError::FrameWriteTimeoutTooLarge);
        }
        self.frame_completion_timeout = frame_completion;
        self.max_frame_write_duration = max_frame_write;
        Ok(self)
    }

    /// Maximum queued caller-originated writes.
    pub const fn command_queue_capacity(self) -> NonZeroUsize {
        self.command_queue_capacity
    }

    /// Maximum queued transport-owned watchdog or disconnect replies.
    pub const fn control_queue_capacity(self) -> NonZeroUsize {
        self.control_queue_capacity
    }

    /// Maximum admitted inbound application messages awaiting the consumer.
    pub const fn application_queue_capacity(self) -> NonZeroUsize {
        self.application_queue_capacity
    }

    /// Local Origin-State-Id placed in every runtime-built DWR, DWA, DPR, and
    /// DPA message.
    pub const fn local_origin_state_id(self) -> Option<u32> {
        self.local_origin_state_id
    }

    /// Maximum duration allowed to complete a frame after its first octet.
    pub const fn frame_completion_timeout(self) -> Duration {
        self.frame_completion_timeout
    }

    /// Maximum duration allowed for any one frame write.
    pub const fn max_frame_write_duration(self) -> Duration {
        self.max_frame_write_duration
    }
}

/// Invalid bounded queue configuration for a Diameter peer runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DiameterPeerRuntimeConfigError {
    /// The caller-originated command queue exceeds Tokio's safe semaphore bound.
    #[error("Diameter peer runtime command queue capacity is too large")]
    CommandQueueTooLarge,
    /// The transport-owned control queue exceeds Tokio's safe semaphore bound.
    #[error("Diameter peer runtime control queue capacity is too large")]
    ControlQueueTooLarge,
    /// The inbound application queue exceeds Tokio's safe semaphore bound.
    #[error("Diameter peer runtime application queue capacity is too large")]
    ApplicationQueueTooLarge,
    /// The partial-frame receive bound is zero.
    #[error("Diameter peer runtime frame completion timeout is zero")]
    FrameCompletionTimeoutZero,
    /// The partial-frame receive bound overflows the monotonic clock.
    #[error("Diameter peer runtime frame completion timeout is too large")]
    FrameCompletionTimeoutTooLarge,
    /// The per-frame write bound is zero.
    #[error("Diameter peer runtime frame write timeout is zero")]
    FrameWriteTimeoutZero,
    /// The per-frame write bound overflows the monotonic clock.
    #[error("Diameter peer runtime frame write timeout is too large")]
    FrameWriteTimeoutTooLarge,
}

impl DiameterPeerRuntimeConfigError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommandQueueTooLarge => "diameter_peer_runtime_command_queue_too_large",
            Self::ControlQueueTooLarge => "diameter_peer_runtime_control_queue_too_large",
            Self::ApplicationQueueTooLarge => "diameter_peer_runtime_application_queue_too_large",
            Self::FrameCompletionTimeoutZero => {
                "diameter_peer_runtime_frame_completion_timeout_zero"
            }
            Self::FrameCompletionTimeoutTooLarge => {
                "diameter_peer_runtime_frame_completion_timeout_too_large"
            }
            Self::FrameWriteTimeoutZero => "diameter_peer_runtime_frame_write_timeout_zero",
            Self::FrameWriteTimeoutTooLarge => {
                "diameter_peer_runtime_frame_write_timeout_too_large"
            }
        }
    }
}

/// RFC 3539 watchdog base interval (`Twinit`) before per-interval jitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiameterWatchdogTwinit(Duration);

impl DiameterWatchdogTwinit {
    /// RFC 3539 minimum base interval before jitter.
    pub const MINIMUM: Duration = Duration::from_secs(6);

    /// Validate a base watchdog interval.
    ///
    /// The runtime applies fresh RFC 3539 jitter whenever it starts or resets
    /// a pending watchdog interval. The caller applies jitter only when
    /// deciding when to make the initial probe attempt from the exposed
    /// inbound-activity clock.
    pub fn new(value: Duration) -> Result<Self, DiameterWatchdogTwinitError> {
        if value < Self::MINIMUM {
            return Err(DiameterWatchdogTwinitError::BelowMinimum);
        }
        let Some(maximum_effective) = value.checked_add(Duration::from_secs(2)) else {
            return Err(DiameterWatchdogTwinitError::TooLarge);
        };
        if Instant::now().checked_add(maximum_effective).is_none() {
            return Err(DiameterWatchdogTwinitError::TooLarge);
        }
        Ok(Self(value))
    }

    /// Return the caller-selected base `Twinit` before jitter.
    pub const fn get(self) -> Duration {
        self.0
    }

    /// Sample one effective interval using RFC 3539's -2 through +2 second
    /// jitter range. Callers use this for the initial idle schedule; the
    /// runtime calls it independently on every pending-Tw reset.
    pub fn sample_effective_interval(self) -> Duration {
        let jitter_seconds = rand::random_range(-2_i64..=2_i64);
        if jitter_seconds.is_negative() {
            self.get()
                .saturating_sub(Duration::from_secs(jitter_seconds.unsigned_abs()))
        } else {
            self.get()
                .saturating_add(Duration::from_secs(jitter_seconds.unsigned_abs()))
        }
    }
}

/// Invalid RFC 3539 watchdog interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DiameterWatchdogTwinitError {
    /// The base interval is below six seconds.
    #[error("Diameter watchdog Twinit is below the RFC 3539 minimum")]
    BelowMinimum,
    /// The interval cannot be represented by the local monotonic clock.
    #[error("Diameter watchdog interval is too large")]
    TooLarge,
}

impl DiameterWatchdogTwinitError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BelowMinimum => "diameter_watchdog_twinit_below_minimum",
            Self::TooLarge => "diameter_watchdog_twinit_too_large",
        }
    }
}

/// Redaction-safe aggregate activity observed by one peer runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiameterPeerActivity {
    sequence: u64,
    last_inbound: Instant,
    last_outbound: Instant,
}

impl DiameterPeerActivity {
    /// Monotonic count of successfully received or emitted Diameter frames.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Most recent successfully received frame time.
    pub const fn last_inbound(self) -> Instant {
        self.last_inbound
    }

    /// Most recent successfully emitted frame time.
    pub const fn last_outbound(self) -> Instant {
        self.last_outbound
    }

    /// Most recent inbound or outbound activity time.
    pub fn last_activity(self) -> Instant {
        self.last_inbound.max(self.last_outbound)
    }
}

/// Stable, redaction-safe full-duplex peer-runtime failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DiameterPeerRuntimeError {
    /// The TLS connection has not completed a successful CER/CEA exchange.
    #[error("Diameter peer runtime requires a negotiated connection")]
    NotNegotiated,
    /// Runtime ownership was requested without an entered Tokio runtime.
    #[error("Diameter peer runtime requires an active Tokio runtime")]
    RuntimeUnavailable,
    /// The underlying mutually authenticated TLS transport failed.
    #[error("Diameter peer runtime transport failed")]
    Transport(DiameterTlsError),
    /// A command was incompatible with the current peer-session state.
    #[error("Diameter peer runtime command was not admitted")]
    CommandNotAdmitted,
    /// A typed watchdog or disconnect message was malformed.
    #[error("Diameter peer runtime control message was invalid")]
    InvalidControlMessage,
    /// A control message's Diameter identity did not match the authenticated peer.
    #[error("Diameter peer runtime identity did not match")]
    PeerIdentityMismatch,
    /// A second local control request conflicts with one already outstanding.
    #[error("Diameter peer runtime transaction is already outstanding")]
    TransactionConflict,
    /// An answer did not match the exact outstanding request identifiers.
    #[error("Diameter peer runtime transaction did not match")]
    TransactionMismatch,
    /// An unexpected peer-base command was received after capability negotiation.
    #[error("Diameter peer runtime received a protocol-invalid command")]
    ProtocolViolation,
    /// A bounded internal or application-delivery queue was exhausted.
    #[error("Diameter peer runtime backpressure limit was reached")]
    Backpressure,
    /// A caller-supplied absolute operation deadline elapsed.
    #[error("Diameter peer runtime deadline exceeded")]
    DeadlineExceeded,
    /// The first RFC 3539 watchdog interval elapsed with a DWA pending; the
    /// connection is now suspect and remains open for one grace interval.
    #[error("Diameter peer entered watchdog suspect state")]
    WatchdogSuspect,
    /// Aggregate peer activity means a new DWR is not due yet.
    #[error("Diameter peer watchdog probe is not due")]
    WatchdogNotDue,
    /// A locally initiated graceful disconnect replaced the pending watchdog.
    #[error("Diameter peer watchdog was superseded by disconnect")]
    WatchdogSupersededByDisconnect,
    /// A runtime-owned correlation generation cannot be advanced safely.
    #[error("Diameter peer runtime correlation authority is exhausted")]
    CorrelationAuthorityExhausted,
    /// The local consumer closed the runtime or all user handles were dropped.
    #[error("Diameter peer runtime is closed")]
    Closed,
    /// A valid DPR/DPA exchange closed the peer connection. `peer_cause` is
    /// present only when the remote peer initiated the disconnect.
    #[error("Diameter peer disconnected")]
    PeerDisconnected {
        /// The peer's typed reconnect-policy signal, when peer initiated.
        peer_cause: Option<DisconnectCause>,
    },
}

impl DiameterPeerRuntimeError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotNegotiated => "diameter_peer_runtime_not_negotiated",
            Self::RuntimeUnavailable => "diameter_peer_runtime_unavailable",
            Self::Transport(_) => "diameter_peer_runtime_transport",
            Self::CommandNotAdmitted => "diameter_peer_runtime_command_not_admitted",
            Self::InvalidControlMessage => "diameter_peer_runtime_invalid_control_message",
            Self::PeerIdentityMismatch => "diameter_peer_runtime_peer_identity_mismatch",
            Self::TransactionConflict => "diameter_peer_runtime_transaction_conflict",
            Self::TransactionMismatch => "diameter_peer_runtime_transaction_mismatch",
            Self::ProtocolViolation => "diameter_peer_runtime_protocol_violation",
            Self::Backpressure => "diameter_peer_runtime_backpressure",
            Self::DeadlineExceeded => "diameter_peer_runtime_deadline_exceeded",
            Self::WatchdogSuspect => "diameter_peer_runtime_watchdog_suspect",
            Self::WatchdogNotDue => "diameter_peer_runtime_watchdog_not_due",
            Self::WatchdogSupersededByDisconnect => {
                "diameter_peer_runtime_watchdog_superseded_by_disconnect"
            }
            Self::CorrelationAuthorityExhausted => {
                "diameter_peer_runtime_correlation_authority_exhausted"
            }
            Self::Closed => "diameter_peer_runtime_closed",
            Self::PeerDisconnected { .. } => "diameter_peer_runtime_peer_disconnected",
        }
    }
}

impl From<DiameterTlsError> for DiameterPeerRuntimeError {
    fn from(error: DiameterTlsError) -> Self {
        Self::Transport(error)
    }
}

/// One admitted inbound application message and its protection evidence.
pub struct DiameterApplicationMessage {
    message: OwnedMessage,
    admission: PeerCommandAdmission,
}

impl DiameterApplicationMessage {
    /// Borrow the decoded application message.
    pub const fn message(&self) -> &OwnedMessage {
        &self.message
    }

    /// Consume this value and return the decoded application message.
    pub fn into_message(self) -> OwnedMessage {
        self.message
    }

    /// Exact generation and protection admission covering the message.
    pub const fn admission(&self) -> PeerCommandAdmission {
        self.admission
    }
}

impl fmt::Debug for DiameterApplicationMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterApplicationMessage")
            .field("message", &"<redacted>")
            .field("admission", &self.admission)
            .finish()
    }
}

/// Exclusive bounded receiver for admitted inbound application messages.
pub struct DiameterApplicationReceiver {
    receiver: mpsc::Receiver<DiameterApplicationMessage>,
    pending: Option<DiameterApplicationMessage>,
    terminal: watch::Receiver<Option<DiameterPeerRuntimeError>>,
    core: Arc<RuntimeCore>,
    shutdown: Arc<std::net::TcpStream>,
    closing: Arc<RuntimeClosing>,
}

impl DiameterApplicationReceiver {
    /// Receive the next application message. Terminal transport and protocol
    /// failures are returned instead of being hidden as an ordinary EOF.
    pub async fn receive(
        &mut self,
    ) -> Result<DiameterApplicationMessage, DiameterPeerRuntimeError> {
        let mut closing = self.closing.subscribe();
        loop {
            drop(self.core.active_state().await?);
            if let Some(message) = self.pending.take() {
                return Ok(message);
            }
            tokio::select! {
                biased;
                changed = self.terminal.changed() => {
                    if changed.is_err() {
                        return Err(self.core.terminate(DiameterPeerRuntimeError::Closed, true).await);
                    }
                }
                changed = closing.changed() => {
                    let _ = changed;
                    return Err(self.core.terminate(DiameterPeerRuntimeError::Closed, true).await);
                }
                message = self.receiver.recv() => {
                    let Some(message) = message else {
                        return wait_for_terminal(&self.core, &mut self.terminal).await;
                    };
                    // Reconcile material retirement and terminal publication
                    // after dequeue so a credential epoch change cannot release
                    // an already-buffered application message. Retain it on
                    // `self` before the next await so cancellation cannot
                    // silently discard an admitted frame.
                    self.pending = Some(message);
                }
            }
        }
    }
}

impl fmt::Debug for DiameterApplicationReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiameterApplicationReceiver(..)")
    }
}

impl Drop for DiameterApplicationReceiver {
    fn drop(&mut self) {
        // A runtime without its sole application consumer cannot safely
        // discard a future admitted message while continuing watchdog traffic.
        mark_closing(&self.closing, &self.shutdown);
    }
}

/// Cloneable command and observability handle for one peer runtime.
#[derive(Clone)]
pub struct DiameterPeerHandle {
    commands: mpsc::Sender<WriterCommand>,
    core: Arc<RuntimeCore>,
    evidence: DiameterTlsEvidence,
    _lifetime: Arc<RuntimeHandleLifetime>,
}

impl DiameterPeerHandle {
    /// Emit one admitted application message before the absolute deadline.
    pub async fn send_application(
        &self,
        message: OwnedMessage,
        deadline: Instant,
    ) -> Result<PeerCommandAdmission, DiameterPeerRuntimeError> {
        {
            let mut state = self.core.active_state().await?;
            if PeerCommandClass::from_header(&message.header) != PeerCommandClass::Application {
                return Err(DiameterPeerRuntimeError::CommandNotAdmitted);
            }
            // Fail safe before queueing so a product cannot declare inbound-DPR
            // quiescence while an application write is waiting behind the writer.
            state.application_quiesced = false;
        }
        let (result_tx, result_rx) = oneshot::channel();
        self.enqueue(
            WriterCommand::Application {
                message,
                deadline,
                result: result_tx,
            },
            deadline,
        )
        .await?;
        self.await_submitted(result_rx, deadline).await
    }

    /// Send a typed DWR after a true inbound-idle interval and await its exact
    /// correlated DWA. The caller uses [`Self::activity`] and its own initial
    /// RFC 3539 jitter to schedule the attempt; the runtime rejects attempts
    /// earlier than the minimum valid jittered `twinit` interval.
    /// `write_deadline` bounds queueing and emission. Once the DWR is on wire,
    /// the runtime applies fresh jitter whenever any inbound Diameter message
    /// resets Tw, so this future may legitimately outlive `write_deadline`.
    /// Identifier allocation and reconnect policy remain caller-owned.
    pub async fn probe_watchdog(
        &self,
        hop_by_hop_identifier: u32,
        end_to_end_identifier: u32,
        twinit: DiameterWatchdogTwinit,
        write_deadline: Instant,
    ) -> Result<DeviceWatchdogAnswer, DiameterPeerRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();
        let (started_tx, started_rx) = oneshot::channel();
        self.enqueue(
            WriterCommand::Watchdog {
                transaction: TransactionId::new(hop_by_hop_identifier, end_to_end_identifier),
                twinit,
                write_deadline,
                started: started_tx,
                result: result_tx,
            },
            write_deadline,
        )
        .await?;
        self.await_watchdog(started_rx, result_rx, write_deadline)
            .await
    }

    /// Send a typed DPR and await its exact correlated DPA. Once submitted,
    /// an unproven caller timeout, completion failure, or deadline terminally
    /// closes this runtime. Only a deadline that the enqueue or writer path
    /// proves it rejected before starting leaves the runtime active.
    pub async fn disconnect(
        &self,
        cause: DisconnectCause,
        hop_by_hop_identifier: u32,
        end_to_end_identifier: u32,
        deadline: Instant,
    ) -> Result<DisconnectPeerAnswer, DiameterPeerRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.enqueue(
            WriterCommand::Disconnect {
                transaction: TransactionId::new(hop_by_hop_identifier, end_to_end_identifier),
                cause,
                deadline,
                result: result_tx,
            },
            deadline,
        )
        .await?;
        self.await_submitted(result_rx, deadline).await
    }

    /// Return the exact authenticated TLS evidence retained by this runtime.
    pub const fn evidence(&self) -> &DiameterTlsEvidence {
        &self.evidence
    }

    /// Return the exact peer-session generation.
    pub fn generation(&self) -> PeerSessionGeneration {
        self.core.generation
    }

    /// Return a redaction-safe peer-session snapshot.
    pub async fn peer_session_snapshot(
        &self,
    ) -> Result<PeerSessionSnapshot, DiameterPeerRuntimeError> {
        Ok(self.core.active_state().await?.session.snapshot())
    }

    /// Return current peer readiness.
    pub async fn readiness(&self) -> Result<PeerSessionReadiness, DiameterPeerRuntimeError> {
        Ok(self.core.active_state().await?.session.readiness())
    }

    /// Return inbound and outbound frame activity. A caller can use
    /// [`DiameterPeerActivity::last_inbound`] to schedule a jittered watchdog
    /// attempt without relying only on application messages;
    /// [`Self::probe_watchdog`] still rechecks that inbound-idle clock
    /// atomically before emitting DWR. Outbound activity is observability only
    /// and does not postpone an RFC 3539 watchdog.
    pub async fn activity(&self) -> Result<DiameterPeerActivity, DiameterPeerRuntimeError> {
        Ok(self.core.active_state().await?.activity)
    }

    /// Declare whether product-owned application transactions are fully
    /// quiesced for an inbound DPR. The runtime defaults to false and
    /// automatically clears this declaration on every admitted inbound or
    /// outbound application message. A product must set true only after its
    /// own transaction ledger proves that no answer can still be in flight.
    pub async fn set_application_quiesced_for_disconnect(
        &self,
        quiesced: bool,
    ) -> Result<(), DiameterPeerRuntimeError> {
        self.core.active_state().await?.application_quiesced = quiesced;
        Ok(())
    }

    /// Terminally close this runtime and revoke its exact session generation.
    pub async fn close(&self) {
        self.core
            .terminate(DiameterPeerRuntimeError::Closed, true)
            .await;
    }

    async fn enqueue(
        &self,
        command: WriterCommand,
        deadline: Instant,
    ) -> Result<(), DiameterPeerRuntimeError> {
        let state = self.core.active_state().await?;
        if Instant::now() >= deadline {
            return Err(DiameterPeerRuntimeError::DeadlineExceeded);
        }
        let outcome = self.commands.try_send(command);
        drop(state);
        match outcome {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(DiameterPeerRuntimeError::Backpressure),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // The writer receiver is owned by its supervised task. Once
                // that channel closes, the supervisor is obliged to publish
                // the task's exact terminal cause. Waiting here avoids racing
                // that publication with a generic local `Closed` fallback.
                let mut terminal = self.core.terminal.subscribe();
                wait_for_terminal(&self.core, &mut terminal).await
            }
        }
    }

    async fn await_submitted<T>(
        &self,
        result: oneshot::Receiver<Result<T, DiameterPeerRuntimeError>>,
        deadline: Instant,
    ) -> Result<T, DiameterPeerRuntimeError> {
        await_submitted_result(&self.core, result, deadline).await
    }

    async fn await_watchdog(
        &self,
        mut started: oneshot::Receiver<()>,
        mut result: oneshot::Receiver<Result<DeviceWatchdogAnswer, DiameterPeerRuntimeError>>,
        write_deadline: Instant,
    ) -> Result<DeviceWatchdogAnswer, DiameterPeerRuntimeError> {
        let mut guard = SubmittedOperationGuard::new(
            Arc::clone(&self.core.shutdown),
            Arc::clone(&self.core.closing),
        );
        let mut terminal = self.core.terminal.subscribe();
        // Before emission, the caller's write deadline covers both queueing
        // and flush. After the DWR is flushed, the RFC watchdog timer owned by
        // the runtime determines completion and can be reset by inbound peer
        // activity.
        let prestart = tokio::select! {
            biased;
            response = &mut result => {
                match response {
                    Ok(response) => {
                        guard.disarm();
                        return response;
                    }
                    Err(_) => {
                        guard.disarm();
                        let mut fresh_terminal = self.core.terminal.subscribe();
                        return wait_for_terminal(&self.core, &mut fresh_terminal).await;
                    }
                }
            }
            started_result = &mut started => {
                WatchdogPrestart::Started(started_result.is_ok())
            }
            terminal = wait_for_terminal(&self.core, &mut terminal) => {
                guard.disarm();
                return prefer_committed_result(&mut result, terminal);
            }
            _ = tokio::time::sleep_until(write_deadline) => {
                WatchdogPrestart::Deadline
            }
        };
        let outcome = match prestart {
            WatchdogPrestart::Started(true) => self.await_result(result).await,
            WatchdogPrestart::Started(false) => {
                // A pre-emission validation failure is carried by `result`; a
                // task failure is followed by terminal publication. Do not
                // collapse either to Closed.
                self.await_result(result).await
            }
            WatchdogPrestart::Deadline => {
                match arbitrate_watchdog_write_deadline(&self.core, &mut started, &mut result).await
                {
                    WatchdogDeadlineOutcome::Complete(outcome) => outcome,
                    WatchdogDeadlineOutcome::Emitted => self.await_result(result).await,
                    WatchdogDeadlineOutcome::AwaitTerminal => {
                        let mut fresh_terminal = self.core.terminal.subscribe();
                        wait_for_terminal(&self.core, &mut fresh_terminal).await
                    }
                }
            }
        };
        guard.disarm();
        outcome
    }

    async fn await_result<T>(
        &self,
        result: oneshot::Receiver<Result<T, DiameterPeerRuntimeError>>,
    ) -> Result<T, DiameterPeerRuntimeError> {
        await_operation_result(&self.core, result).await
    }
}

async fn await_submitted_result<T>(
    core: &RuntimeCore,
    mut result: oneshot::Receiver<Result<T, DiameterPeerRuntimeError>>,
    deadline: Instant,
) -> Result<T, DiameterPeerRuntimeError> {
    let mut guard =
        SubmittedOperationGuard::new(Arc::clone(&core.shutdown), Arc::clone(&core.closing));
    let mut terminal = core.terminal.subscribe();
    let outcome = tokio::select! {
        biased;
        response = &mut result => {
            match response {
                Ok(response) => response,
                Err(_) => {
                    let mut fresh_terminal = core.terminal.subscribe();
                    wait_for_terminal(core, &mut fresh_terminal).await
                }
            }
        }
        terminal = wait_for_terminal(core, &mut terminal) => {
            prefer_committed_result(&mut result, terminal)
        },
        _ = tokio::time::sleep_until(deadline) => {
            match arbitrate_submitted_deadline(core, &mut result).await {
                SubmittedDeadlineOutcome::Complete(outcome) => outcome,
                SubmittedDeadlineOutcome::AwaitTerminal => {
                    let mut fresh_terminal = core.terminal.subscribe();
                    wait_for_terminal(core, &mut fresh_terminal).await
                }
            }
        }
    };
    guard.disarm();
    outcome
}

enum WatchdogPrestart {
    Started(bool),
    Deadline,
}

enum SubmittedDeadlineOutcome<T> {
    Complete(Result<T, DiameterPeerRuntimeError>),
    AwaitTerminal,
}

enum WatchdogDeadlineOutcome {
    Complete(Result<DeviceWatchdogAnswer, DiameterPeerRuntimeError>),
    Emitted,
    AwaitTerminal,
}

async fn arbitrate_submitted_deadline<T>(
    core: &RuntimeCore,
    result: &mut oneshot::Receiver<Result<T, DiameterPeerRuntimeError>>,
) -> SubmittedDeadlineOutcome<T> {
    let mut state = core.state.lock().await;
    match result.try_recv() {
        Ok(outcome) => SubmittedDeadlineOutcome::Complete(outcome),
        Err(oneshot::error::TryRecvError::Closed) => match state.terminal {
            Some(error) => SubmittedDeadlineOutcome::Complete(Err(error)),
            None => SubmittedDeadlineOutcome::AwaitTerminal,
        },
        Err(oneshot::error::TryRecvError::Empty) => {
            if let Some(error) = state.terminal {
                return SubmittedDeadlineOutcome::Complete(Err(error));
            }
            let contender = if core.closing.is_marked() {
                DiameterPeerRuntimeError::Closed
            } else if core.is_retired() {
                DiameterPeerRuntimeError::Transport(DiameterTlsError::Retired)
            } else {
                DiameterPeerRuntimeError::DeadlineExceeded
            };
            let _ = core.terminate_locked(&mut state, contender, true);
            SubmittedDeadlineOutcome::Complete(Err(state
                .terminal
                .unwrap_or(DiameterPeerRuntimeError::Closed)))
        }
    }
}

async fn arbitrate_watchdog_write_deadline(
    core: &RuntimeCore,
    started: &mut oneshot::Receiver<()>,
    result: &mut oneshot::Receiver<Result<DeviceWatchdogAnswer, DiameterPeerRuntimeError>>,
) -> WatchdogDeadlineOutcome {
    let mut state = core.state.lock().await;
    match result.try_recv() {
        Ok(outcome) => WatchdogDeadlineOutcome::Complete(outcome),
        Err(oneshot::error::TryRecvError::Closed) => match state.terminal {
            Some(error) => WatchdogDeadlineOutcome::Complete(Err(error)),
            None => WatchdogDeadlineOutcome::AwaitTerminal,
        },
        Err(oneshot::error::TryRecvError::Empty) => {
            if let Some(error) = state.terminal {
                return WatchdogDeadlineOutcome::Complete(Err(error));
            }
            match started.try_recv() {
                Ok(()) => return WatchdogDeadlineOutcome::Emitted,
                Err(oneshot::error::TryRecvError::Closed) => {
                    return match result.try_recv() {
                        Ok(outcome) => WatchdogDeadlineOutcome::Complete(outcome),
                        Err(_) => WatchdogDeadlineOutcome::AwaitTerminal,
                    };
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
            let contender = if core.closing.is_marked() {
                DiameterPeerRuntimeError::Closed
            } else if core.is_retired() {
                DiameterPeerRuntimeError::Transport(DiameterTlsError::Retired)
            } else {
                DiameterPeerRuntimeError::DeadlineExceeded
            };
            let _ = core.terminate_locked(&mut state, contender, true);
            WatchdogDeadlineOutcome::Complete(Err(state
                .terminal
                .unwrap_or(DiameterPeerRuntimeError::Closed)))
        }
    }
}

async fn await_operation_result<T>(
    core: &RuntimeCore,
    mut result: oneshot::Receiver<Result<T, DiameterPeerRuntimeError>>,
) -> Result<T, DiameterPeerRuntimeError> {
    let mut terminal = core.terminal.subscribe();
    tokio::select! {
        biased;
        response = &mut result => {
            match response {
                Ok(response) => response,
                Err(_) => wait_for_terminal(core, &mut terminal).await,
            }
        }
        terminal = wait_for_terminal(core, &mut terminal) => {
            prefer_committed_result(&mut result, terminal)
        },
    }
}

fn prefer_committed_result<T>(
    result: &mut oneshot::Receiver<Result<T, DiameterPeerRuntimeError>>,
    terminal: Result<T, DiameterPeerRuntimeError>,
) -> Result<T, DiameterPeerRuntimeError> {
    result.try_recv().unwrap_or(terminal)
}

impl fmt::Debug for DiameterPeerHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterPeerHandle")
            .field("generation", &self.core.generation)
            .field("evidence", &self.evidence)
            .finish_non_exhaustive()
    }
}

/// Owned full-duplex runtime before splitting command and receive halves.
pub struct DiameterPeerRuntime {
    handle: DiameterPeerHandle,
    receiver: DiameterApplicationReceiver,
}

impl DiameterPeerRuntime {
    /// Clone a command handle while retaining the exclusive receive half.
    pub fn handle(&self) -> DiameterPeerHandle {
        self.handle.clone()
    }

    /// Split the runtime into a cloneable command handle and exclusive receiver.
    pub fn into_parts(self) -> (DiameterPeerHandle, DiameterApplicationReceiver) {
        (self.handle, self.receiver)
    }
}

impl fmt::Debug for DiameterPeerRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterPeerRuntime")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

impl DiameterTlsConnection {
    /// Consume a successfully negotiated TLS/TCP connection into a bounded
    /// full-duplex runtime. Calling this before CER/CEA success fails closed.
    pub fn into_peer_runtime(
        mut self,
        config: DiameterPeerRuntimeConfig,
    ) -> Result<DiameterPeerRuntime, DiameterPeerRuntimeError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| DiameterPeerRuntimeError::RuntimeUnavailable)?;
        if !self.readiness()?.traffic_ready {
            return Err(DiameterPeerRuntimeError::NotNegotiated);
        }
        start_runtime(self.into_runtime_parts(), config, &runtime)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransactionId {
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
}

impl TransactionId {
    const fn new(hop_by_hop_identifier: u32, end_to_end_identifier: u32) -> Self {
        Self {
            hop_by_hop_identifier,
            end_to_end_identifier,
        }
    }

    const fn matches(self, message: &OwnedMessage) -> bool {
        self.hop_by_hop_identifier == message.header.hop_by_hop_identifier
            && self.end_to_end_identifier == message.header.end_to_end_identifier
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WatchdogAnswerAuthority {
    generation: PeerSessionGeneration,
    transaction: TransactionId,
}

impl WatchdogAnswerAuthority {
    const fn new(generation: PeerSessionGeneration, transaction: TransactionId) -> Self {
        Self {
            generation,
            transaction,
        }
    }

    fn authorizes(self, generation: PeerSessionGeneration, message: &OwnedMessage) -> bool {
        self.generation == generation
            && self.transaction.matches(message)
            && PeerCommandClass::from_header(&message.header) == PeerCommandClass::DeviceWatchdog
            && !message.header.flags.is_request()
    }
}

enum WriterCommand {
    Application {
        message: OwnedMessage,
        deadline: Instant,
        result: oneshot::Sender<Result<PeerCommandAdmission, DiameterPeerRuntimeError>>,
    },
    Watchdog {
        transaction: TransactionId,
        twinit: DiameterWatchdogTwinit,
        write_deadline: Instant,
        started: oneshot::Sender<()>,
        result: oneshot::Sender<Result<DeviceWatchdogAnswer, DiameterPeerRuntimeError>>,
    },
    Disconnect {
        transaction: TransactionId,
        cause: DisconnectCause,
        deadline: Instant,
        result: oneshot::Sender<Result<DisconnectPeerAnswer, DiameterPeerRuntimeError>>,
    },
}

enum ControlCommand {
    Watchdog {
        message: OwnedMessage,
        authority: WatchdogAnswerAuthority,
        deadline: Instant,
    },
    Error {
        message: OwnedMessage,
        deadline: Instant,
        completion: oneshot::Sender<Result<(), DiameterPeerRuntimeError>>,
    },
    Disconnect {
        message: OwnedMessage,
        answer: DisconnectPeerAnswer,
        peer_cause: DisconnectCause,
        deadline: Instant,
        interrupted_watchdog:
            Option<oneshot::Sender<Result<DeviceWatchdogAnswer, DiameterPeerRuntimeError>>>,
        completion: oneshot::Sender<Result<(), DiameterPeerRuntimeError>>,
    },
}

struct PendingWatchdog {
    incarnation: u64,
    transaction: TransactionId,
    twinit: DiameterWatchdogTwinit,
    timer_reset: watch::Sender<Instant>,
    result: Option<oneshot::Sender<Result<DeviceWatchdogAnswer, DiameterPeerRuntimeError>>>,
}

struct PendingDisconnect {
    incarnation: u64,
    transaction: TransactionId,
    result: oneshot::Sender<Result<DisconnectPeerAnswer, DiameterPeerRuntimeError>>,
    superseded_watchdog:
        Option<oneshot::Sender<Result<DeviceWatchdogAnswer, DiameterPeerRuntimeError>>>,
}

struct RuntimeState {
    session: PeerSession,
    terminal: Option<DiameterPeerRuntimeError>,
    pending_watchdog: Option<PendingWatchdog>,
    pending_disconnect: Option<PendingDisconnect>,
    next_watchdog_incarnation: u64,
    next_disconnect_incarnation: u64,
    activity: DiameterPeerActivity,
    application_quiesced: bool,
}

struct RuntimeCore {
    state: Mutex<RuntimeState>,
    terminal: watch::Sender<Option<DiameterPeerRuntimeError>>,
    shutdown: Arc<std::net::TcpStream>,
    closing: Arc<RuntimeClosing>,
    generation: PeerSessionGeneration,
    expected_peer: opc_proto_diameter::peer::PeerIdentity,
    frame_limits: DiameterFrameLimits,
    material_status: opc_tls::TlsMaterialStatusReceiver,
    admitted_epoch: opc_tls::TlsMaterialEpoch,
    hard_deadline: Instant,
    retired: Arc<std::sync::atomic::AtomicBool>,
    local_origin_state_id: Option<u32>,
    frame_completion_timeout: Duration,
    max_frame_write_duration: Duration,
}

impl RuntimeCore {
    fn terminal_error(&self) -> DiameterPeerRuntimeError {
        (*self.terminal.borrow()).unwrap_or(DiameterPeerRuntimeError::Closed)
    }

    fn is_retired(&self) -> bool {
        retirement_required(
            &self.material_status,
            self.admitted_epoch,
            self.hard_deadline,
            &self.retired,
        )
    }

    async fn ensure_active(&self) -> Result<(), DiameterPeerRuntimeError> {
        if let Some(error) = *self.terminal.borrow() {
            return Err(error);
        }
        if self.closing.is_marked() {
            return Err(self.terminate(DiameterPeerRuntimeError::Closed, true).await);
        }
        if self.is_retired() {
            let error = DiameterPeerRuntimeError::Transport(DiameterTlsError::Retired);
            return Err(self.terminate(error, true).await);
        }
        Ok(())
    }

    async fn active_state(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, RuntimeState>, DiameterPeerRuntimeError> {
        let state = self.state.lock().await;
        if let Some(error) = state.terminal {
            return Err(error);
        }
        if self.closing.is_marked() {
            drop(state);
            return Err(self.terminate(DiameterPeerRuntimeError::Closed, true).await);
        }
        if self.is_retired() {
            drop(state);
            let error = DiameterPeerRuntimeError::Transport(DiameterTlsError::Retired);
            return Err(self.terminate(error, true).await);
        }
        Ok(state)
    }

    async fn observe_inbound_activity(&self) -> Result<(), DiameterPeerRuntimeError> {
        let now = Instant::now();
        let mut state = self.active_state().await?;
        state.activity.sequence = state.activity.sequence.saturating_add(1);
        state.activity.last_inbound = now;
        let twinit = state
            .pending_watchdog
            .as_ref()
            .map(|pending| pending.twinit);
        if let Some(twinit) = twinit {
            state
                .session
                .watchdog_peer_activity_on(self.generation)
                .map_err(|_| DiameterPeerRuntimeError::CommandNotAdmitted)?;
            let deadline = jittered_watchdog_deadline(now, twinit, self.hard_deadline);
            if let Some(pending) = state.pending_watchdog.as_mut() {
                pending.timer_reset.send_replace(deadline);
            }
        }
        Ok(())
    }

    async fn terminate(
        &self,
        error: DiameterPeerRuntimeError,
        fail_session: bool,
    ) -> DiameterPeerRuntimeError {
        let _ = self.terminate_if(error, fail_session, |_| true).await;
        // `terminate_if` serializes terminal publication under `state`. A
        // competing closer may therefore win while this contender waits for
        // that lock. Public completion paths must return the published winner,
        // never the contender they happened to observe locally.
        self.terminal_error()
    }

    async fn terminate_if<P>(
        &self,
        error: DiameterPeerRuntimeError,
        fail_session: bool,
        predicate: P,
    ) -> bool
    where
        P: FnOnce(&RuntimeState) -> bool,
    {
        let mut state = self.state.lock().await;
        if state.terminal.is_some() || !predicate(&state) {
            false
        } else {
            self.terminate_locked(&mut state, error, fail_session)
        }
    }

    fn terminate_locked(
        &self,
        state: &mut RuntimeState,
        error: DiameterPeerRuntimeError,
        fail_session: bool,
    ) -> bool {
        self.terminate_locked_with(state, error, fail_session, || {})
    }

    fn terminate_locked_with<F>(
        &self,
        state: &mut RuntimeState,
        error: DiameterPeerRuntimeError,
        fail_session: bool,
        before_publish: F,
    ) -> bool
    where
        F: FnOnce(),
    {
        if state.terminal.is_some() {
            return false;
        }
        if fail_session {
            let _ = state
                .session
                .fail_on(self.generation, PeerSessionBlocker::SessionFailed);
        }
        let watchdog = state.pending_watchdog.take();
        let disconnect = state.pending_disconnect.take();
        // Full-close the socket before publishing terminal state or completing
        // a public operation. This ordering makes the observable terminal
        // boundary synchronous rather than a promise that a supervisor will
        // close it later.
        let _ = self.shutdown.shutdown(Shutdown::Both);
        state.terminal = Some(error);
        // Complete every live operation after the socket and state are
        // terminal but before watch/closing wakeups. On a multi-thread
        // executor this prevents a later terminal notification from preempting
        // the operation result committed by this winner.
        if let Some(mut pending) = watchdog {
            if let Some(result) = pending.result.take() {
                let _ = result.send(Err(error));
            }
        }
        if let Some(pending) = disconnect {
            if let Some(result) = pending.superseded_watchdog {
                let _ = result.send(Err(error));
            }
            let _ = pending.result.send(Err(error));
        }
        before_publish();
        self.terminal.send_replace(Some(error));
        self.closing.mark();
        true
    }

    fn classify_transport(&self, error: DiameterTlsError) -> DiameterPeerRuntimeError {
        if self.closing.is_marked() {
            self.terminal_error()
        } else if self.is_retired() {
            DiameterPeerRuntimeError::Transport(DiameterTlsError::Retired)
        } else {
            DiameterPeerRuntimeError::Transport(error)
        }
    }

    fn classify_write_deadline(&self) -> DiameterPeerRuntimeError {
        if self.closing.is_marked() {
            self.terminal_error()
        } else if self.is_retired() {
            DiameterPeerRuntimeError::Transport(DiameterTlsError::Retired)
        } else {
            DiameterPeerRuntimeError::DeadlineExceeded
        }
    }
}

async fn wait_for_terminal<T>(
    core: &RuntimeCore,
    terminal: &mut watch::Receiver<Option<DiameterPeerRuntimeError>>,
) -> Result<T, DiameterPeerRuntimeError> {
    let mut closing = core.closing.subscribe();
    loop {
        if let Some(error) = *terminal.borrow() {
            return Err(error);
        }
        if core.closing.is_marked() {
            return Err(core.terminate(DiameterPeerRuntimeError::Closed, true).await);
        }
        tokio::select! {
            biased;
            changed = terminal.changed() => {
                if changed.is_err() {
                    return Err(core.terminate(DiameterPeerRuntimeError::Closed, true).await);
                }
            }
            changed = closing.changed() => {
                let _ = changed;
                return Err(core.terminate(DiameterPeerRuntimeError::Closed, true).await);
            }
        }
    }
}

fn jittered_watchdog_deadline(
    now: Instant,
    twinit: DiameterWatchdogTwinit,
    hard_deadline: Instant,
) -> Instant {
    let effective = twinit.sample_effective_interval();
    now.checked_add(effective)
        .map_or(hard_deadline, |deadline| deadline.min(hard_deadline))
}

fn take_incarnation(next: &mut u64) -> Result<u64, DiameterPeerRuntimeError> {
    let incarnation = *next;
    *next = (*next)
        .checked_add(1)
        .ok_or(DiameterPeerRuntimeError::CorrelationAuthorityExhausted)?;
    Ok(incarnation)
}

struct RuntimeHandleLifetime {
    shutdown: Arc<std::net::TcpStream>,
    closing: Arc<RuntimeClosing>,
}

struct RuntimeSupervisorLifetime {
    shutdown: Arc<std::net::TcpStream>,
    closing: Arc<RuntimeClosing>,
}

struct SubmittedOperationGuard {
    shutdown: Arc<std::net::TcpStream>,
    closing: Arc<RuntimeClosing>,
    armed: bool,
}

struct RuntimeClosing {
    marked: AtomicBool,
    signal: watch::Sender<bool>,
}

impl RuntimeClosing {
    fn new() -> Self {
        let (signal, _) = watch::channel(false);
        Self {
            marked: AtomicBool::new(false),
            signal,
        }
    }

    fn mark(&self) {
        self.marked.store(true, Ordering::Release);
        self.signal.send_replace(true);
    }

    fn is_marked(&self) -> bool {
        self.marked.load(Ordering::Acquire)
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.signal.subscribe()
    }
}

impl SubmittedOperationGuard {
    fn new(shutdown: Arc<std::net::TcpStream>, closing: Arc<RuntimeClosing>) -> Self {
        Self {
            shutdown,
            closing,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SubmittedOperationGuard {
    fn drop(&mut self) {
        if self.armed {
            mark_closing(&self.closing, &self.shutdown);
        }
    }
}

impl Drop for RuntimeHandleLifetime {
    fn drop(&mut self) {
        mark_closing(&self.closing, &self.shutdown);
    }
}

impl Drop for RuntimeSupervisorLifetime {
    fn drop(&mut self) {
        // A dropped Tokio runtime aborts the reader, writer, and supervisor
        // together. Publish a synchronous closure marker from the supervisor
        // future's owned guard even when that future is never polled again.
        mark_closing(&self.closing, &self.shutdown);
    }
}

fn mark_closing(closing: &RuntimeClosing, shutdown: &std::net::TcpStream) {
    closing.mark();
    let _ = shutdown.shutdown(Shutdown::Both);
}

fn start_runtime(
    parts: DiameterTlsRuntimeParts,
    config: DiameterPeerRuntimeConfig,
    runtime: &tokio::runtime::Handle,
) -> Result<DiameterPeerRuntime, DiameterPeerRuntimeError> {
    let DiameterTlsRuntimeParts {
        io,
        shutdown,
        session,
        generation,
        evidence,
        expected_peer,
        frame_limits,
        material_status,
        hard_deadline,
        retired,
        retirement_task,
    } = parts;
    let admitted_epoch = evidence.material_epoch();
    let (terminal_tx, terminal_rx) = watch::channel(None);
    let closing = Arc::new(RuntimeClosing::new());
    let started_at = Instant::now();
    let core = Arc::new(RuntimeCore {
        state: Mutex::new(RuntimeState {
            session,
            terminal: None,
            pending_watchdog: None,
            pending_disconnect: None,
            next_watchdog_incarnation: 1,
            next_disconnect_incarnation: 1,
            activity: DiameterPeerActivity {
                sequence: 0,
                last_inbound: started_at,
                last_outbound: started_at,
            },
            application_quiesced: false,
        }),
        terminal: terminal_tx,
        shutdown: Arc::clone(&shutdown),
        closing: Arc::clone(&closing),
        generation,
        expected_peer: expected_peer.diameter_identity().clone(),
        frame_limits,
        material_status,
        admitted_epoch,
        hard_deadline,
        retired,
        local_origin_state_id: config.local_origin_state_id,
        frame_completion_timeout: config.frame_completion_timeout,
        max_frame_write_duration: config.max_frame_write_duration,
    });
    let (commands_tx, commands_rx) = mpsc::channel(config.command_queue_capacity.get());
    let (control_tx, control_rx) = mpsc::channel(config.control_queue_capacity.get());
    let (applications_tx, applications_rx) = mpsc::channel(config.application_queue_capacity.get());
    let (reader, writer) = tokio::io::split(io);

    let reader_core = Arc::clone(&core);
    let mut reader_task = runtime.spawn(async move {
        let outcome = reader_loop(
            reader,
            Arc::clone(&reader_core),
            control_tx,
            applications_tx,
        )
        .await;
        finish_runtime_task(&reader_core, outcome).await
    });
    let writer_core = Arc::clone(&core);
    let mut writer_task = runtime.spawn(async move {
        let outcome = writer_loop(writer, Arc::clone(&writer_core), commands_rx, control_rx).await;
        finish_runtime_task(&writer_core, outcome).await
    });
    let supervisor_core = Arc::clone(&core);
    let supervisor_lifetime = RuntimeSupervisorLifetime {
        shutdown: Arc::clone(&shutdown),
        closing: Arc::clone(&closing),
    };
    runtime.spawn(async move {
        let _supervisor_lifetime = supervisor_lifetime;
        let _retirement_task = retirement_task;
        let (error, reader_finished) = tokio::select! {
            outcome = &mut reader_task => (
                outcome.unwrap_or(Err(DiameterPeerRuntimeError::Transport(
                    DiameterTlsError::Transport,
                ))),
                true,
            ),
            outcome = &mut writer_task => (
                outcome.unwrap_or(Err(DiameterPeerRuntimeError::Transport(
                    DiameterTlsError::Transport,
                ))),
                false,
            ),
        };
        let terminal = error.err().unwrap_or(DiameterPeerRuntimeError::Closed);
        supervisor_core
            .terminate(
                terminal,
                !matches!(terminal, DiameterPeerRuntimeError::PeerDisconnected { .. }),
            )
            .await;
        if reader_finished {
            writer_task.abort();
            let _ = writer_task.await;
        } else {
            reader_task.abort();
            let _ = reader_task.await;
        }
    });

    let handle_lifetime = Arc::new(RuntimeHandleLifetime {
        shutdown: Arc::clone(&shutdown),
        closing: Arc::clone(&closing),
    });
    Ok(DiameterPeerRuntime {
        handle: DiameterPeerHandle {
            commands: commands_tx,
            core: Arc::clone(&core),
            evidence,
            _lifetime: handle_lifetime,
        },
        receiver: DiameterApplicationReceiver {
            receiver: applications_rx,
            pending: None,
            terminal: terminal_rx,
            core: Arc::clone(&core),
            shutdown,
            closing,
        },
    })
}

async fn finish_runtime_task(
    core: &RuntimeCore,
    outcome: Result<(), DiameterPeerRuntimeError>,
) -> Result<(), DiameterPeerRuntimeError> {
    let contender = outcome.err().unwrap_or(DiameterPeerRuntimeError::Closed);
    let winner = core
        .terminate(
            contender,
            !matches!(contender, DiameterPeerRuntimeError::PeerDisconnected { .. }),
        )
        .await;
    Err(winner)
}

async fn reader_loop<R>(
    mut reader: R,
    core: Arc<RuntimeCore>,
    control: mpsc::Sender<ControlCommand>,
    applications: mpsc::Sender<DiameterApplicationMessage>,
) -> Result<(), DiameterPeerRuntimeError>
where
    R: AsyncRead + Unpin,
{
    loop {
        core.ensure_active().await?;
        let message = read_runtime_frame(
            &mut reader,
            core.frame_limits,
            core.frame_completion_timeout,
            core.hard_deadline,
        )
        .await
        .map_err(|error| core.classify_transport(error))?;
        // RFC 3539 resets Tw for every structurally valid received Diameter
        // message, including transport-owned commands consumed below.
        core.observe_inbound_activity().await?;
        match PeerCommandClass::from_header(&message.header) {
            PeerCommandClass::Application => {
                let mut state = core.active_state().await?;
                let admission = state
                    .session
                    .admit_message(
                        core.generation,
                        PeerMessageDirection::Inbound,
                        &message.header,
                    )
                    .map_err(|_| DiameterPeerRuntimeError::CommandNotAdmitted)?;
                state.application_quiesced = false;
                let outcome =
                    applications.try_send(DiameterApplicationMessage { message, admission });
                drop(state);
                match outcome {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        return Err(DiameterPeerRuntimeError::Backpressure);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        // The exclusive receiver marks the runtime closing
                        // before it drops this channel. This reader is the task
                        // the supervisor is waiting on, so it must carry the
                        // local close cause rather than wait on itself.
                        return match core.ensure_active().await {
                            Err(error) => Err(error),
                            Ok(()) => Err(DiameterPeerRuntimeError::Closed),
                        };
                    }
                }
            }
            PeerCommandClass::DeviceWatchdog => {
                if message.header.flags.is_request() {
                    handle_watchdog_request(&core, &control, message).await?;
                } else {
                    handle_watchdog_answer(&core, message).await?;
                }
            }
            PeerCommandClass::DisconnectPeer => {
                if message.header.flags.is_request() {
                    let peer_cause = handle_disconnect_request(&core, &control, message).await?;
                    return Err(DiameterPeerRuntimeError::PeerDisconnected {
                        peer_cause: Some(peer_cause),
                    });
                }
                if handle_disconnect_answer(&core, message).await? {
                    return Err(DiameterPeerRuntimeError::PeerDisconnected { peer_cause: None });
                }
            }
            PeerCommandClass::CapabilitiesExchange => {
                return Err(DiameterPeerRuntimeError::ProtocolViolation);
            }
            _ => return Err(DiameterPeerRuntimeError::ProtocolViolation),
        }
    }
}

async fn handle_watchdog_request(
    core: &Arc<RuntimeCore>,
    control: &mpsc::Sender<ControlCommand>,
    message: OwnedMessage,
) -> Result<(), DiameterPeerRuntimeError> {
    let decode_ctx = strict_decode_context(core.frame_limits);
    let request =
        match parse_device_watchdog_request_with_provenance(&borrowed(&message), decode_ctx) {
            Ok(request) => request,
            Err(error) => {
                emit_bound_peer_error_answer(core, control, &message, &error, decode_ctx).await?;
                return Err(DiameterPeerRuntimeError::InvalidControlMessage);
            }
        };
    ensure_expected_identity(core, &request.identity)?;
    let (identity, authority) = {
        let mut state = core.active_state().await?;
        state
            .session
            .observe_watchdog_request_on(core.generation, &message.header, &request)
            .map_err(|_| DiameterPeerRuntimeError::CommandNotAdmitted)?;
        (
            state.session.local_capabilities().identity.clone(),
            WatchdogAnswerAuthority::new(
                core.generation,
                TransactionId::new(
                    message.header.hop_by_hop_identifier,
                    message.header.end_to_end_identifier,
                ),
            ),
        )
    };
    let answer = DeviceWatchdogAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        identity,
        origin_state_id: core.local_origin_state_id,
        diagnostics: AnswerDiagnostics::default(),
    };
    let answer = build_device_watchdog_answer(
        &answer,
        message.header.hop_by_hop_identifier,
        message.header.end_to_end_identifier,
        core.frame_limits.encode_context(),
    )
    .map_err(|_| DiameterPeerRuntimeError::InvalidControlMessage)?;
    let deadline = bounded_operation_deadline(
        Instant::now(),
        core.max_frame_write_duration,
        core.hard_deadline,
    );
    enqueue_control(
        core,
        control,
        ControlCommand::Watchdog {
            message: answer,
            authority,
            deadline,
        },
    )
    .await
}

async fn enqueue_control(
    core: &RuntimeCore,
    control: &mpsc::Sender<ControlCommand>,
    command: ControlCommand,
) -> Result<(), DiameterPeerRuntimeError> {
    let state = core.active_state().await?;
    let outcome = control.try_send(command);
    drop(state);
    match outcome {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => Err(DiameterPeerRuntimeError::Backpressure),
        Err(mpsc::error::TrySendError::Closed(_)) => {
            // The writer receiver is supervised independently of this reader.
            // Once it closes, wait for the supervisor to publish that task's
            // exact cause instead of masking it as queue backpressure.
            let mut terminal = core.terminal.subscribe();
            wait_for_terminal(core, &mut terminal).await
        }
    }
}

async fn await_control_completion(
    core: &RuntimeCore,
    completion: oneshot::Receiver<Result<(), DiameterPeerRuntimeError>>,
    deadline: Instant,
) -> Result<(), DiameterPeerRuntimeError> {
    match tokio::time::timeout_at(deadline, completion).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_)) => {
            // A queued control command is dropped when the supervised writer
            // exits. Its exact task cause is published immediately afterward;
            // do not let oneshot cancellation manufacture a generic close.
            let mut terminal = core.terminal.subscribe();
            wait_for_terminal(core, &mut terminal).await
        }
        Err(_) => Err(core.classify_transport(DiameterTlsError::DeadlineExceeded)),
    }
}

async fn emit_bound_peer_error_answer(
    core: &Arc<RuntimeCore>,
    control: &mpsc::Sender<ControlCommand>,
    request: &OwnedMessage,
    parser_error: &DiameterParserError,
    decode_ctx: DecodeContext,
) -> Result<(), DiameterPeerRuntimeError> {
    let request_wire = encoded_bytes(request, core.frame_limits)
        .map_err(|_| DiameterPeerRuntimeError::InvalidControlMessage)?;
    let envelope = match inspect_diameter_request(&request_wire, decode_ctx) {
        DiameterRequestInspection::Request(envelope) => envelope,
        DiameterRequestInspection::Unanswerable(_) => {
            return Err(DiameterPeerRuntimeError::InvalidControlMessage);
        }
    };
    let failure = DiameterRequestFailure::from_parser_error(
        &envelope,
        &request_wire,
        parser_error,
        decode_ctx,
        PEER_DICTIONARIES,
        core.frame_limits.encode_context(),
    )
    .map_err(|_| DiameterPeerRuntimeError::InvalidControlMessage)?;
    let identity = core
        .active_state()
        .await?
        .session
        .local_capabilities()
        .identity
        .clone();
    let origin = DiameterErrorOrigin::new(identity.origin_host, identity.origin_realm)
        .map_err(|_| DiameterPeerRuntimeError::InvalidControlMessage)?;
    let answer = build_diameter_error_answer(
        &envelope,
        &failure,
        &origin,
        DiameterErrorAnswerGrammar::Rfc6733ErrorBitFallback,
        core.frame_limits.encode_context(),
    )
    .map_err(|_| DiameterPeerRuntimeError::InvalidControlMessage)?
    .to_owned_message();
    let deadline = bounded_operation_deadline(
        Instant::now(),
        core.max_frame_write_duration,
        core.hard_deadline,
    );
    let (completion, completed) = oneshot::channel();
    enqueue_control(
        core,
        control,
        ControlCommand::Error {
            message: answer,
            deadline,
            completion,
        },
    )
    .await?;
    await_control_completion(core, completed, deadline).await
}

async fn handle_watchdog_answer(
    core: &Arc<RuntimeCore>,
    message: OwnedMessage,
) -> Result<(), DiameterPeerRuntimeError> {
    {
        let state = core.active_state().await?;
        let Some(pending) = state.pending_watchdog.as_ref() else {
            return Ok(());
        };
        if pending.transaction.hop_by_hop_identifier != message.header.hop_by_hop_identifier {
            return Ok(());
        }
    }
    let answer = parse_device_watchdog_answer(
        &borrowed(&message),
        strict_decode_context(core.frame_limits),
    )
    .map_err(|_| DiameterPeerRuntimeError::InvalidControlMessage)?;
    ensure_expected_identity(core, &answer.identity)?;
    {
        let mut state = core.active_state().await?;
        let Some(pending) = state.pending_watchdog.as_ref() else {
            return Ok(());
        };
        if pending.transaction.end_to_end_identifier != message.header.end_to_end_identifier {
            return Err(DiameterPeerRuntimeError::TransactionMismatch);
        }
        state
            .session
            .observe_watchdog_answer_on(core.generation, &message.header, &answer)
            .map_err(|_| DiameterPeerRuntimeError::CommandNotAdmitted)?;
        if let Some(mut pending) = state.pending_watchdog.take() {
            if let Some(result) = pending.result.take() {
                // Commit the correlated answer while terminal arbitration is
                // excluded by the state lock, so a concurrent closer cannot
                // preempt this already-observed DWA.
                let _ = result.send(Ok(answer));
            }
        }
    }
    Ok(())
}

async fn handle_disconnect_request(
    core: &Arc<RuntimeCore>,
    control: &mpsc::Sender<ControlCommand>,
    message: OwnedMessage,
) -> Result<DisconnectCause, DiameterPeerRuntimeError> {
    let decode_ctx = strict_decode_context(core.frame_limits);
    let request =
        match parse_disconnect_peer_request_with_provenance(&borrowed(&message), decode_ctx) {
            Ok(request) => request,
            Err(error) => {
                emit_bound_peer_error_answer(core, control, &message, &error, decode_ctx).await?;
                return Err(DiameterPeerRuntimeError::InvalidControlMessage);
            }
        };
    ensure_expected_identity(core, &request.identity)?;
    let (answer, interrupted_watchdog) = {
        let mut state = core.active_state().await?;
        state
            .session
            .observe_disconnect_request_on(core.generation, &message.header, &request)
            .map_err(|_| DiameterPeerRuntimeError::CommandNotAdmitted)?;
        let identity = state.session.local_capabilities().identity.clone();
        let (result_code, diagnostics) = if state.application_quiesced {
            (RESULT_CODE_DIAMETER_SUCCESS, AnswerDiagnostics::default())
        } else {
            (
                RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY,
                AnswerDiagnostics::default(),
            )
        };
        let answer = DisconnectPeerAnswer {
            result_code,
            identity,
            origin_state_id: core.local_origin_state_id,
            diagnostics,
        };
        let interrupted_watchdog = state
            .pending_watchdog
            .take()
            .and_then(|mut pending| pending.result.take());
        (answer, interrupted_watchdog)
    };
    let wire_answer = build_disconnect_peer_answer(
        &answer,
        message.header.hop_by_hop_identifier,
        message.header.end_to_end_identifier,
        core.frame_limits.encode_context(),
    )
    .map_err(|_| DiameterPeerRuntimeError::InvalidControlMessage)?;
    let (completion_tx, completion_rx) = oneshot::channel();
    let deadline = bounded_operation_deadline(
        Instant::now(),
        core.max_frame_write_duration,
        core.hard_deadline,
    );
    enqueue_control(
        core,
        control,
        ControlCommand::Disconnect {
            message: wire_answer,
            answer,
            peer_cause: request.disconnect_cause,
            deadline,
            interrupted_watchdog,
            completion: completion_tx,
        },
    )
    .await?;
    await_control_completion(core, completion_rx, deadline)
        .await
        .map(|()| request.disconnect_cause)
}

async fn handle_disconnect_answer(
    core: &Arc<RuntimeCore>,
    message: OwnedMessage,
) -> Result<bool, DiameterPeerRuntimeError> {
    {
        let state = core.active_state().await?;
        let Some(pending) = state.pending_disconnect.as_ref() else {
            return Ok(false);
        };
        if pending.transaction.hop_by_hop_identifier != message.header.hop_by_hop_identifier {
            return Ok(false);
        }
    }
    let answer = parse_disconnect_peer_answer(
        &borrowed(&message),
        strict_decode_context(core.frame_limits),
    )
    .map_err(|_| DiameterPeerRuntimeError::InvalidControlMessage)?;
    ensure_expected_identity(core, &answer.identity)?;
    {
        let mut state = core.active_state().await?;
        let Some(pending) = state.pending_disconnect.as_ref() else {
            return Ok(false);
        };
        if pending.transaction.end_to_end_identifier != message.header.end_to_end_identifier {
            return Err(DiameterPeerRuntimeError::TransactionMismatch);
        }
        state
            .session
            .observe_disconnect_answer_on(core.generation, &message.header, &answer)
            .map_err(|_| DiameterPeerRuntimeError::CommandNotAdmitted)?;
        let Some(mut pending) = state.pending_disconnect.take() else {
            return Ok(false);
        };
        let intended = DiameterPeerRuntimeError::PeerDisconnected { peer_cause: None };
        // Linearize successful local disconnect completion while holding the
        // same state lock used by every competing terminator. TCP is closed
        // before success becomes public; the exact result becomes ready before
        // terminal/closing watches wake, so the caller cannot observe a false
        // disconnect failure after receiving a valid correlated DPA.
        let _ = core.shutdown.shutdown(Shutdown::Both);
        state.terminal = Some(intended);
        if let Some(result) = pending.superseded_watchdog.take() {
            let _ = result.send(Err(
                DiameterPeerRuntimeError::WatchdogSupersededByDisconnect,
            ));
        }
        let _ = pending.result.send(Ok(answer));
        core.terminal.send_replace(Some(intended));
        core.closing.mark();
    }
    Ok(true)
}

async fn writer_loop<W>(
    mut writer: W,
    core: Arc<RuntimeCore>,
    mut commands: mpsc::Receiver<WriterCommand>,
    mut control: mpsc::Receiver<ControlCommand>,
) -> Result<(), DiameterPeerRuntimeError>
where
    W: AsyncWrite + Unpin,
{
    let mut terminal = core.terminal.subscribe();
    loop {
        core.ensure_active().await?;
        tokio::select! {
            biased;
            changed = terminal.changed() => {
                if changed.is_err() {
                    return Err(DiameterPeerRuntimeError::Closed);
                }
                return Err(core.terminal_error());
            }
            command = control.recv() => {
                let Some(command) = command else {
                    // The reader exclusively owns the control sender. Its EOF
                    // means that task has exited with the authoritative peer,
                    // protocol, or transport cause; let the supervisor publish
                    // that cause instead of racing it with a generic Closed.
                    return wait_for_terminal(&core, &mut terminal).await;
                };
                write_control(&mut writer, &core, command).await?;
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    return Err(DiameterPeerRuntimeError::Closed);
                };
                write_command(&mut writer, &core, command).await?;
            }
        }
    }
}

async fn write_control<W>(
    writer: &mut W,
    core: &Arc<RuntimeCore>,
    command: ControlCommand,
) -> Result<(), DiameterPeerRuntimeError>
where
    W: AsyncWrite + Unpin,
{
    match command {
        ControlCommand::Watchdog {
            message,
            authority,
            deadline,
        } => {
            if !authority.authorizes(core.generation, &message) {
                return Err(DiameterPeerRuntimeError::CommandNotAdmitted);
            }
            write_runtime_frame(writer, core, &message, deadline)
                .await
                .map(drop)
        }
        ControlCommand::Error {
            message,
            deadline,
            completion,
        } => match write_runtime_frame(writer, core, &message, deadline).await {
            Ok(mut state) => {
                let terminal = DiameterPeerRuntimeError::InvalidControlMessage;
                let _ = core.terminate_locked_with(&mut state, terminal, true, || {
                    // The malformed-request error answer is fully flushed.
                    // Wake its reader before publishing terminal watches so
                    // no later caller frame can cross this boundary.
                    let _ = completion.send(Ok(()));
                });
                let winner = state.terminal.unwrap_or(terminal);
                drop(state);
                Err(winner)
            }
            Err(error) => {
                let state = core.state.lock().await;
                let winner = state.terminal.unwrap_or(error);
                let _ = completion.send(Err(winner));
                drop(state);
                Err(winner)
            }
        },
        ControlCommand::Disconnect {
            message,
            answer,
            peer_cause,
            deadline,
            interrupted_watchdog,
            completion,
        } => {
            {
                let mut state = core.active_state().await?;
                state
                    .session
                    .disconnect_answer_sent_on(core.generation, &message.header, &answer)
                    .map_err(|_| DiameterPeerRuntimeError::CommandNotAdmitted)?;
            }
            match write_runtime_frame(writer, core, &message, deadline).await {
                Ok(mut state) => {
                    let terminal = DiameterPeerRuntimeError::PeerDisconnected {
                        peer_cause: Some(peer_cause),
                    };
                    let _ = core.terminate_locked_with(&mut state, terminal, false, || {
                        if let Some(result) = interrupted_watchdog {
                            let _ = result.send(Err(terminal));
                        }
                        let _ = completion.send(Ok(()));
                    });
                    let winner = state.terminal.unwrap_or(terminal);
                    drop(state);
                    Err(winner)
                }
                Err(error) => {
                    let state = core.state.lock().await;
                    let winner = state.terminal.unwrap_or(error);
                    if let Some(result) = interrupted_watchdog {
                        let _ = result.send(Err(winner));
                    }
                    let _ = completion.send(Err(winner));
                    drop(state);
                    Err(winner)
                }
            }
        }
    }
}

async fn write_command<W>(
    writer: &mut W,
    core: &Arc<RuntimeCore>,
    command: WriterCommand,
) -> Result<(), DiameterPeerRuntimeError>
where
    W: AsyncWrite + Unpin,
{
    match command {
        WriterCommand::Application {
            message,
            deadline,
            result,
        } => {
            let (admission, wire) = {
                let mut state = core.active_state().await?;
                if Instant::now() >= deadline {
                    let _ = result.send(Err(DiameterPeerRuntimeError::DeadlineExceeded));
                    return Ok(());
                }
                let wire = match encoded_bytes(&message, core.frame_limits) {
                    Ok(wire) => wire,
                    Err(error) => {
                        let _ = result.send(Err(DiameterPeerRuntimeError::Transport(error)));
                        return Ok(());
                    }
                };
                let admission = match state
                    .session
                    .admit_message(
                        core.generation,
                        PeerMessageDirection::Outbound,
                        &message.header,
                    )
                    .map_err(|_| DiameterPeerRuntimeError::CommandNotAdmitted)
                {
                    Ok(admission) => admission,
                    Err(error) => {
                        // Commit a pre-emission rejection while holding the
                        // same state lock that arbitrates a concurrent caller
                        // deadline or terminal close.
                        let _ = result.send(Err(error));
                        return Ok(());
                    }
                };
                state.application_quiesced = false;
                (admission, wire)
            };
            match write_runtime_wire_frame(writer, core, &wire, deadline).await {
                Ok(state) => {
                    // Commit success under the first post-flush state guard.
                    // A deadline queued behind this guard must observe the
                    // result before it can terminalize the runtime.
                    let _ = result.send(Ok(admission));
                    drop(state);
                    Ok(())
                }
                Err(error) => {
                    let state = core.state.lock().await;
                    let winner = state.terminal.unwrap_or(error);
                    let _ = result.send(Err(winner));
                    drop(state);
                    Err(winner)
                }
            }
        }
        WriterCommand::Watchdog {
            transaction,
            twinit,
            write_deadline,
            started,
            result,
        } => {
            let prepared = {
                let mut state = core.active_state().await?;
                if Instant::now() >= write_deadline {
                    let _ = result.send(Err(DiameterPeerRuntimeError::DeadlineExceeded));
                    return Ok(());
                }
                if state.pending_watchdog.is_some() || state.pending_disconnect.is_some() {
                    let _ = result.send(Err(DiameterPeerRuntimeError::TransactionConflict));
                    return Ok(());
                }
                let now = Instant::now();
                let earliest_effective = twinit.get().saturating_sub(Duration::from_secs(2));
                if now.saturating_duration_since(state.activity.last_inbound) < earliest_effective {
                    let _ = result.send(Err(DiameterPeerRuntimeError::WatchdogNotDue));
                    return Ok(());
                }
                let incarnation = match take_incarnation(&mut state.next_watchdog_incarnation) {
                    Ok(incarnation) => incarnation,
                    Err(error) => {
                        let _ = result.send(Err(error));
                        return Ok(());
                    }
                };
                let request = DeviceWatchdogRequest {
                    identity: state.session.local_capabilities().identity.clone(),
                    origin_state_id: core.local_origin_state_id,
                };
                let message = match build_device_watchdog_request(
                    &request,
                    transaction.hop_by_hop_identifier,
                    transaction.end_to_end_identifier,
                    core.frame_limits.encode_context(),
                ) {
                    Ok(message) => message,
                    Err(_) => {
                        let _ = result.send(Err(DiameterPeerRuntimeError::InvalidControlMessage));
                        return Ok(());
                    }
                };
                if state
                    .session
                    .watchdog_request_sent_on(core.generation, &message.header)
                    .is_err()
                {
                    let _ = result.send(Err(DiameterPeerRuntimeError::CommandNotAdmitted));
                    return Ok(());
                }
                let (timer_reset, timer) = watch::channel(core.hard_deadline);
                state.pending_watchdog = Some(PendingWatchdog {
                    incarnation,
                    transaction,
                    twinit,
                    timer_reset,
                    result: Some(result),
                });
                (message, incarnation, timer)
            };
            let (message, incarnation, mut timer) = prepared;
            let mut state = write_runtime_frame(writer, core, &message, write_deadline).await?;
            let deadline = jittered_watchdog_deadline(Instant::now(), twinit, core.hard_deadline);
            let should_start = if let Some(pending) = state
                .pending_watchdog
                .as_mut()
                .filter(|pending| pending.incarnation == incarnation)
            {
                pending.timer_reset.send_replace(deadline);
                let _ = timer.borrow_and_update();
                true
            } else {
                false
            };
            // Commit this exact operation's start token under the first
            // post-flush state guard. Its caller can therefore distinguish an
            // emitted DWR from every other concurrent probe.
            let _ = started.send(());
            drop(state);
            if should_start {
                spawn_watchdog_timeout(Arc::clone(core), incarnation, timer);
            }
            Ok(())
        }
        WriterCommand::Disconnect {
            transaction,
            cause,
            deadline,
            result,
        } => {
            let message = {
                let mut state = core.active_state().await?;
                if Instant::now() >= deadline {
                    let _ = result.send(Err(DiameterPeerRuntimeError::DeadlineExceeded));
                    return Ok(());
                }
                if state.pending_disconnect.is_some() {
                    let _ = result.send(Err(DiameterPeerRuntimeError::TransactionConflict));
                    return Ok(());
                }
                let incarnation = match take_incarnation(&mut state.next_disconnect_incarnation) {
                    Ok(incarnation) => incarnation,
                    Err(error) => {
                        let _ = result.send(Err(error));
                        return Ok(());
                    }
                };
                let request = DisconnectPeerRequest {
                    identity: state.session.local_capabilities().identity.clone(),
                    disconnect_cause: cause,
                    origin_state_id: core.local_origin_state_id,
                };
                let message = match build_disconnect_peer_request(
                    &request,
                    transaction.hop_by_hop_identifier,
                    transaction.end_to_end_identifier,
                    core.frame_limits.encode_context(),
                ) {
                    Ok(message) => message,
                    Err(_) => {
                        let _ = result.send(Err(DiameterPeerRuntimeError::InvalidControlMessage));
                        return Ok(());
                    }
                };
                if state
                    .session
                    .disconnect_request_sent_on(core.generation, &message.header, cause)
                    .is_err()
                {
                    let _ = result.send(Err(DiameterPeerRuntimeError::CommandNotAdmitted));
                    return Ok(());
                }
                let superseded_watchdog = state
                    .pending_watchdog
                    .take()
                    .and_then(|mut pending| pending.result.take());
                state.pending_disconnect = Some(PendingDisconnect {
                    incarnation,
                    transaction,
                    result,
                    superseded_watchdog,
                });
                (message, incarnation)
            };
            let (message, incarnation) = message;
            let mut state = write_runtime_frame(writer, core, &message, deadline).await?;
            let superseded = state
                .pending_disconnect
                .as_mut()
                .filter(|pending| pending.incarnation == incarnation)
                .and_then(|pending| pending.superseded_watchdog.take());
            if let Some(result) = superseded {
                // A flushed DPR commits watchdog supersession under the first
                // post-flush guard, before a queued deadline can terminalize
                // the displaced operation with a false timeout.
                let _ = result.send(Err(
                    DiameterPeerRuntimeError::WatchdogSupersededByDisconnect,
                ));
            }
            drop(state);
            spawn_disconnect_timeout(Arc::clone(core), incarnation, transaction, deadline);
            Ok(())
        }
    }
}

async fn write_runtime_frame<'a, W>(
    writer: &mut W,
    core: &'a RuntimeCore,
    message: &OwnedMessage,
    deadline: Instant,
) -> Result<tokio::sync::MutexGuard<'a, RuntimeState>, DiameterPeerRuntimeError>
where
    W: AsyncWrite + Unpin,
{
    let state = core.active_state().await?;
    let wire = match encoded_bytes(message, core.frame_limits) {
        Ok(wire) => wire,
        Err(error) => {
            drop(state);
            return Err(core
                .terminate(DiameterPeerRuntimeError::Transport(error), true)
                .await);
        }
    };
    drop(state);
    write_runtime_wire_frame(writer, core, &wire, deadline).await
}

async fn write_runtime_wire_frame<'a, W>(
    writer: &mut W,
    core: &'a RuntimeCore,
    wire: &[u8],
    deadline: Instant,
) -> Result<tokio::sync::MutexGuard<'a, RuntimeState>, DiameterPeerRuntimeError>
where
    W: AsyncWrite + Unpin,
{
    drop(core.active_state().await?);
    let deadline = deadline.min(bounded_operation_deadline(
        Instant::now(),
        core.max_frame_write_duration,
        core.hard_deadline,
    ));
    if Instant::now() >= deadline {
        let contender = core.classify_write_deadline();
        return Err(core.terminate(contender, true).await);
    }
    if let Err(error) = write_wire_frame(writer, wire, core.frame_limits, deadline).await {
        let contender = match error {
            DiameterTlsError::DeadlineExceeded => core.classify_write_deadline(),
            other => core.classify_transport(other),
        };
        return Err(core.terminate(contender, true).await);
    }
    let mut state = core.active_state().await?;
    state.activity.sequence = state.activity.sequence.saturating_add(1);
    state.activity.last_outbound = Instant::now();
    Ok(state)
}

fn bounded_operation_deadline(now: Instant, duration: Duration, hard_deadline: Instant) -> Instant {
    now.checked_add(duration)
        .map_or(hard_deadline, |deadline| deadline.min(hard_deadline))
}

fn spawn_watchdog_timeout(
    core: Arc<RuntimeCore>,
    incarnation: u64,
    timer_reset: watch::Receiver<Instant>,
) {
    tokio::spawn(async move {
        watchdog_timeout_loop(core, incarnation, timer_reset).await;
    });
}

async fn watchdog_timeout_loop(
    core: Arc<RuntimeCore>,
    incarnation: u64,
    mut timer_reset: watch::Receiver<Instant>,
) {
    let mut terminal = core.terminal.subscribe();
    if terminal.borrow().is_some() {
        return;
    }
    let mut deadline = *timer_reset.borrow_and_update();
    let mut suspect = false;
    loop {
        tokio::select! {
            biased;
            changed = terminal.changed() => {
                let _ = changed;
                return;
            }
            changed = timer_reset.changed() => {
                if changed.is_err() {
                    return;
                }
                deadline = *timer_reset.borrow_and_update();
                suspect = false;
            }
            _ = tokio::time::sleep_until(deadline) => {
                let mut state = match core.active_state().await {
                    Ok(state) => state,
                    Err(_) => return,
                };
                if state
                    .pending_watchdog
                    .as_ref()
                    .is_none_or(|pending| pending.incarnation != incarnation)
                {
                    return;
                }
                if timer_reset.has_changed().unwrap_or(false) {
                    deadline = *timer_reset.borrow_and_update();
                    suspect = false;
                    continue;
                }
                if suspect {
                    drop(state);
                    let terminated = terminate_watchdog_if_unreset(
                        &core,
                        incarnation,
                        &timer_reset,
                    )
                    .await;
                    if terminated {
                        return;
                    }
                    // Inbound activity may have reset Tw after the check under
                    // the first state guard but before terminal arbitration
                    // reacquired it. The predicate observes that reset while
                    // holding the authoritative state lock; consume it and
                    // resume instead of closing a recovered peer.
                    if timer_reset.has_changed().unwrap_or(false) {
                        deadline = *timer_reset.borrow_and_update();
                        suspect = false;
                        continue;
                    }
                    return;
                }

                let twinit = state
                    .pending_watchdog
                    .as_ref()
                    .map(|pending| pending.twinit);
                let Some(twinit) = twinit else {
                    return;
                };
                if state
                    .session
                    .watchdog_suspect_on(core.generation)
                    .is_err()
                {
                    drop(state);
                    core.terminate(DiameterPeerRuntimeError::CommandNotAdmitted, true)
                        .await;
                    return;
                }
                let result = state
                    .pending_watchdog
                    .as_mut()
                    .and_then(|pending| pending.result.take());
                deadline = jittered_watchdog_deadline(
                    Instant::now(),
                    twinit,
                    core.hard_deadline,
                );
                suspect = true;
                if let Some(result) = result {
                    // Commit the first-interval result while the transition to
                    // SUSPECT remains state-serialized against terminal close.
                    let _ = result.send(Err(DiameterPeerRuntimeError::WatchdogSuspect));
                }
            }
        }
    }
}

async fn terminate_watchdog_if_unreset(
    core: &RuntimeCore,
    incarnation: u64,
    timer_reset: &watch::Receiver<Instant>,
) -> bool {
    core.terminate_if(DiameterPeerRuntimeError::DeadlineExceeded, true, |state| {
        state
            .pending_watchdog
            .as_ref()
            .is_some_and(|pending| pending.incarnation == incarnation)
            && !timer_reset.has_changed().unwrap_or(false)
    })
    .await
}

fn spawn_disconnect_timeout(
    core: Arc<RuntimeCore>,
    incarnation: u64,
    transaction: TransactionId,
    deadline: Instant,
) {
    tokio::spawn(async move {
        let mut terminal = core.terminal.subscribe();
        if terminal.borrow().is_some() {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {}
            changed = terminal.changed() => {
                let _ = changed;
                return;
            }
        }
        let _ = core
            .terminate_if(DiameterPeerRuntimeError::DeadlineExceeded, true, |state| {
                state.pending_disconnect.as_ref().is_some_and(|pending| {
                    pending.incarnation == incarnation && pending.transaction == transaction
                })
            })
            .await;
    });
}

fn strict_decode_context(limits: DiameterFrameLimits) -> DecodeContext {
    DecodeContext {
        max_message_len: limits.max_message_len(),
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}

fn ensure_expected_identity(
    core: &RuntimeCore,
    actual: &opc_proto_diameter::peer::PeerIdentity,
) -> Result<(), DiameterPeerRuntimeError> {
    if actual.semantically_eq(&core.expected_peer) {
        Ok(())
    } else {
        Err(DiameterPeerRuntimeError::PeerIdentityMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BrokenPipeAfterRelease {
        first_poll: Option<oneshot::Sender<()>>,
        failure_poll: Option<oneshot::Sender<()>>,
        released: Arc<AtomicBool>,
        waiter: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
    }

    struct BrokenPipeRelease {
        released: Arc<AtomicBool>,
        waiter: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
    }

    struct NeverReadyWriter;

    impl BrokenPipeAfterRelease {
        fn new() -> (
            Self,
            BrokenPipeRelease,
            oneshot::Receiver<()>,
            oneshot::Receiver<()>,
        ) {
            let (first_poll, first_polled) = oneshot::channel();
            let (failure_poll, failure_polled) = oneshot::channel();
            let released = Arc::new(AtomicBool::new(false));
            let waiter = Arc::new(std::sync::Mutex::new(None));
            (
                Self {
                    first_poll: Some(first_poll),
                    failure_poll: Some(failure_poll),
                    released: Arc::clone(&released),
                    waiter: Arc::clone(&waiter),
                },
                BrokenPipeRelease { released, waiter },
                first_polled,
                failure_polled,
            )
        }
    }

    impl BrokenPipeRelease {
        fn release(&self) {
            self.released.store(true, Ordering::Release);
            let waiter = self
                .waiter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(waiter) = waiter {
                waiter.wake();
            }
        }
    }

    impl AsyncWrite for BrokenPipeAfterRelease {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            _buffer: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if !self.released.load(Ordering::Acquire) {
                if let Some(first_poll) = self.first_poll.take() {
                    let _ = first_poll.send(());
                }
                *self
                    .waiter
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(context.waker().clone());
                return std::task::Poll::Pending;
            }
            if let Some(failure_poll) = self.failure_poll.take() {
                let _ = failure_poll.send(());
            }
            std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for NeverReadyWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            _buffer: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Pending
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn test_identity_state() -> opc_identity::IdentityState {
        let mut ca_parameters = rcgen::CertificateParams::default();
        ca_parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("generate test CA key");
        let ca = rcgen::CertifiedIssuer::self_signed(ca_parameters, ca_key)
            .expect("sign test CA certificate");

        let spiffe_id =
            "spiffe://example.test/tenant/test/ns/test/sa/diameter/nf/test/instance/runtime";
        let mut leaf_parameters = rcgen::CertificateParams::default();
        leaf_parameters.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(spiffe_id).expect("valid test SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        leaf_parameters.not_before = now - time::Duration::minutes(1);
        leaf_parameters.not_after = now + time::Duration::hours(1);
        let leaf_key = rcgen::KeyPair::generate().expect("generate test leaf key");
        let leaf = leaf_parameters
            .signed_by(&leaf_key, &ca)
            .expect("sign test leaf certificate");

        let mut trust_bundles = opc_identity::TrustBundleSet::new();
        trust_bundles.insert(opc_identity::TrustBundle {
            trust_domain: opc_identity::TrustDomain::new("example.test")
                .expect("valid test trust domain"),
            certificates: vec![ca.der().clone()],
        });
        opc_identity::build_identity_state(
            vec![leaf.der().clone(), ca.der().clone()],
            rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
                leaf_key.serialize_der(),
            )),
            trust_bundles,
        )
        .expect("build valid test identity state")
    }

    fn test_tcp_pair() -> (std::net::TcpStream, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind test TCP listener");
        let address = listener.local_addr().expect("read test listener address");
        let connector = std::thread::spawn(move || {
            std::net::TcpStream::connect(address).expect("connect test TCP")
        });
        let (accepted, _) = listener.accept().expect("accept test TCP");
        let connected = connector.join().expect("join test TCP connector");
        (accepted, connected)
    }

    fn test_runtime_core() -> (
        Arc<RuntimeCore>,
        watch::Sender<Option<opc_identity::IdentityState>>,
        std::net::TcpStream,
    ) {
        test_runtime_core_with_hard_deadline(Instant::now() + Duration::from_secs(60))
    }

    fn test_runtime_core_with_hard_deadline(
        hard_deadline: Instant,
    ) -> (
        Arc<RuntimeCore>,
        watch::Sender<Option<opc_identity::IdentityState>>,
        std::net::TcpStream,
    ) {
        let (material_source, material_rx) = watch::channel(Some(test_identity_state()));
        let material_controller = opc_tls::TlsMaterialController::new(material_rx);
        let material_status = material_controller.subscribe_material_changes();
        let admitted_epoch = material_status.status().epoch();

        let application_id = opc_proto_diameter::ApplicationId::new(1);
        let expected_peer =
            opc_proto_diameter::peer::PeerIdentity::new("peer.example.test", "example.test");
        let mut capabilities = opc_proto_diameter::peer::PeerCapabilities::new(
            opc_proto_diameter::peer::PeerIdentity::new("local.example.test", "example.test"),
            vec![opc_proto_diameter::peer::HostIpAddress::Ipv4([
                127, 0, 0, 1,
            ])],
            opc_proto_diameter::VendorId::new(0),
            "runtime-test",
        );
        capabilities.auth_application_ids = vec![application_id];
        capabilities.inband_security_ids =
            vec![opc_proto_diameter::base::INBAND_SECURITY_ID_NO_INBAND_SECURITY];
        let mut remote_capabilities = opc_proto_diameter::peer::PeerCapabilities::new(
            expected_peer.clone(),
            vec![opc_proto_diameter::peer::HostIpAddress::Ipv4([
                127, 0, 0, 2,
            ])],
            opc_proto_diameter::VendorId::new(0),
            "runtime-peer-test",
        );
        remote_capabilities.auth_application_ids = vec![application_id];
        remote_capabilities.inband_security_ids =
            vec![opc_proto_diameter::base::INBAND_SECURITY_ID_NO_INBAND_SECURITY];
        let generation = PeerSessionGeneration::new(
            std::num::NonZeroU64::new(1).expect("nonzero test generation"),
        );
        let mut session = PeerSession::with_policy(
            capabilities,
            opc_proto_diameter::peer::PeerSessionPolicy::default()
                .accept_application(application_id),
        );
        session
            .begin_connection_generation(generation)
            .expect("bind test session generation");
        let _ = session.capabilities_request_sent();
        let _ = session.observe_capabilities_answer(
            &opc_proto_diameter::peer::CapabilitiesExchangeAnswer {
                result_code: RESULT_CODE_DIAMETER_SUCCESS,
                capabilities: remote_capabilities,
                diagnostics: AnswerDiagnostics::default(),
            },
        );

        let (shutdown, connected_peer) = test_tcp_pair();
        let (terminal, _) = watch::channel(None);
        let started_at = Instant::now();
        let core = Arc::new(RuntimeCore {
            state: Mutex::new(RuntimeState {
                session,
                terminal: None,
                pending_watchdog: None,
                pending_disconnect: None,
                next_watchdog_incarnation: 1,
                next_disconnect_incarnation: 1,
                activity: DiameterPeerActivity {
                    sequence: 0,
                    last_inbound: started_at,
                    last_outbound: started_at,
                },
                application_quiesced: false,
            }),
            terminal,
            shutdown: Arc::new(shutdown),
            closing: Arc::new(RuntimeClosing::new()),
            generation,
            expected_peer,
            frame_limits: DiameterFrameLimits::default(),
            material_status,
            admitted_epoch,
            hard_deadline,
            retired: Arc::new(AtomicBool::new(false)),
            local_origin_state_id: None,
            frame_completion_timeout: Duration::from_secs(5),
            max_frame_write_duration: Duration::from_secs(5),
        });
        (core, material_source, connected_peer)
    }

    fn test_capacity() -> NonZeroUsize {
        NonZeroUsize::new(8).expect("nonzero test capacity")
    }

    #[test]
    fn runtime_configuration_rejects_panicking_queue_and_timeout_inputs() {
        let capacity = test_capacity();
        let oversized = NonZeroUsize::new(tokio::sync::Semaphore::MAX_PERMITS + 1)
            .expect("oversized value remains nonzero");
        assert_eq!(
            DiameterPeerRuntimeConfig::new(oversized, capacity, capacity, None),
            Err(DiameterPeerRuntimeConfigError::CommandQueueTooLarge)
        );
        let config = DiameterPeerRuntimeConfig::new(capacity, capacity, capacity, None)
            .expect("valid runtime configuration");
        assert_eq!(
            config.with_frame_io_timeouts(Duration::ZERO, Duration::from_secs(1)),
            Err(DiameterPeerRuntimeConfigError::FrameCompletionTimeoutZero)
        );
        assert_eq!(
            config.with_frame_io_timeouts(Duration::from_secs(1), Duration::ZERO),
            Err(DiameterPeerRuntimeConfigError::FrameWriteTimeoutZero)
        );
        assert_eq!(
            config.with_frame_io_timeouts(Duration::MAX, Duration::from_secs(1)),
            Err(DiameterPeerRuntimeConfigError::FrameCompletionTimeoutTooLarge)
        );
        assert_eq!(
            config.with_frame_io_timeouts(Duration::from_secs(1), Duration::MAX),
            Err(DiameterPeerRuntimeConfigError::FrameWriteTimeoutTooLarge)
        );
    }

    #[test]
    fn watchdog_twinit_is_bounded_and_each_jittered_deadline_is_rfc_sized() {
        assert_eq!(
            DiameterWatchdogTwinit::new(Duration::from_secs(5)),
            Err(DiameterWatchdogTwinitError::BelowMinimum)
        );
        assert_eq!(
            DiameterWatchdogTwinit::new(Duration::MAX),
            Err(DiameterWatchdogTwinitError::TooLarge)
        );
        let twinit =
            DiameterWatchdogTwinit::new(Duration::from_secs(6)).expect("minimum Twinit is valid");
        let now = Instant::now();
        let hard_deadline = now + Duration::from_secs(30);
        for _ in 0..256 {
            let effective = jittered_watchdog_deadline(now, twinit, hard_deadline)
                .saturating_duration_since(now);
            assert!(effective >= Duration::from_secs(4));
            assert!(effective <= Duration::from_secs(8));
        }
    }

    #[test]
    fn correlation_incarnation_never_wraps() {
        let mut next = u64::MAX;
        assert_eq!(
            take_incarnation(&mut next),
            Err(DiameterPeerRuntimeError::CorrelationAuthorityExhausted)
        );
        assert_eq!(next, u64::MAX);
    }

    #[test]
    fn runtime_errors_have_stable_redaction_safe_codes() {
        let cases = [
            (
                DiameterPeerRuntimeError::NotNegotiated,
                "diameter_peer_runtime_not_negotiated",
            ),
            (
                DiameterPeerRuntimeError::RuntimeUnavailable,
                "diameter_peer_runtime_unavailable",
            ),
            (
                DiameterPeerRuntimeError::CommandNotAdmitted,
                "diameter_peer_runtime_command_not_admitted",
            ),
            (
                DiameterPeerRuntimeError::InvalidControlMessage,
                "diameter_peer_runtime_invalid_control_message",
            ),
            (
                DiameterPeerRuntimeError::PeerIdentityMismatch,
                "diameter_peer_runtime_peer_identity_mismatch",
            ),
            (
                DiameterPeerRuntimeError::TransactionConflict,
                "diameter_peer_runtime_transaction_conflict",
            ),
            (
                DiameterPeerRuntimeError::TransactionMismatch,
                "diameter_peer_runtime_transaction_mismatch",
            ),
            (
                DiameterPeerRuntimeError::ProtocolViolation,
                "diameter_peer_runtime_protocol_violation",
            ),
            (
                DiameterPeerRuntimeError::Backpressure,
                "diameter_peer_runtime_backpressure",
            ),
            (
                DiameterPeerRuntimeError::DeadlineExceeded,
                "diameter_peer_runtime_deadline_exceeded",
            ),
            (
                DiameterPeerRuntimeError::WatchdogSuspect,
                "diameter_peer_runtime_watchdog_suspect",
            ),
            (
                DiameterPeerRuntimeError::WatchdogNotDue,
                "diameter_peer_runtime_watchdog_not_due",
            ),
            (
                DiameterPeerRuntimeError::WatchdogSupersededByDisconnect,
                "diameter_peer_runtime_watchdog_superseded_by_disconnect",
            ),
            (
                DiameterPeerRuntimeError::CorrelationAuthorityExhausted,
                "diameter_peer_runtime_correlation_authority_exhausted",
            ),
            (
                DiameterPeerRuntimeError::Closed,
                "diameter_peer_runtime_closed",
            ),
            (
                DiameterPeerRuntimeError::PeerDisconnected { peer_cause: None },
                "diameter_peer_runtime_peer_disconnected",
            ),
        ];
        for (error, code) in cases {
            assert_eq!(error.as_str(), code);
            assert!(!error.to_string().contains("secret"));
        }
    }

    #[test]
    fn transaction_requires_both_diameter_identifiers() {
        let transaction = TransactionId::new(7, 9);
        let message = OwnedMessage {
            header: opc_proto_diameter::Header::new(
                opc_proto_diameter::CommandFlags::from_bits(0),
                opc_proto_diameter::CommandCode::new(280),
                opc_proto_diameter::ApplicationId::new(0),
                7,
                9,
            ),
            raw_avps: bytes::Bytes::new(),
        };
        assert!(transaction.matches(&message));
        let mut wrong_hop = message.clone();
        wrong_hop.header.hop_by_hop_identifier = 8;
        assert!(!transaction.matches(&wrong_hop));
        let mut wrong_end = message;
        wrong_end.header.end_to_end_identifier = 10;
        assert!(!transaction.matches(&wrong_end));
    }

    #[tokio::test]
    async fn write_failure_returns_the_authoritative_terminal_winner() {
        let (core, _material_source, _connected_peer) = test_runtime_core();
        let (mut writer, release, first_polled, failure_polled) = BrokenPipeAfterRelease::new();
        let message = OwnedMessage {
            header: opc_proto_diameter::Header::new(
                opc_proto_diameter::CommandFlags::request(true),
                opc_proto_diameter::CommandCode::new(268),
                opc_proto_diameter::ApplicationId::new(1),
                7,
                9,
            ),
            raw_avps: bytes::Bytes::new(),
        };
        let write_core = Arc::clone(&core);
        let write_task = tokio::spawn(async move {
            write_runtime_frame(
                &mut writer,
                &write_core,
                &message,
                Instant::now() + Duration::from_secs(30),
            )
            .await
            .map(drop)
        });
        first_polled.await.expect("writer reached its first poll");

        let state = core.state.lock().await;
        let terminate_core = Arc::clone(&core);
        let (terminate_started, terminate_queued) = oneshot::channel();
        let terminate_task = tokio::spawn(async move {
            let _ = terminate_started.send(());
            terminate_core
                .terminate(DiameterPeerRuntimeError::ProtocolViolation, true)
                .await
        });
        terminate_queued
            .await
            .expect("authoritative terminator started");
        tokio::task::yield_now().await;

        release.release();
        failure_polled
            .await
            .expect("writer emitted the competing transport failure");
        tokio::task::yield_now().await;
        drop(state);

        assert_eq!(
            terminate_task.await.expect("join authoritative terminator"),
            DiameterPeerRuntimeError::ProtocolViolation
        );
        assert_eq!(
            write_task.await.expect("join runtime frame writer"),
            Err(DiameterPeerRuntimeError::ProtocolViolation)
        );
        assert_eq!(
            core.terminal_error(),
            DiameterPeerRuntimeError::ProtocolViolation
        );
    }

    #[tokio::test(start_paused = true)]
    async fn hard_deadline_write_timeout_is_classified_as_retirement() {
        let hard_deadline = Instant::now() + Duration::from_secs(1);
        let (core, _material_source, _connected_peer) =
            test_runtime_core_with_hard_deadline(hard_deadline);
        let message = OwnedMessage {
            header: opc_proto_diameter::Header::new(
                opc_proto_diameter::CommandFlags::request(true),
                opc_proto_diameter::CommandCode::new(268),
                opc_proto_diameter::ApplicationId::new(1),
                31,
                37,
            ),
            raw_avps: bytes::Bytes::new(),
        };
        let wire = encoded_bytes(&message, core.frame_limits).expect("encode test frame");
        let mut writer = NeverReadyWriter;
        let mut write = Box::pin(write_runtime_wire_frame(
            &mut writer,
            &core,
            &wire,
            hard_deadline + Duration::from_secs(30),
        ));
        let pending = std::future::poll_fn(|context| {
            match std::future::Future::poll(write.as_mut(), context) {
                std::task::Poll::Pending => std::task::Poll::Ready(true),
                std::task::Poll::Ready(_) => std::task::Poll::Ready(false),
            }
        })
        .await;
        assert!(pending, "write must be pending before hard expiry");
        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(
            write.await.map(drop),
            Err(DiameterPeerRuntimeError::Transport(
                DiameterTlsError::Retired,
            )),
        );
        assert_eq!(
            core.terminal_error(),
            DiameterPeerRuntimeError::Transport(DiameterTlsError::Retired),
        );
    }

    #[tokio::test]
    async fn submitted_timeout_returns_result_committed_by_terminal_winner() {
        let (core, _material_source, _connected_peer) = test_runtime_core();
        let (result_tx, result_rx) = oneshot::channel();
        let state = core.state.lock().await;
        let mut submitted = Box::pin(await_submitted_result(&core, result_rx, Instant::now()));

        let blocked = std::future::poll_fn(|context| {
            match std::future::Future::poll(submitted.as_mut(), context) {
                std::task::Poll::Pending => std::task::Poll::Ready(true),
                std::task::Poll::Ready(_) => std::task::Poll::Ready(false),
            }
        })
        .await;
        assert!(
            blocked,
            "elapsed submitted deadline must wait for terminal arbitration"
        );

        let intended = DiameterPeerRuntimeError::PeerDisconnected { peer_cause: None };
        let _ = core.shutdown.shutdown(Shutdown::Both);
        let mut state = state;
        state.terminal = Some(intended);
        let _ = result_tx.send(Ok(7_u8));
        core.terminal.send_replace(Some(intended));
        core.closing.mark();
        drop(state);

        assert_eq!(
            submitted.await,
            Ok(7),
            "the committed result must survive a losing caller timeout"
        );
        assert_eq!(core.terminal_error(), intended);
    }

    #[tokio::test]
    async fn terminal_branch_rechecks_result_committed_after_its_initial_poll() {
        let (result_tx, mut result_rx) = oneshot::channel();
        let initially_pending = std::future::poll_fn(|context| {
            match std::future::Future::poll(std::pin::Pin::new(&mut result_rx), context) {
                std::task::Poll::Pending => std::task::Poll::Ready(true),
                std::task::Poll::Ready(_) => std::task::Poll::Ready(false),
            }
        })
        .await;
        assert!(initially_pending, "the result branch was initially pending");

        result_tx
            .send(Ok(29_u8))
            .expect("commit result after its first poll");
        assert_eq!(
            prefer_committed_result(
                &mut result_rx,
                Err(DiameterPeerRuntimeError::ProtocolViolation),
            ),
            Ok(29),
            "a terminal arm polled later in the same select pass must not mask the result",
        );
    }

    #[tokio::test]
    async fn watchdog_write_deadline_uses_the_exact_start_token() {
        let (core, _material_source, _connected_peer) = test_runtime_core();
        let (started_tx, mut started_rx) = oneshot::channel();
        let (result_tx, mut result_rx) = oneshot::channel();
        let state = core.state.lock().await;
        let mut arbitration = Box::pin(arbitrate_watchdog_write_deadline(
            &core,
            &mut started_rx,
            &mut result_rx,
        ));
        let blocked = std::future::poll_fn(|context| {
            match std::future::Future::poll(arbitration.as_mut(), context) {
                std::task::Poll::Pending => std::task::Poll::Ready(true),
                std::task::Poll::Ready(_) => std::task::Poll::Ready(false),
            }
        })
        .await;
        assert!(blocked, "deadline arbitration must wait for runtime state");
        started_tx
            .send(())
            .expect("commit this probe's start token under runtime state");
        drop(state);
        assert!(matches!(
            arbitration.await,
            WatchdogDeadlineOutcome::Emitted
        ));
        drop(result_tx);

        let (other_core, _material_source, _connected_peer) = test_runtime_core();
        let (unrelated_started_tx, _unrelated_started_rx) = oneshot::channel();
        unrelated_started_tx
            .send(())
            .expect("commit unrelated probe start");
        let (_this_started_tx, mut this_started_rx) = oneshot::channel();
        let (_this_result_tx, mut this_result_rx) = oneshot::channel();
        assert!(matches!(
            arbitrate_watchdog_write_deadline(
                &other_core,
                &mut this_started_rx,
                &mut this_result_rx,
            )
            .await,
            WatchdogDeadlineOutcome::Complete(Err(DiameterPeerRuntimeError::DeadlineExceeded))
        ));
        assert_eq!(
            other_core.terminal_error(),
            DiameterPeerRuntimeError::DeadlineExceeded,
            "an unrelated probe cannot waive this operation's expired write deadline",
        );
    }

    #[tokio::test]
    async fn watchdog_reset_wins_before_second_interval_terminal_arbitration() {
        let (core, _material_source, _connected_peer) = test_runtime_core();
        let now = Instant::now();
        let (timer_reset, timer) = watch::channel(now + Duration::from_secs(6));
        let incarnation = 41;
        let mut state = core.state.lock().await;
        state.pending_watchdog = Some(PendingWatchdog {
            incarnation,
            transaction: TransactionId::new(17, 19),
            twinit: DiameterWatchdogTwinit::new(Duration::from_secs(6)).expect("valid test Twinit"),
            timer_reset: timer_reset.clone(),
            result: None,
        });

        let mut termination = Box::pin(terminate_watchdog_if_unreset(&core, incarnation, &timer));
        let blocked = std::future::poll_fn(|context| {
            match std::future::Future::poll(termination.as_mut(), context) {
                std::task::Poll::Pending => std::task::Poll::Ready(true),
                std::task::Poll::Ready(_) => std::task::Poll::Ready(false),
            }
        })
        .await;
        assert!(
            blocked,
            "second-interval termination must wait for the runtime state lock"
        );

        timer_reset.send_replace(now + Duration::from_secs(12));
        drop(state);
        assert!(
            !termination.await,
            "a state-ordered Tw reset must reject stale second-interval close"
        );
        let state = core.state.lock().await;
        assert!(state.terminal.is_none());
        assert_eq!(
            state
                .pending_watchdog
                .as_ref()
                .map(|pending| pending.incarnation),
            Some(incarnation)
        );
    }

    #[tokio::test]
    async fn accepted_watchdog_answer_survives_later_disconnect_state() {
        for peer_requested in [false, true] {
            let (core, _material_source, _connected_peer) = test_runtime_core();
            let request = DeviceWatchdogRequest {
                identity: core.expected_peer.clone(),
                origin_state_id: Some(23),
            };
            let request_message = build_device_watchdog_request(
                &request,
                0x7700,
                0x8800,
                core.frame_limits.encode_context(),
            )
            .expect("build accepted DWR");
            let authority = {
                let mut state = core.state.lock().await;
                state
                    .session
                    .observe_watchdog_request_on(core.generation, &request_message.header, &request)
                    .expect("accept exact-generation DWR");
                WatchdogAnswerAuthority::new(
                    core.generation,
                    TransactionId::new(
                        request_message.header.hop_by_hop_identifier,
                        request_message.header.end_to_end_identifier,
                    ),
                )
            };
            let answer = {
                let state = core.state.lock().await;
                build_device_watchdog_answer(
                    &DeviceWatchdogAnswer {
                        result_code: RESULT_CODE_DIAMETER_SUCCESS,
                        identity: state.session.local_capabilities().identity.clone(),
                        origin_state_id: core.local_origin_state_id,
                        diagnostics: AnswerDiagnostics::default(),
                    },
                    request_message.header.hop_by_hop_identifier,
                    request_message.header.end_to_end_identifier,
                    core.frame_limits.encode_context(),
                )
                .expect("build authorized DWA")
            };

            let disconnect = DisconnectPeerRequest {
                identity: if peer_requested {
                    core.expected_peer.clone()
                } else {
                    let state = core.state.lock().await;
                    state.session.local_capabilities().identity.clone()
                },
                disconnect_cause: DisconnectCause::Rebooting,
                origin_state_id: None,
            };
            let disconnect_message = build_disconnect_peer_request(
                &disconnect,
                0x7701,
                0x8801,
                core.frame_limits.encode_context(),
            )
            .expect("build DPR transition");
            {
                let mut state = core.state.lock().await;
                let expected_state = if peer_requested {
                    state
                        .session
                        .observe_disconnect_request_on(
                            core.generation,
                            &disconnect_message.header,
                            &disconnect,
                        )
                        .expect("observe peer DPR")
                        .state
                } else {
                    state
                        .session
                        .disconnect_request_sent_on(
                            core.generation,
                            &disconnect_message.header,
                            DisconnectCause::Rebooting,
                        )
                        .expect("commit local DPR")
                        .state
                };
                assert_eq!(
                    expected_state,
                    if peer_requested {
                        opc_proto_diameter::peer::PeerSessionState::Draining
                    } else {
                        opc_proto_diameter::peer::PeerSessionState::Disconnecting
                    }
                );
            }

            let (mut writer, mut reader) = tokio::io::duplex(4096);
            write_control(
                &mut writer,
                &core,
                ControlCommand::Watchdog {
                    message: answer,
                    authority,
                    deadline: Instant::now() + Duration::from_secs(1),
                },
            )
            .await
            .expect("accepted DWR retains authority across disconnect transition");
            let emitted = read_runtime_frame(
                &mut reader,
                core.frame_limits,
                Duration::from_secs(1),
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .expect("read retained-authority DWA");
            assert!(authority.authorizes(core.generation, &emitted));
        }
    }

    #[tokio::test]
    async fn cancelled_receive_retains_a_dequeued_application_message() {
        let (core, _material_source, _connected_peer) = test_runtime_core();
        let message = OwnedMessage {
            header: opc_proto_diameter::Header::new(
                opc_proto_diameter::CommandFlags::request(true),
                opc_proto_diameter::CommandCode::new(268),
                opc_proto_diameter::ApplicationId::new(1),
                17,
                19,
            ),
            raw_avps: bytes::Bytes::from_static(b"application-message"),
        };
        let admission = {
            let state = core.state.lock().await;
            state
                .session
                .admit_message(
                    core.generation,
                    PeerMessageDirection::Inbound,
                    &message.header,
                )
                .expect("admit test application message")
        };
        let (applications, applications_rx) = mpsc::channel(1);
        applications
            .send(DiameterApplicationMessage {
                message: message.clone(),
                admission,
            })
            .await
            .expect("buffer test application message");
        let mut receiver = DiameterApplicationReceiver {
            receiver: applications_rx,
            pending: None,
            terminal: core.terminal.subscribe(),
            core: Arc::clone(&core),
            shutdown: Arc::clone(&core.shutdown),
            closing: Arc::clone(&core.closing),
        };

        // Reproduce the state immediately after the channel dequeue: the
        // message is receiver-owned before the post-dequeue active-state
        // reconciliation awaits the runtime mutex.
        receiver.pending = receiver.receiver.recv().await;
        assert!(receiver.pending.is_some());
        let state = core.state.lock().await;
        let mut cancelled_receive = Box::pin(receiver.receive());
        let blocked = std::future::poll_fn(|context| {
            match std::future::Future::poll(cancelled_receive.as_mut(), context) {
                std::task::Poll::Pending => std::task::Poll::Ready(true),
                std::task::Poll::Ready(_) => std::task::Poll::Ready(false),
            }
        })
        .await;
        assert!(blocked, "receive must await the held runtime-state mutex");
        drop(cancelled_receive);
        drop(state);

        let retained = receiver
            .receive()
            .await
            .expect("cancelled receive retained the dequeued message");
        assert_eq!(retained.message(), &message);
        assert_eq!(retained.admission(), admission);
    }
}
