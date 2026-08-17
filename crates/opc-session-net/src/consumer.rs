//! Authenticated typed application access to a fixed session quorum.
//!
//! The transport in this module is intentionally separate from both the
//! consensus-member ALPN and the quarantined compatibility ALPN. It exposes
//! only [`opc_session_store::SessionConsumerOperation`] and uses a bounded
//! mutual-TLS transport with both fresh stateless calls and an optional fixed
//! persistent-client pool. A consumer never
//! receives a local member ID, Openraft peer, SQLite backend, snapshot path,
//! or raw replication append/rebuild operation.

use std::collections::{BTreeSet, VecDeque};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::stream::{self, BoxStream, StreamExt};
use futures_util::FutureExt;
use opc_session_store::{
    checked_session_deadline, session_consumer_batch_result_into_store,
    validate_stored_record_expiry_profile, BackendCapabilities, CompareAndSet, CompareAndSetResult,
    LeaseError, LeaseGuard, OwnerId, RecordExpiryPreflight, RestoreScanPage, RestoreScanRequest,
    SessionConsumerAuthorizationManifest, SessionConsumerBatchResult, SessionConsumerChange,
    SessionConsumerIdentity, SessionConsumerLeaseError, SessionConsumerLeaseGrant,
    SessionConsumerOperation, SessionConsumerOutcomeUnknown, SessionConsumerRejection,
    SessionConsumerRequest, SessionConsumerRequestId, SessionConsumerResponse,
    SessionConsumerScope, SessionConsumerStoreError, SessionOp, SessionOpResult,
    SessionQuorumConsumer, StatelessSessionConsumer, StoreError,
    MAX_SESSION_CONSUMER_BATCH_RESPONSE_BYTES,
};
use opc_types::SpiffeId;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use crate::consensus::RemoteAddrResolver;
use crate::error::{classify_tls_io_error, ProtocolError};
use crate::lifecycle::{
    CertificateExpiryEvidence, ConnectionLifecycle, ConnectionLifecyclePolicy, RetirementReason,
    SessionReauthenticationControl,
};
use crate::protocol::{
    bounded_session_op_expectations, compare_and_set_result_matches_key, get_result_matches_key,
    read_authenticated_frame_payload_until, read_frame_payload,
    validate_restore_scan_wire_payload_bytes, write_frame_bounded_until,
    write_frame_bounded_until_classified_with_progress, FrameWriteError, FrameWriteProgress,
    WireBackendCapabilities, MAX_NEGOTIATED_FRAME_SIZE,
};

/// Dedicated ALPN for authenticated session-quorum consumers.
pub const SESSION_QUORUM_CONSUMER_ALPN: &[u8] = b"opc-session-consumer/1";

/// Fixed wire revision for [`SESSION_QUORUM_CONSUMER_ALPN`].
pub const SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION: u16 = 2;

/// Maximum sequential application requests processed on one consumer
/// connection. Every request has an exact nonzero connection-local
/// correlation and only one can be in flight.
pub const MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION: usize = 4096;
/// Fixed logical width of the nonzero connection-local correlation value.
pub const SESSION_QUORUM_CONSUMER_CORRELATION_ID_BYTES: usize = std::mem::size_of::<u32>();
/// Revision 2 deliberately admits one in-flight request per physical lane.
pub const MAX_SESSION_QUORUM_CONSUMER_IN_FLIGHT_PER_CONNECTION: usize = 1;

/// Default number of authenticated request lanes retained by a persistent
/// consumer client.
pub const DEFAULT_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS: usize = 4;
/// Hard upper bound for persistent request lanes.
pub const MAX_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS: usize = 16;
/// Default bounded admission count for persistent calls.
pub const DEFAULT_PERSISTENT_SESSION_CONSUMER_PENDING_CALLS: usize = 64;
/// Hard upper bound for persistent call admission.
pub const MAX_PERSISTENT_SESSION_CONSUMER_PENDING_CALLS: usize = 256;
/// Default maximum age of a request-pool wait.
pub const DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT: Duration =
    Duration::from_millis(250);
/// Default number of separate persistent watch slots.
pub const DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS: usize = 2;
/// Hard upper bound for persistent watch slots.
pub const MAX_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS: usize = 16;
/// Default cold connection setup budget for a persistent lane.
pub const DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT: Duration = Duration::from_millis(1500);
/// Default maximum number of pre-write connection attempts for one call.
pub const DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS: usize = 2;
/// Default upper bound for reconnect jitter.
pub const DEFAULT_PERSISTENT_SESSION_CONSUMER_RECONNECT_JITTER: Duration =
    Duration::from_millis(25);
/// Default bounded graceful persistent-client shutdown drain.
pub const DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);

const DEFAULT_CONSUMER_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_CONSUMER_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CONSUMER_MAX_CONNECTIONS: usize = 256;
const CONSUMER_WATCH_CHANNEL_CAPACITY: usize = 64;
const CONSUMER_WATCH_CHANNEL_MAX_BYTES: usize = 512 * 1024;
const CONSUMER_WATCH_CANCELLATION_RECHECK_INTERVAL: Duration = Duration::from_millis(50);
// The service rejects a batch before effects whenever its serialized response
// could exceed this ceiling. Reserve a small outer-wire allowance so every
// admitted service response remains frameable by the listener.
const MIN_SESSION_CONSUMER_RESPONSE_FRAME_SIZE: usize =
    MAX_SESSION_CONSUMER_BATCH_RESPONSE_BYTES + 4 * 1024;

fn checked_consumer_frame_size(size: u32) -> Result<usize, ProtocolError> {
    let size = usize::try_from(size).map_err(|_| ProtocolError::InvalidWireValue)?;
    if !(MIN_SESSION_CONSUMER_RESPONSE_FRAME_SIZE..=MAX_NEGOTIATED_FRAME_SIZE).contains(&size) {
        return Err(ProtocolError::InvalidWireValue);
    }
    Ok(size)
}

fn consumer_wire_frame_size(size: usize) -> Result<u32, ProtocolError> {
    if !(MIN_SESSION_CONSUMER_RESPONSE_FRAME_SIZE..=MAX_NEGOTIATED_FRAME_SIZE).contains(&size) {
        return Err(ProtocolError::InvalidWireValue);
    }
    u32::try_from(size).map_err(|_| ProtocolError::InvalidWireValue)
}

// Return true only when the JSON arrays for encrypted payload bytes alone
// exceed the complete negotiated request-frame budget. The exact bounded
// encoder remains authoritative for every other request. This lower bound is
// allocation-free and prevents an obviously oversized mutation from spending
// its operation budget materializing a frame that cannot be transmitted.
// Payload contents are inspected only to count their one-, two-, or
// three-digit JSON width; they are never retained or exposed.
fn consumer_payload_fragments_exceed_frame(
    request: &SessionConsumerRequest,
    max_frame_size: usize,
) -> bool {
    fn debit_payload(remaining: &mut usize, payload: &[u8]) -> bool {
        // `[0,0]` needs at least two bytes per element plus one byte shared by
        // the opening bracket and the final closing bracket. Account this
        // content-independent floor before scanning any values, so extremely
        // large payloads reject in constant time.
        let Some(base) = payload
            .len()
            .checked_mul(2)
            .and_then(|size| size.checked_add(1))
        else {
            return true;
        };
        let Some(after_base) = remaining.checked_sub(base) else {
            return true;
        };
        *remaining = after_base;

        // Decimal JSON adds one byte for values >= 10 and another for values
        // >= 100. Stop as soon as the payload-only lower bound crosses the
        // whole-frame budget.
        for byte in payload {
            let extra = usize::from(*byte >= 10) + usize::from(*byte >= 100);
            let Some(after_extra) = remaining.checked_sub(extra) else {
                return true;
            };
            *remaining = after_extra;
        }
        false
    }

    let mut remaining = max_frame_size;
    match request.operation() {
        SessionConsumerOperation::CompareAndSet { op } => {
            debit_payload(&mut remaining, op.new_record.payload.as_bytes())
        }
        SessionConsumerOperation::Batch { ops } => ops.iter().any(|operation| match operation {
            SessionOp::CompareAndSet(op) => {
                debit_payload(&mut remaining, op.new_record.payload.as_bytes())
            }
            _ => false,
        }),
        _ => false,
    }
}

fn valid_consumer_operation_timeout(timeout: Duration) -> bool {
    !timeout.is_zero() && timeout <= DEFAULT_CONSUMER_OPERATION_TIMEOUT
}

struct QueuedConsumerWatchItem {
    item: Option<Result<SessionConsumerChange, StoreError>>,
    // Retained for precisely as long as this item occupies the bounded local
    // queue. Dropping it returns its byte budget to the producer.
    _byte_permit: OwnedSemaphorePermit,
    // The persistent pool is retained only while this item waits for caller
    // delivery, so the diagnostic remains exact even when the stream drops.
    watch_pool: Option<Arc<PersistentSessionConsumerPool>>,
}

impl QueuedConsumerWatchItem {
    fn into_item(mut self) -> Result<SessionConsumerChange, StoreError> {
        if let Some(pool) = self.watch_pool.take() {
            pool.counters.watch_buffered.fetch_sub(1, Ordering::Relaxed);
        }
        self.item
            .take()
            .expect("queued watch item is returned at most once")
    }
}

impl Drop for QueuedConsumerWatchItem {
    fn drop(&mut self) {
        if self.item.is_some() {
            if let Some(pool) = self.watch_pool.take() {
                pool.counters.watch_buffered.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

fn consumer_watch_item_byte_count(item: &Result<SessionConsumerChange, StoreError>) -> Option<u32> {
    let encoded = serde_json::to_vec(item).ok()?;
    if encoded.len() > CONSUMER_WATCH_CHANNEL_MAX_BYTES {
        return None;
    }
    u32::try_from(encoded.len().max(1)).ok()
}

#[derive(Clone, Copy)]
enum ConsumerWatchTerminal {
    Unavailable,
    Protocol,
    Store(SessionConsumerStoreError),
    PayloadTooLarge { actual: usize, max: usize },
}

impl ConsumerWatchTerminal {
    fn into_item(self) -> Result<SessionConsumerChange, StoreError> {
        let error = match self {
            Self::Unavailable => {
                StoreError::BackendUnavailable("consumer watch unavailable".into())
            }
            Self::Protocol => {
                StoreError::BackendUnavailable("consumer watch protocol invalid".into())
            }
            Self::Store(error) => error.into_store_error(),
            Self::PayloadTooLarge { actual, max } => StoreError::PayloadTooLarge { actual, max },
        };
        Err(error)
    }
}

/// One fixed out-of-band terminal slot ordered after the bounded item queue.
///
/// The slot stores only closed enum discriminants and two sizes; it never
/// retains an application payload or identifying value. Keeping it outside
/// the item and byte semaphores means either saturation boundary can still
/// preserve the exact terminal condition without adding an unbounded waiter.
struct ConsumerWatchTerminalSlot {
    item: StdMutex<Option<ConsumerWatchTerminal>>,
    watch_pool: Option<Weak<PersistentSessionConsumerPool>>,
}

impl ConsumerWatchTerminalSlot {
    fn new(watch_pool: Option<&Arc<PersistentSessionConsumerPool>>) -> Self {
        Self {
            item: StdMutex::new(None),
            watch_pool: watch_pool.map(Arc::downgrade),
        }
    }

    fn store(&self, item: ConsumerWatchTerminal) {
        let mut slot = self
            .item
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_some() {
            return;
        }
        if let Some(pool) = self.watch_pool.as_ref().and_then(Weak::upgrade) {
            counter_increment(&pool.counters.watch_buffered);
        }
        *slot = Some(item);
    }

    fn take(&self) -> Option<Result<SessionConsumerChange, StoreError>> {
        let item = self
            .item
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()?;
        if let Some(pool) = self.watch_pool.as_ref().and_then(Weak::upgrade) {
            pool.counters.watch_buffered.fetch_sub(1, Ordering::Relaxed);
        }
        Some(item.into_item())
    }
}

impl Drop for ConsumerWatchTerminalSlot {
    fn drop(&mut self) {
        let occupied = self
            .item
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .is_some();
        if occupied {
            if let Some(pool) = self.watch_pool.as_ref().and_then(Weak::upgrade) {
                pool.counters.watch_buffered.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

fn queued_consumer_watch_stream(
    receiver: mpsc::Receiver<QueuedConsumerWatchItem>,
    terminal: Arc<ConsumerWatchTerminalSlot>,
) -> BoxStream<'static, Result<SessionConsumerChange, StoreError>> {
    stream::unfold(
        (receiver, terminal),
        |(mut receiver, terminal)| async move {
            match receiver.recv().await {
                Some(item) => Some((item.into_item(), (receiver, terminal))),
                None => terminal.take().map(|item| (item, (receiver, terminal))),
            }
        },
    )
    .boxed()
}

fn consumer_watch_transport_lost(error: &ProtocolError) -> bool {
    matches!(
        error,
        ProtocolError::Io(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
            )
    )
}

/// Per-frame positive-byte observation used to distinguish a clean
/// inter-frame disconnect from a truncated authenticated frame.  The state is
/// deliberately local to one decoder invocation and retains no frame bytes.
#[derive(Default)]
struct ConsumerFrameReadProgress {
    started: AtomicBool,
}

impl ConsumerFrameReadProgress {
    fn started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }
}

struct ConsumerProgressReader<'a, R> {
    inner: &'a mut R,
    progress: &'a ConsumerFrameReadProgress,
}

impl<R> AsyncRead for ConsumerProgressReader<'_, R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut *self.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            self.progress.started.store(true, Ordering::Release);
        }
        result
    }
}

const fn normalized_consumer_watch_cursor(start_sequence: u64) -> u64 {
    if start_sequence == 0 {
        1
    } else {
        start_sequence
    }
}

enum ConsumerWatchRead {
    Frame(Result<ConsumerWireResponse, ProtocolError>),
    Idle,
    Reconnect,
}

/// Redaction-safe construction or transport failure for a typed consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionConsumerClientError {
    /// Mutual TLS authentication or the expected server identity failed.
    #[error("session consumer authentication failed")]
    Authentication,
    /// Cluster/configuration/epoch scope was rejected.
    #[error("session consumer scope was rejected")]
    Scope,
    /// A malformed or unexpected typed frame was received.
    #[error("session consumer protocol failed")]
    Protocol,
    /// The quorum endpoint was unavailable.
    #[error("session consumer endpoint is unavailable")]
    Unavailable,
    /// The bounded connection or operation deadline elapsed.
    #[error("session consumer deadline elapsed")]
    Deadline,
    /// The fixed persistent consumer pool could not admit the call.
    #[error("session consumer is overloaded")]
    Overloaded,
    /// The persistent consumer client has begun shutdown.
    #[error("session consumer is shutting down")]
    ShuttingDown,
}

/// Effect-boundary-preserving failure from the persistent client's raw typed
/// request surface.
///
/// Callers that use the operation-specific mutation helpers receive their
/// corresponding mutation error type. Callers that retain a complete typed
/// request can use this error to distinguish a request proven not transmitted
/// from one whose outcome must be recovered under the exact retained request
/// identity and body.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PersistentSessionConsumerExecuteError {
    /// No call-frame byte crossed the transport boundary.
    #[error("persistent consumer request was not transmitted: {cause}")]
    NotTransmitted {
        /// Redaction-safe pre-write transport classification.
        cause: SessionConsumerClientError,
    },
    /// A read-only request may have been transmitted, but has no caller
    /// effect and is safe to retry under the normal read policy.
    #[error("persistent consumer read is unavailable: {cause}")]
    ReadUnavailable {
        /// Redaction-safe transport classification.
        cause: SessionConsumerClientError,
    },
    /// The call may have crossed the transport boundary.
    #[error("persistent consumer request outcome is unconfirmed; retry only the retained request")]
    OutcomeUnknown {
        /// Caller-owned identity of the complete request that may be retried.
        request_id: SessionConsumerRequestId,
    },
}

impl fmt::Debug for PersistentSessionConsumerExecuteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::NotTransmitted { .. } => "not_transmitted",
            Self::ReadUnavailable { .. } => "read_unavailable",
            Self::OutcomeUnknown { .. } => "outcome_unknown",
        };
        formatter
            .debug_struct("PersistentSessionConsumerExecuteError")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

impl PersistentSessionConsumerExecuteError {
    /// Return the only request identity permitted for exact recovery.
    pub const fn exact_retry_id(&self) -> Option<SessionConsumerRequestId> {
        match self {
            Self::OutcomeUnknown { request_id } => Some(*request_id),
            Self::NotTransmitted { .. } | Self::ReadUnavailable { .. } => None,
        }
    }
}

fn persistent_execute_error_for_request(
    request: &SessionConsumerRequest,
    error: SessionConsumerCallError,
) -> PersistentSessionConsumerExecuteError {
    persistent_execute_error_with_effect(
        request.request_id(),
        consumer_operation_is_effectful(request.operation()),
        error,
    )
}

#[cfg(test)]
fn persistent_execute_error(
    request_id: SessionConsumerRequestId,
    error: SessionConsumerCallError,
) -> PersistentSessionConsumerExecuteError {
    persistent_execute_error_with_effect(request_id, true, error)
}

fn persistent_execute_error_with_effect(
    request_id: SessionConsumerRequestId,
    effectful: bool,
    error: SessionConsumerCallError,
) -> PersistentSessionConsumerExecuteError {
    match error {
        SessionConsumerCallError::BeforeCallWrite(cause) => {
            PersistentSessionConsumerExecuteError::NotTransmitted { cause }
        }
        SessionConsumerCallError::MayHaveSent(cause) if !effectful => {
            PersistentSessionConsumerExecuteError::ReadUnavailable { cause }
        }
        SessionConsumerCallError::MayHaveSent(_) => {
            PersistentSessionConsumerExecuteError::OutcomeUnknown { request_id }
        }
    }
}

fn consumer_operation_is_effectful(operation: &SessionConsumerOperation) -> bool {
    match operation {
        SessionConsumerOperation::Capabilities
        | SessionConsumerOperation::Get { .. }
        | SessionConsumerOperation::PreflightRecordExpiry { .. }
        | SessionConsumerOperation::ScanRestoreRecords { .. }
        | SessionConsumerOperation::Watch { .. } => false,
        SessionConsumerOperation::Batch { ops } => ops
            .iter()
            .any(|operation| !matches!(operation, SessionOp::Get { .. })),
        SessionConsumerOperation::CompareAndSet { .. }
        | SessionConsumerOperation::DeleteFenced { .. }
        | SessionConsumerOperation::RefreshTtl { .. }
        | SessionConsumerOperation::AcquireLease { .. }
        | SessionConsumerOperation::RenewLease { .. }
        | SessionConsumerOperation::ReleaseLease { .. } => true,
        _ => true,
    }
}

/// Redaction-safe invalid persistent-consumer configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PersistentSessionConsumerConfigError {
    /// A bounded numeric capacity was outside the public hard limits.
    #[error("invalid persistent session consumer capacity")]
    Capacity,
    /// A required finite duration or retry count was invalid.
    #[error("invalid persistent session consumer timing")]
    Timing,
}

/// Fixed, validated capacity and timing policy for a persistent consumer.
///
/// Fields are private so a pool cannot be constructed with an unbounded task,
/// queue, or connection cardinality. A pending-call count of zero deliberately
/// selects fail-fast admission.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PersistentSessionConsumerConfig {
    request_connections: usize,
    pending_calls: usize,
    pool_wait_timeout: Duration,
    watch_connections: usize,
    setup_timeout: Duration,
    connect_attempts: usize,
    reconnect_jitter: Duration,
    shutdown_drain: Duration,
}

impl fmt::Debug for PersistentSessionConsumerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentSessionConsumerConfig")
            .field("request_connections", &self.request_connections)
            .field("pending_calls", &self.pending_calls)
            .field("pool_wait_timeout", &self.pool_wait_timeout)
            .field("watch_connections", &self.watch_connections)
            .field("setup_timeout", &self.setup_timeout)
            .field("connect_attempts", &self.connect_attempts)
            .field("reconnect_jitter", &self.reconnect_jitter)
            .field("shutdown_drain", &self.shutdown_drain)
            .finish()
    }
}

impl Default for PersistentSessionConsumerConfig {
    fn default() -> Self {
        Self {
            request_connections: DEFAULT_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS,
            pending_calls: DEFAULT_PERSISTENT_SESSION_CONSUMER_PENDING_CALLS,
            pool_wait_timeout: DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            watch_connections: DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            setup_timeout: DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            connect_attempts: DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
            reconnect_jitter: DEFAULT_PERSISTENT_SESSION_CONSUMER_RECONNECT_JITTER,
            shutdown_drain: DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        }
    }
}

impl PersistentSessionConsumerConfig {
    /// Construct a complete bounded persistent-client configuration.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        request_connections: usize,
        pending_calls: usize,
        pool_wait_timeout: Duration,
        watch_connections: usize,
        setup_timeout: Duration,
        connect_attempts: usize,
        reconnect_jitter: Duration,
        shutdown_drain: Duration,
    ) -> Result<Self, PersistentSessionConsumerConfigError> {
        let config = Self {
            request_connections,
            pending_calls,
            pool_wait_timeout,
            watch_connections,
            setup_timeout,
            connect_attempts,
            reconnect_jitter,
            shutdown_drain,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), PersistentSessionConsumerConfigError> {
        if !(1..=MAX_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS)
            .contains(&self.request_connections)
            || self.pending_calls > MAX_PERSISTENT_SESSION_CONSUMER_PENDING_CALLS
            || !(1..=MAX_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS)
                .contains(&self.watch_connections)
        {
            return Err(PersistentSessionConsumerConfigError::Capacity);
        }
        if self.pool_wait_timeout.is_zero()
            || self.pool_wait_timeout > DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT
            || self.setup_timeout.is_zero()
            || self.setup_timeout > DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT
            || self.shutdown_drain.is_zero()
            || self.shutdown_drain > DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN
            || self.connect_attempts == 0
            || self.connect_attempts > DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS
            || self.reconnect_jitter > DEFAULT_PERSISTENT_SESSION_CONSUMER_RECONNECT_JITTER
        {
            return Err(PersistentSessionConsumerConfigError::Timing);
        }
        Ok(())
    }

    /// Return the fixed normal-request lane count.
    pub const fn request_connections(&self) -> usize {
        self.request_connections
    }
    /// Return the bounded persistent-call admission count.
    pub const fn pending_calls(&self) -> usize {
        self.pending_calls
    }
    /// Return the maximum bounded wait for a request lane.
    pub const fn pool_wait_timeout(&self) -> Duration {
        self.pool_wait_timeout
    }
    /// Return the isolated watch capacity.
    pub const fn watch_connections(&self) -> usize {
        self.watch_connections
    }
    /// Return the cold physical setup deadline.
    pub const fn setup_timeout(&self) -> Duration {
        self.setup_timeout
    }
    /// Return the maximum safe pre-write attempt count.
    pub const fn connect_attempts(&self) -> usize {
        self.connect_attempts
    }
    /// Return the bounded reconnect jitter maximum.
    pub const fn reconnect_jitter(&self) -> Duration {
        self.reconnect_jitter
    }
    /// Return the shutdown drain limit.
    pub const fn shutdown_drain(&self) -> Duration {
        self.shutdown_drain
    }
}

/// Fixed numeric, nonidentifying persistent-pool diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PersistentSessionConsumerDiagnostics {
    pub setup_attempts: u64,
    pub setup_failures: u64,
    pub setup_successes: u64,
    pub resolve_attempts: u64,
    pub resolve_failures: u64,
    pub tcp_attempts: u64,
    pub tcp_failures: u64,
    pub tls_attempts: u64,
    pub tls_failures: u64,
    pub hello_attempts: u64,
    pub hello_failures: u64,
    pub pool_wait_current: u64,
    pub pool_wait_max: u64,
    pub pool_wait_count: u64,
    pub pool_wait_max_duration_millis: u64,
    pub pool_wait_oldest_age_millis: u64,
    pub active: u64,
    pub max_active: u64,
    pub idle: u64,
    pub reused: u64,
    pub reconnects: u64,
    pub failures: u64,
    pub queued: u64,
    pub inflight: u64,
    pub max_inflight: u64,
    pub watch_active: u64,
    pub max_watch_active: u64,
    /// Current caller-visible items held in bounded persistent-watch queues.
    pub watch_buffered: u64,
    pub successes: u64,
    pub not_transmitted: u64,
    pub outcome_unknown: u64,
    pub overload: u64,
    pub shutdown: u64,
    pub authentication: u64,
    pub scope: u64,
    pub protocol: u64,
    pub deadline: u64,
}

/// Conservative transport-capacity readiness only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PersistentSessionConsumerReadiness {
    pub ready: bool,
    pub configured_request_connections: usize,
    pub ready_request_connections: usize,
}

/// Bounded persistent-client shutdown result.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PersistentSessionConsumerShutdownReport {
    pub drained_calls: u64,
    pub forced_calls: u64,
    pub drained_watches: u64,
    pub forced_watches: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionConsumerCallError {
    BeforeCallWrite(SessionConsumerClientError),
    MayHaveSent(SessionConsumerClientError),
}

impl SessionConsumerCallError {
    const fn into_client_error(self) -> SessionConsumerClientError {
        match self {
            Self::BeforeCallWrite(error) | Self::MayHaveSent(error) => error,
        }
    }
}

fn classify_call_write_error(
    error: FrameWriteError,
    pre_request_budget_active: bool,
) -> SessionConsumerCallError {
    match error {
        FrameWriteError::BeforeWrite(error) => SessionConsumerCallError::BeforeCallWrite(
            pre_request_error(error.into(), pre_request_budget_active),
        ),
        FrameWriteError::MayHaveWritten(error) => {
            SessionConsumerCallError::MayHaveSent(error.into())
        }
    }
}

fn classify_interrupted_call_write(
    progress: &FrameWriteProgress,
    error: SessionConsumerClientError,
) -> SessionConsumerCallError {
    if progress.accepted_any() {
        SessionConsumerCallError::MayHaveSent(error)
    } else {
        SessionConsumerCallError::BeforeCallWrite(error)
    }
}

const fn pre_request_timeout_error(pre_request_budget_active: bool) -> SessionConsumerClientError {
    if pre_request_budget_active {
        SessionConsumerClientError::Unavailable
    } else {
        SessionConsumerClientError::Deadline
    }
}

const fn pre_request_error(
    error: SessionConsumerClientError,
    pre_request_budget_active: bool,
) -> SessionConsumerClientError {
    match error {
        SessionConsumerClientError::Deadline => {
            pre_request_timeout_error(pre_request_budget_active)
        }
        _ => error,
    }
}

fn ensure_pre_request_budget_remaining(
    deadline: tokio::time::Instant,
    pre_request_budget_active: bool,
) -> Result<(), SessionConsumerClientError> {
    if pre_request_budget_active && tokio::time::Instant::now() >= deadline {
        Err(SessionConsumerClientError::Unavailable)
    } else {
        Ok(())
    }
}

const fn consumer_rejection_into_client_error(
    rejection: SessionConsumerRejection,
) -> SessionConsumerClientError {
    match rejection {
        SessionConsumerRejection::ScopeMismatch => SessionConsumerClientError::Scope,
        SessionConsumerRejection::MalformedRequest => SessionConsumerClientError::Protocol,
        SessionConsumerRejection::Unauthorized => SessionConsumerClientError::Authentication,
        SessionConsumerRejection::Unavailable => SessionConsumerClientError::Unavailable,
    }
}

fn complete_before_deadline<T, E>(
    value: T,
    deadline: tokio::time::Instant,
    late_error: E,
) -> Result<T, E> {
    if tokio::time::Instant::now() < deadline {
        Ok(value)
    } else {
        Err(late_error)
    }
}

/// Result failure for a state mutation submitted through the consumer port.
///
/// This is deliberately distinct from [`StoreError`]. If the request crossed
/// the transport effect boundary without a response, only an exact replay of
/// the *same request body* under the retained [`SessionConsumerRequestId`] is
/// permitted to recover the durable result. A new ID would be a new mutation.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionConsumerMutationError {
    /// The application call frame was never written, so no mutation effect is
    /// possible. A caller may safely try another admitted quorum endpoint.
    #[error("consumer mutation was not transmitted: {cause}")]
    NotTransmitted {
        /// Redaction-safe transport classification before the call boundary.
        cause: SessionConsumerClientError,
    },
    /// The durable outcome is unconfirmed. Retry only the identical request
    /// with this retained ID; never mint a new ID for the same mutation.
    #[error("consumer mutation outcome is unconfirmed; retry only the retained request ID")]
    OutcomeUnknown {
        /// Caller-owned exact retry identity.
        request_id: SessionConsumerRequestId,
    },
    /// A confirmed consumer-store failure.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl fmt::Debug for SessionConsumerMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::NotTransmitted { .. } => "not_transmitted",
            Self::OutcomeUnknown { .. } => "outcome_unknown",
            Self::Store(_) => "store",
        };
        formatter
            .debug_struct("SessionConsumerMutationError")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

impl SessionConsumerMutationError {
    /// Return the sole request identity permitted for exact recovery.
    pub const fn exact_retry_id(&self) -> Option<SessionConsumerRequestId> {
        match self {
            Self::OutcomeUnknown { request_id } => Some(*request_id),
            Self::NotTransmitted { .. } | Self::Store(_) => None,
        }
    }
}

/// Result failure for a lease mutation submitted through the consumer port.
///
/// While [`Self::OutcomeUnknown`] is held, the presented guard is lost for
/// writes. The caller may use only the retained ID to recover the exact
/// durable acquisition/renewal/release result; it must not write with the old
/// guard while that recovery is pending.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionConsumerLeaseMutationError {
    /// The application call frame was never written, so the lease state is
    /// unchanged. A caller may safely try another admitted quorum endpoint.
    #[error("consumer lease mutation was not transmitted: {cause}")]
    NotTransmitted {
        /// Redaction-safe transport classification before the call boundary.
        cause: SessionConsumerClientError,
    },
    /// The lease outcome is unconfirmed and the old guard is unusable.
    #[error("consumer lease outcome is unconfirmed; old guard is lost")]
    OutcomeUnknown {
        /// Caller-owned exact retry identity.
        request_id: SessionConsumerRequestId,
    },
    /// A confirmed consumer lease failure.
    #[error(transparent)]
    Lease(#[from] LeaseError),
}

impl fmt::Debug for SessionConsumerLeaseMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::NotTransmitted { .. } => "not_transmitted",
            Self::OutcomeUnknown { .. } => "outcome_unknown",
            Self::Lease(_) => "lease",
        };
        formatter
            .debug_struct("SessionConsumerLeaseMutationError")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

impl SessionConsumerLeaseMutationError {
    /// Return the sole request identity permitted for exact result recovery.
    pub const fn exact_retry_id(&self) -> Option<SessionConsumerRequestId> {
        match self {
            Self::OutcomeUnknown { request_id } => Some(*request_id),
            Self::NotTransmitted { .. } | Self::Lease(_) => None,
        }
    }
}

impl From<ProtocolError> for SessionConsumerClientError {
    fn from(error: ProtocolError) -> Self {
        match error {
            ProtocolError::Authentication => Self::Authentication,
            ProtocolError::Io(io_error) if io_error.kind() == io::ErrorKind::TimedOut => {
                Self::Deadline
            }
            ProtocolError::Io(_) => Self::Unavailable,
            ProtocolError::BackendUnavailable(_) => Self::Unavailable,
            ProtocolError::VersionMismatch { .. } | ProtocolError::ContractMismatch => {
                Self::Protocol
            }
            ProtocolError::FrameTooLarge(_)
            | ProtocolError::Serialization(_)
            | ProtocolError::InvalidWireValue
            | ProtocolError::UnexpectedResponse => Self::Protocol,
        }
    }
}

/// Redaction-safe authorization configuration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionConsumerAuthorizationError {
    /// No consumer identity was admitted.
    #[error("session consumer authorization is empty")]
    Empty,
    /// A member identity was configured as a consumer identity.
    #[error("session consumer identity overlaps a consensus member")]
    MemberRoleConflict,
    /// One configured identity did not satisfy the consumer identity bounds.
    #[error("invalid session consumer authorization identity")]
    InvalidIdentity,
}

/// Exact mTLS authorization policy for typed application consumers.
///
/// Consumers and consensus members are separate identity sets. An identity in
/// the consensus-member set is rejected even if it is also present in the
/// consumer set, preventing role confusion at the listener boundary.
#[derive(Clone)]
pub struct SessionConsumerAuthorizer {
    scope: SessionConsumerScope,
    consumers: BTreeSet<String>,
    consensus_members: BTreeSet<String>,
}

impl fmt::Debug for SessionConsumerAuthorizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConsumerAuthorizer")
            .field("consumer_count", &self.consumers.len())
            .field("consensus_member_count", &self.consensus_members.len())
            .finish()
    }
}

impl SessionConsumerAuthorizer {
    /// Construct an authorization policy from the store-issued current-member
    /// manifest and application mTLS SPIFFE IDs.
    ///
    /// The member exclusion set and scope cannot be supplied independently:
    /// doing so would let a deployment omit an actual quorum member and admit
    /// it through the consumer listener.
    pub fn try_new(
        manifest: SessionConsumerAuthorizationManifest,
        consumer_identities: impl IntoIterator<Item = SpiffeId>,
    ) -> Result<Self, SessionConsumerAuthorizationError> {
        Self::from_authoritative_members(
            manifest.scope(),
            consumer_identities,
            manifest.consensus_member_identities().map(str::to_owned),
        )
    }

    fn from_authoritative_members(
        scope: SessionConsumerScope,
        consumer_identities: impl IntoIterator<Item = SpiffeId>,
        consensus_member_identities: impl IntoIterator<Item = String>,
    ) -> Result<Self, SessionConsumerAuthorizationError> {
        let consumers = consumer_identities
            .into_iter()
            .map(|identity| {
                SessionConsumerIdentity::new(identity.as_str().to_owned())
                    .map(|identity| identity.as_str().to_owned())
                    .map_err(|_| SessionConsumerAuthorizationError::InvalidIdentity)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if consumers.is_empty() {
            return Err(SessionConsumerAuthorizationError::Empty);
        }
        let consensus_members = consensus_member_identities
            .into_iter()
            .map(|identity| {
                SessionConsumerIdentity::new(identity)
                    .map(|identity| identity.as_str().to_owned())
                    .map_err(|_| SessionConsumerAuthorizationError::InvalidIdentity)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if consumers
            .iter()
            .any(|identity| consensus_members.contains(identity))
        {
            return Err(SessionConsumerAuthorizationError::MemberRoleConflict);
        }
        Ok(Self {
            scope,
            consumers,
            consensus_members,
        })
    }

    /// Return the only consensus scope this policy admits.
    pub const fn scope(&self) -> SessionConsumerScope {
        self.scope
    }

    fn authorize(
        &self,
        identity: &SpiffeId,
    ) -> Result<SessionConsumerIdentity, SessionConsumerRejection> {
        let identity = identity.as_str();
        if self.consensus_members.contains(identity) || !self.consumers.contains(identity) {
            return Err(SessionConsumerRejection::Unauthorized);
        }
        SessionConsumerIdentity::new(identity.to_owned())
            .map_err(|_| SessionConsumerRejection::Unauthorized)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerHello {
    transport_revision: u16,
    scope: SessionConsumerScope,
    response_frame_size: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerHelloAck {
    transport_revision: u16,
    scope: SessionConsumerScope,
    request_frame_size: u32,
}

/// Connection-local request/response correlation. It is deliberately not an
/// application request ID and is never surfaced in public diagnostics/errors.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerCall {
    correlation: NonZeroU32,
    request: Box<SessionConsumerRequest>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BorrowedConsumerCall<'a> {
    correlation: NonZeroU32,
    request: &'a SessionConsumerRequest,
}

/// Serialization-only view of a call. Keeping the caller-owned request
/// borrowed avoids copying a potentially maximum-sized payload for every safe
/// pre-write reconnect attempt while retaining the exact revision-2 encoding.
#[derive(Serialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum BorrowedConsumerWireRequest<'a> {
    Call(BorrowedConsumerCall<'a>),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerCallResponse {
    correlation: NonZeroU32,
    #[serde(
        serialize_with = "serialize_consumer_response_box",
        deserialize_with = "deserialize_consumer_response_box"
    )]
    response: Box<SessionConsumerResponse>,
}

struct BorrowedConsumerCallResponse<'a> {
    correlation: NonZeroU32,
    response: SerializableConsumerResponse<'a>,
}

impl Serialize for BorrowedConsumerCallResponse<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("BorrowedConsumerCallResponse", 2)?;
        state.serialize_field("correlation", &self.correlation)?;
        state.serialize_field("response", &self.response)?;
        state.end()
    }
}

struct SerializableConsumerResponse<'a>(&'a SessionConsumerResponse);

impl Serialize for SerializableConsumerResponse<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialize_consumer_response(self.0, serializer)
    }
}

#[derive(Serialize)]
struct ConsumerCapabilitiesResponseWire {
    response: &'static str,
    body: WireBackendCapabilities,
}

#[derive(Deserialize)]
#[serde(
    tag = "response",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ConsumerSessionResponseWire {
    Capabilities(WireBackendCapabilities),
    Get(Result<Option<opc_session_store::StoredSessionRecord>, SessionConsumerStoreError>),
    PreflightRecordExpiry(Result<(), SessionConsumerStoreError>),
    CompareAndSet(Result<CompareAndSetResult, SessionConsumerStoreError>),
    DeleteFenced(Result<(), SessionConsumerStoreError>),
    RefreshTtl(Result<(), SessionConsumerStoreError>),
    Batch(Result<Vec<SessionConsumerBatchResult>, SessionConsumerStoreError>),
    ScanRestoreRecords(Result<RestoreScanPage, SessionConsumerStoreError>),
    WatchOpened,
    AcquireLease(Result<SessionConsumerLeaseGrant, SessionConsumerLeaseError>),
    RenewLease(Result<SessionConsumerLeaseGrant, SessionConsumerLeaseError>),
    ReleaseLease(Result<(), SessionConsumerLeaseError>),
    OutcomeUnknown(SessionConsumerOutcomeUnknown),
    Rejected(SessionConsumerRejection),
}

impl TryFrom<ConsumerSessionResponseWire> for SessionConsumerResponse {
    type Error = crate::protocol::WireConversionError;

    fn try_from(response: ConsumerSessionResponseWire) -> Result<Self, Self::Error> {
        Ok(match response {
            ConsumerSessionResponseWire::Capabilities(capabilities) => {
                Self::Capabilities(BackendCapabilities::try_from(capabilities)?)
            }
            ConsumerSessionResponseWire::Get(value) => Self::Get(value),
            ConsumerSessionResponseWire::PreflightRecordExpiry(value) => {
                Self::PreflightRecordExpiry(value)
            }
            ConsumerSessionResponseWire::CompareAndSet(value) => Self::CompareAndSet(value),
            ConsumerSessionResponseWire::DeleteFenced(value) => Self::DeleteFenced(value),
            ConsumerSessionResponseWire::RefreshTtl(value) => Self::RefreshTtl(value),
            ConsumerSessionResponseWire::Batch(value) => Self::Batch(value),
            ConsumerSessionResponseWire::ScanRestoreRecords(value) => {
                Self::ScanRestoreRecords(value)
            }
            ConsumerSessionResponseWire::WatchOpened => Self::WatchOpened,
            ConsumerSessionResponseWire::AcquireLease(value) => Self::AcquireLease(value),
            ConsumerSessionResponseWire::RenewLease(value) => Self::RenewLease(value),
            ConsumerSessionResponseWire::ReleaseLease(value) => Self::ReleaseLease(value),
            ConsumerSessionResponseWire::OutcomeUnknown(value) => Self::OutcomeUnknown(value),
            ConsumerSessionResponseWire::Rejected(value) => Self::Rejected(value),
        })
    }
}

fn serialize_consumer_response<S>(
    response: &SessionConsumerResponse,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match response {
        SessionConsumerResponse::Capabilities(capabilities) => ConsumerCapabilitiesResponseWire {
            response: "capabilities",
            body: WireBackendCapabilities::try_from(capabilities)
                .map_err(serde::ser::Error::custom)?,
        }
        .serialize(serializer),
        response => response.serialize(serializer),
    }
}

fn serialize_consumer_response_box<S>(
    response: &SessionConsumerResponse,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serialize_consumer_response(response, serializer)
}

fn deserialize_consumer_response_box<'de, D>(
    deserializer: D,
) -> Result<Box<SessionConsumerResponse>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    ConsumerSessionResponseWire::deserialize(deserializer)
        .and_then(|response| {
            SessionConsumerResponse::try_from(response).map_err(serde::de::Error::custom)
        })
        .map(Box::new)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerWatchEntry {
    correlation: NonZeroU32,
    entry: Box<Result<SessionConsumerChange, SessionConsumerStoreError>>,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ConsumerWireRequest {
    Hello(ConsumerHello),
    Call(ConsumerCall),
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ConsumerWireResponse {
    HelloAck(ConsumerHelloAck),
    HelloRejected(SessionConsumerRejection),
    Response(ConsumerCallResponse),
    WatchEntry(ConsumerWatchEntry),
}

#[derive(Serialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum BorrowedConsumerWireResponse<'a> {
    Response(BorrowedConsumerCallResponse<'a>),
}

fn exact_correlation(expected: NonZeroU32, received: NonZeroU32) -> Result<(), ProtocolError> {
    if expected != received {
        Err(ProtocolError::UnexpectedResponse)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConsumerOperationKind {
    Capabilities,
    Get,
    PreflightRecordExpiry,
    CompareAndSet,
    DeleteFenced,
    RefreshTtl,
    Batch {
        contains_mutation: bool,
    },
    ScanRestoreRecords,
    Watch,
    AcquireLease,
    RenewLease,
    ReleaseLease,
    /// A newer operation is never treated as an existing response family.
    /// It is conservatively effectful only for generic rejection/ambiguity.
    UnknownEffectful,
}

impl ConsumerOperationKind {
    fn from_operation(operation: &SessionConsumerOperation) -> Self {
        match operation {
            SessionConsumerOperation::Capabilities => Self::Capabilities,
            SessionConsumerOperation::Get { .. } => Self::Get,
            SessionConsumerOperation::PreflightRecordExpiry { .. } => Self::PreflightRecordExpiry,
            SessionConsumerOperation::CompareAndSet { .. } => Self::CompareAndSet,
            SessionConsumerOperation::DeleteFenced { .. } => Self::DeleteFenced,
            SessionConsumerOperation::RefreshTtl { .. } => Self::RefreshTtl,
            SessionConsumerOperation::Batch { ops } => Self::Batch {
                contains_mutation: ops.iter().any(|op| !matches!(op, SessionOp::Get { .. })),
            },
            SessionConsumerOperation::ScanRestoreRecords { .. } => Self::ScanRestoreRecords,
            SessionConsumerOperation::Watch { .. } => Self::Watch,
            SessionConsumerOperation::AcquireLease { .. } => Self::AcquireLease,
            SessionConsumerOperation::RenewLease { .. } => Self::RenewLease,
            SessionConsumerOperation::ReleaseLease { .. } => Self::ReleaseLease,
            _ => Self::UnknownEffectful,
        }
    }
}

fn response_matches_operation(
    operation: ConsumerOperationKind,
    response: &SessionConsumerResponse,
) -> bool {
    if matches!(response, SessionConsumerResponse::Rejected(_)) {
        return true;
    }
    matches!(
        (operation, response),
        (
            ConsumerOperationKind::Capabilities,
            SessionConsumerResponse::Capabilities(_)
        ) | (ConsumerOperationKind::Get, SessionConsumerResponse::Get(_))
            | (
                ConsumerOperationKind::PreflightRecordExpiry,
                SessionConsumerResponse::PreflightRecordExpiry(_),
            )
            | (
                ConsumerOperationKind::CompareAndSet,
                SessionConsumerResponse::CompareAndSet(_)
            )
            | (
                ConsumerOperationKind::DeleteFenced,
                SessionConsumerResponse::DeleteFenced(_)
            )
            | (
                ConsumerOperationKind::RefreshTtl,
                SessionConsumerResponse::RefreshTtl(_)
            )
            | (
                ConsumerOperationKind::Batch { .. },
                SessionConsumerResponse::Batch(_)
            )
            | (
                ConsumerOperationKind::ScanRestoreRecords,
                SessionConsumerResponse::ScanRestoreRecords(_),
            )
            | (
                ConsumerOperationKind::Watch,
                SessionConsumerResponse::WatchOpened
            )
            | (
                ConsumerOperationKind::AcquireLease,
                SessionConsumerResponse::AcquireLease(_)
            )
            | (
                ConsumerOperationKind::RenewLease,
                SessionConsumerResponse::RenewLease(_)
            )
            | (
                ConsumerOperationKind::ReleaseLease,
                SessionConsumerResponse::ReleaseLease(_)
            )
            | (
                ConsumerOperationKind::CompareAndSet
                    | ConsumerOperationKind::DeleteFenced
                    | ConsumerOperationKind::RefreshTtl,
                SessionConsumerResponse::OutcomeUnknown(SessionConsumerOutcomeUnknown::Mutation),
            )
            | (
                ConsumerOperationKind::Batch {
                    contains_mutation: true,
                },
                SessionConsumerResponse::OutcomeUnknown(SessionConsumerOutcomeUnknown::Mutation),
            )
            | (
                ConsumerOperationKind::UnknownEffectful,
                SessionConsumerResponse::OutcomeUnknown(SessionConsumerOutcomeUnknown::Mutation),
            )
            | (
                ConsumerOperationKind::AcquireLease
                    | ConsumerOperationKind::RenewLease
                    | ConsumerOperationKind::ReleaseLease,
                SessionConsumerResponse::OutcomeUnknown(SessionConsumerOutcomeUnknown::Lease),
            )
    )
}

/// Check the closed, typed error against the operation that can actually
/// produce it.  The wire error deliberately erases backend detail, so this is
/// a conservative allow-list derived from the public consumer operation
/// contracts. An authenticated peer cannot use a same-variant but impossible
/// error to turn a stale or cross-family response into application success.
fn store_error_matches_operation(
    operation: &SessionConsumerOperation,
    error: SessionConsumerStoreError,
) -> bool {
    match operation {
        SessionConsumerOperation::Get { .. } => matches!(
            error,
            SessionConsumerStoreError::StaleFence
                | SessionConsumerStoreError::Unavailable
                | SessionConsumerStoreError::ProtectedDataRejected
        ),
        SessionConsumerOperation::PreflightRecordExpiry { .. } => matches!(
            error,
            SessionConsumerStoreError::StaleFence
                | SessionConsumerStoreError::Unavailable
                | SessionConsumerStoreError::InvalidInput
                | SessionConsumerStoreError::CapabilityNotSupported
        ),
        SessionConsumerOperation::CompareAndSet { .. } => matches!(
            error,
            SessionConsumerStoreError::NotFound
                | SessionConsumerStoreError::StaleFence
                | SessionConsumerStoreError::CasConflict
                | SessionConsumerStoreError::RequestConflict
                | SessionConsumerStoreError::OutcomeUnavailable
                | SessionConsumerStoreError::Unavailable
                | SessionConsumerStoreError::InvalidInput
                | SessionConsumerStoreError::CapabilityNotSupported
                | SessionConsumerStoreError::PayloadTooLarge
                | SessionConsumerStoreError::LeaseUnavailable
                | SessionConsumerStoreError::ProtectedDataRejected
        ),
        SessionConsumerOperation::DeleteFenced { .. } => matches!(
            error,
            SessionConsumerStoreError::NotFound
                | SessionConsumerStoreError::StaleFence
                | SessionConsumerStoreError::RequestConflict
                | SessionConsumerStoreError::OutcomeUnavailable
                | SessionConsumerStoreError::Unavailable
                | SessionConsumerStoreError::InvalidInput
                | SessionConsumerStoreError::CapabilityNotSupported
                | SessionConsumerStoreError::LeaseUnavailable
                | SessionConsumerStoreError::ProtectedDataRejected
        ),
        SessionConsumerOperation::RefreshTtl { .. } => matches!(
            error,
            SessionConsumerStoreError::NotFound
                | SessionConsumerStoreError::StaleFence
                | SessionConsumerStoreError::RequestConflict
                | SessionConsumerStoreError::OutcomeUnavailable
                | SessionConsumerStoreError::Unavailable
                | SessionConsumerStoreError::InvalidInput
                | SessionConsumerStoreError::CapabilityNotSupported
                | SessionConsumerStoreError::InvalidTtl
                | SessionConsumerStoreError::LeaseUnavailable
                | SessionConsumerStoreError::ProtectedDataRejected
        ),
        // A whole-batch error is emitted only before slot execution (input,
        // preflight, response admission, binding, or availability), never as
        // a disguised result of one ordered slot.
        SessionConsumerOperation::Batch { ops } => {
            matches!(error, SessionConsumerStoreError::RequestConflict)
                || (matches!(error, SessionConsumerStoreError::OutcomeUnavailable)
                    && ops.iter().any(|op| !matches!(op, SessionOp::Get { .. })))
                || matches!(
                    error,
                    SessionConsumerStoreError::StaleFence
                        | SessionConsumerStoreError::Unavailable
                        | SessionConsumerStoreError::InvalidInput
                        | SessionConsumerStoreError::CapabilityNotSupported
                        | SessionConsumerStoreError::InvalidTtl
                        | SessionConsumerStoreError::PayloadTooLarge
                        | SessionConsumerStoreError::ProtectedDataRejected
                )
        }
        SessionConsumerOperation::ScanRestoreRecords { .. } => matches!(
            error,
            SessionConsumerStoreError::StaleFence
                | SessionConsumerStoreError::Unavailable
                | SessionConsumerStoreError::CapabilityNotSupported
                | SessionConsumerStoreError::ProtectedDataRejected
                | SessionConsumerStoreError::RestoreRejected
                | SessionConsumerStoreError::RestoreCursorStale
                | SessionConsumerStoreError::RestoreBudgetExceeded
        ),
        // Watch errors travel in WatchEntry frames, capabilities have no
        // store-error body, and lease operations use their closed lease-error
        // family below.
        _ => false,
    }
}

fn batch_slot_error_matches_operation(
    operation: &SessionOp,
    error: SessionConsumerStoreError,
) -> bool {
    match operation {
        SessionOp::Get { .. } => matches!(
            error,
            SessionConsumerStoreError::StaleFence
                | SessionConsumerStoreError::Unavailable
                | SessionConsumerStoreError::ProtectedDataRejected
        ),
        SessionOp::CompareAndSet(op) => store_error_matches_operation(
            &SessionConsumerOperation::CompareAndSet {
                op: Box::new(op.clone()),
            },
            error,
        ),
        SessionOp::DeleteFenced { lease } => store_error_matches_operation(
            &SessionConsumerOperation::DeleteFenced {
                lease: lease.clone(),
            },
            error,
        ),
        SessionOp::RefreshTtl { lease, ttl } => store_error_matches_operation(
            &SessionConsumerOperation::RefreshTtl {
                lease: lease.clone(),
                ttl: *ttl,
            },
            error,
        ),
    }
}

/// Closed revision-2 error family for an already-open watch. These are the
/// only failures that can describe observation/catch-up of committed changes;
/// mutation, request-binding, lease, restore, and TTL errors are impossible on
/// this stream and therefore poison the authenticated lane.
fn consumer_watch_error_is_legal(error: SessionConsumerStoreError) -> bool {
    matches!(
        error,
        SessionConsumerStoreError::StaleFence
            | SessionConsumerStoreError::Unavailable
            | SessionConsumerStoreError::InvalidInput
            | SessionConsumerStoreError::WatchCatchUpRequired
            | SessionConsumerStoreError::ProtectedDataRejected
    )
}

fn batch_results_match_request(ops: &[SessionOp], results: &[SessionConsumerBatchResult]) -> bool {
    bounded_session_op_expectations(ops)
        .as_ref()
        .is_ok_and(|expected| {
            expected.len() == results.len()
                && ops
                    .iter()
                    .zip(results)
                    .all(|(operation, result)| match (operation, result) {
                        (SessionOp::Get { key }, SessionConsumerBatchResult::Get(result)) => {
                            get_result_matches_key(
                                key,
                                &result
                                    .clone()
                                    .map_err(SessionConsumerStoreError::into_store_error),
                            ) && result.as_ref().is_ok_and(|record| {
                                record.as_ref().is_none_or(|record| {
                                    validate_stored_record_expiry_profile(record).is_ok()
                                })
                            }) || result.as_ref().err().is_some_and(|error| {
                                batch_slot_error_matches_operation(operation, *error)
                            })
                        }
                        (
                            SessionOp::CompareAndSet(op),
                            SessionConsumerBatchResult::CompareAndSet(result),
                        ) => {
                            compare_and_set_result_matches_key(
                                &op.key,
                                &result
                                    .clone()
                                    .map_err(SessionConsumerStoreError::into_store_error),
                            ) && result
                                .as_ref()
                                .is_ok_and(compare_and_set_result_profile_matches)
                                || result.as_ref().err().is_some_and(|error| {
                                    batch_slot_error_matches_operation(operation, *error)
                                })
                        }
                        (
                            SessionOp::DeleteFenced { .. },
                            SessionConsumerBatchResult::DeleteFenced(result),
                        )
                        | (
                            SessionOp::RefreshTtl { .. },
                            SessionConsumerBatchResult::RefreshTtl(result),
                        ) => result.as_ref().err().is_none_or(|error| {
                            batch_slot_error_matches_operation(operation, *error)
                        }),
                        _ => false,
                    })
        })
}

fn compare_and_set_result_profile_matches(result: &CompareAndSetResult) -> bool {
    match result {
        CompareAndSetResult::Success | CompareAndSetResult::Conflict { current: None } => true,
        CompareAndSetResult::Conflict {
            current: Some(record),
        } => validate_stored_record_expiry_profile(record).is_ok(),
    }
}

fn lease_error_matches_operation(
    operation: &SessionConsumerOperation,
    error: SessionConsumerLeaseError,
) -> bool {
    match operation {
        SessionConsumerOperation::AcquireLease { .. } => matches!(
            error,
            SessionConsumerLeaseError::RequestConflict
                | SessionConsumerLeaseError::AlreadyHeld
                | SessionConsumerLeaseError::StaleFence
                | SessionConsumerLeaseError::InvalidTtl
                | SessionConsumerLeaseError::OutcomeUnavailable
                | SessionConsumerLeaseError::Unavailable
        ),
        SessionConsumerOperation::RenewLease { .. } => matches!(
            error,
            SessionConsumerLeaseError::RequestConflict
                | SessionConsumerLeaseError::AlreadyHeld
                | SessionConsumerLeaseError::Expired
                | SessionConsumerLeaseError::StaleFence
                | SessionConsumerLeaseError::NotFound
                | SessionConsumerLeaseError::InvalidTtl
                | SessionConsumerLeaseError::OutcomeUnavailable
                | SessionConsumerLeaseError::Unavailable
        ),
        SessionConsumerOperation::ReleaseLease { .. } => matches!(
            error,
            SessionConsumerLeaseError::RequestConflict
                | SessionConsumerLeaseError::AlreadyHeld
                | SessionConsumerLeaseError::StaleFence
                | SessionConsumerLeaseError::NotFound
                | SessionConsumerLeaseError::OutcomeUnavailable
                | SessionConsumerLeaseError::Unavailable
        ),
        _ => false,
    }
}

fn store_result_matches_operation<T>(
    operation: &SessionConsumerOperation,
    result: &Result<T, SessionConsumerStoreError>,
) -> bool {
    result
        .as_ref()
        .err()
        .is_none_or(|error| store_error_matches_operation(operation, *error))
}

/// Verify that an authenticated response is bound to the complete typed
/// operation that produced it, not merely to its response family.  This is
/// deliberately performed before a retained lane is returned to the pool, so
/// a malicious peer cannot turn a cross-key value or mismatched batch slot
/// into an application-visible success.
fn response_matches_request(
    request: &SessionConsumerRequest,
    response: &SessionConsumerResponse,
) -> bool {
    if !response_matches_operation(
        ConsumerOperationKind::from_operation(request.operation()),
        response,
    ) {
        return false;
    }

    match (request.operation(), response) {
        (SessionConsumerOperation::Get { key }, SessionConsumerResponse::Get(result)) => {
            get_result_matches_key(
                key,
                &result
                    .clone()
                    .map_err(SessionConsumerStoreError::into_store_error),
            ) && match result {
                Ok(record) => record
                    .as_ref()
                    .is_none_or(|record| validate_stored_record_expiry_profile(record).is_ok()),
                Err(error) => store_error_matches_operation(request.operation(), *error),
            }
        }
        (
            SessionConsumerOperation::CompareAndSet { op },
            SessionConsumerResponse::CompareAndSet(result),
        ) => {
            compare_and_set_result_matches_key(
                &op.key,
                &result
                    .clone()
                    .map_err(SessionConsumerStoreError::into_store_error),
            ) && match result {
                Ok(result) => compare_and_set_result_profile_matches(result),
                Err(error) => store_error_matches_operation(request.operation(), *error),
            }
        }
        (
            SessionConsumerOperation::PreflightRecordExpiry { .. },
            SessionConsumerResponse::PreflightRecordExpiry(result),
        ) => store_result_matches_operation(request.operation(), result),
        (
            SessionConsumerOperation::DeleteFenced { .. },
            SessionConsumerResponse::DeleteFenced(result),
        )
        | (
            SessionConsumerOperation::RefreshTtl { .. },
            SessionConsumerResponse::RefreshTtl(result),
        ) => store_result_matches_operation(request.operation(), result),
        (SessionConsumerOperation::Batch { ops }, SessionConsumerResponse::Batch(Ok(results))) => {
            batch_results_match_request(ops, results)
        }
        (SessionConsumerOperation::Batch { .. }, SessionConsumerResponse::Batch(Err(error))) => {
            store_error_matches_operation(request.operation(), *error)
        }
        (
            SessionConsumerOperation::ScanRestoreRecords { request },
            SessionConsumerResponse::ScanRestoreRecords(Ok(page)),
        ) => {
            page.cursor_profile == opc_session_store::RestoreScanCursorProfile::DurableOpaqueV1
                && validate_restore_scan_wire_payload_bytes(&page.records).is_ok()
                && page.validate_for_request(request).is_ok()
                && page
                    .records
                    .iter()
                    .all(|record| validate_stored_record_expiry_profile(record).is_ok())
        }
        (
            SessionConsumerOperation::ScanRestoreRecords { .. },
            SessionConsumerResponse::ScanRestoreRecords(result),
        ) => store_result_matches_operation(request.operation(), result),
        (
            SessionConsumerOperation::AcquireLease { key, owner, ttl },
            SessionConsumerResponse::AcquireLease(Ok(grant)),
        ) => {
            let lease = grant.guard();
            lease.key() == key
                && lease.owner() == owner
                && crate::protocol::validate_lease_profile(lease).is_ok()
                && grant.authority_time() == lease.acquired_at()
                && checked_session_deadline(grant.authority_time(), *ttl)
                    .is_ok_and(|deadline| deadline == lease.expires_at())
        }
        (
            SessionConsumerOperation::AcquireLease { .. },
            SessionConsumerResponse::AcquireLease(Err(error)),
        ) => lease_error_matches_operation(request.operation(), *error),
        (
            SessionConsumerOperation::RenewLease { lease, ttl },
            SessionConsumerResponse::RenewLease(Ok(grant)),
        ) => {
            let renewed = grant.guard();
            renewed.key() == lease.key()
                && renewed.owner() == lease.owner()
                && renewed.fence() == lease.fence()
                && renewed.credential_id() == lease.credential_id()
                && renewed.acquired_at() == lease.acquired_at()
                && crate::protocol::validate_lease_profile(renewed).is_ok()
                && grant.authority_time() >= lease.acquired_at()
                && renewed.expires_at() > lease.expires_at()
                && checked_session_deadline(grant.authority_time(), *ttl)
                    .is_ok_and(|deadline| deadline == renewed.expires_at())
        }
        (
            SessionConsumerOperation::RenewLease { .. },
            SessionConsumerResponse::RenewLease(Err(error)),
        ) => lease_error_matches_operation(request.operation(), *error),
        (
            SessionConsumerOperation::ReleaseLease { .. },
            SessionConsumerResponse::ReleaseLease(Err(error)),
        ) => lease_error_matches_operation(request.operation(), *error),
        (SessionConsumerOperation::Capabilities, SessionConsumerResponse::Capabilities(_))
        | (SessionConsumerOperation::Watch { .. }, SessionConsumerResponse::WatchOpened)
        | (
            SessionConsumerOperation::ReleaseLease { .. },
            SessionConsumerResponse::ReleaseLease(Ok(())),
        )
        | (_, SessionConsumerResponse::Rejected(_))
        | (_, SessionConsumerResponse::OutcomeUnknown(_)) => true,
        _ => false,
    }
}

/// A typed authority or malformed-request rejection is a valid response to
/// expose to the caller, but may be followed by peer-side lane retirement.
/// It must not be republished into the idle pool; the next independent call
/// will resolve and authenticate a fresh lane.  Unavailable remains
/// request-local because the server keeps a healthy lane after that typed
/// pre-dispatch rejection.
fn response_retires_connection_authority(response: &SessionConsumerResponse) -> bool {
    matches!(
        response,
        SessionConsumerResponse::Rejected(
            SessionConsumerRejection::ScopeMismatch
                | SessionConsumerRejection::Unauthorized
                | SessionConsumerRejection::MalformedRequest
        )
    )
}

fn batch_result_is_outcome_unknown(result: &SessionConsumerBatchResult) -> bool {
    match result {
        SessionConsumerBatchResult::Get(result) => {
            matches!(result, Err(SessionConsumerStoreError::OutcomeUnavailable))
        }
        SessionConsumerBatchResult::CompareAndSet(result) => {
            matches!(result, Err(SessionConsumerStoreError::OutcomeUnavailable))
        }
        SessionConsumerBatchResult::DeleteFenced(result)
        | SessionConsumerBatchResult::RefreshTtl(result) => {
            matches!(result, Err(SessionConsumerStoreError::OutcomeUnavailable))
        }
    }
}

/// Classify every legal ambiguity representation before publishing outcome
/// counters or returning a pooled lane. Nested batch uncertainty is a
/// request-level outcome, never an outer successful response.
fn response_is_outcome_unknown(
    operation: &SessionConsumerOperation,
    response: &SessionConsumerResponse,
) -> bool {
    match response {
        SessionConsumerResponse::OutcomeUnknown(_) => true,
        SessionConsumerResponse::CompareAndSet(Err(
            SessionConsumerStoreError::OutcomeUnavailable,
        ))
        | SessionConsumerResponse::DeleteFenced(Err(
            SessionConsumerStoreError::OutcomeUnavailable,
        ))
        | SessionConsumerResponse::RefreshTtl(Err(SessionConsumerStoreError::OutcomeUnavailable)) => {
            consumer_operation_is_effectful(operation)
        }
        SessionConsumerResponse::Batch(Err(SessionConsumerStoreError::OutcomeUnavailable)) => {
            consumer_operation_is_effectful(operation)
        }
        SessionConsumerResponse::Batch(Ok(results)) => {
            consumer_operation_is_effectful(operation)
                && results.iter().any(batch_result_is_outcome_unknown)
        }
        SessionConsumerResponse::AcquireLease(Err(
            SessionConsumerLeaseError::OutcomeUnavailable,
        ))
        | SessionConsumerResponse::RenewLease(Err(SessionConsumerLeaseError::OutcomeUnavailable))
        | SessionConsumerResponse::ReleaseLease(Err(
            SessionConsumerLeaseError::OutcomeUnavailable,
        )) => true,
        _ => false,
    }
}

/// Return whether a complete, semantically valid response carries a known
/// application failure. Transport success is not operation success: typed
/// store and lease errors remain failures in the fixed outcome inventory even
/// though the authenticated lane can often be reused safely.
fn response_is_known_failure(response: &SessionConsumerResponse) -> bool {
    match response {
        SessionConsumerResponse::Get(Err(_))
        | SessionConsumerResponse::PreflightRecordExpiry(Err(_))
        | SessionConsumerResponse::CompareAndSet(Err(_))
        | SessionConsumerResponse::DeleteFenced(Err(_))
        | SessionConsumerResponse::RefreshTtl(Err(_))
        | SessionConsumerResponse::ScanRestoreRecords(Err(_)) => true,
        SessionConsumerResponse::Batch(Err(_)) => true,
        SessionConsumerResponse::Batch(Ok(results)) => results.iter().any(|result| match result {
            SessionConsumerBatchResult::Get(result) => result.is_err(),
            SessionConsumerBatchResult::CompareAndSet(result) => result.is_err(),
            SessionConsumerBatchResult::DeleteFenced(result)
            | SessionConsumerBatchResult::RefreshTtl(result) => result.is_err(),
        }),
        SessionConsumerResponse::AcquireLease(Err(_))
        | SessionConsumerResponse::RenewLease(Err(_))
        | SessionConsumerResponse::ReleaseLease(Err(_)) => true,
        SessionConsumerResponse::Rejected(_) => true,
        _ => false,
    }
}

/// Decode the fixed consumer revision without accepting a shared DTO's
/// forward-compatible unknown fields. The consumer transport owns an exact
/// wire contract, while its application DTOs are intentionally shared with
/// internal/legacy code and cannot globally enable `deny_unknown_fields`.
/// `serde_ignored` reports most fields that shared DTO deserializers would
/// ignore. Internally tagged enums can hide deeper ignored fields from that
/// adapter, so the decoded revision-2 type is serialized through a streaming
/// byte comparator against the bounded received payload. This rejects aliases,
/// omissions, noncanonical encodings, and unknown nested fields without a
/// second buffer, a generic JSON tree, or surfacing their content.
async fn read_consumer_frame<R, T>(
    reader: &mut R,
    max_frame_size: usize,
) -> Result<T, ProtocolError>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de> + Serialize,
{
    let payload = read_frame_payload(reader, max_frame_size).await?;
    decode_consumer_frame_payload(&payload)
}

/// Read one authenticated consumer frame while retaining the exact revision's
/// deny-unknown decoder. `Ok(None)` is reserved for a no-byte idle expiry;
/// once any byte is consumed a stall remains a protocol timeout.
#[cfg(test)]
async fn read_authenticated_consumer_frame_within<R, T>(
    reader: &mut R,
    max_frame_size: usize,
    timeout: Duration,
) -> Result<Option<T>, ProtocolError>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de> + Serialize,
{
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or(ProtocolError::InvalidWireValue)?;
    read_authenticated_consumer_frame_until(reader, max_frame_size, deadline).await
}

async fn read_authenticated_consumer_frame_until<R, T>(
    reader: &mut R,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
) -> Result<Option<T>, ProtocolError>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de> + Serialize,
{
    let progress = ConsumerFrameReadProgress::default();
    let mut reader = ConsumerProgressReader {
        inner: reader,
        progress: &progress,
    };
    let payload = read_authenticated_frame_payload_until(&mut reader, max_frame_size, deadline)
        .await
        .map_err(|error| {
            if progress.started() && consumer_watch_transport_lost(&error) {
                // Only a zero-byte close between frames is a recoverable
                // watch disconnect. Once an authenticated frame begins, EOF
                // or reset is truncation and poisons the lane.
                ProtocolError::InvalidWireValue
            } else {
                error
            }
        })?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    decode_consumer_frame_payload(&payload).map(Some)
}

fn decode_consumer_frame_payload<T>(payload: &[u8]) -> Result<T, ProtocolError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let mut ignored = false;
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let decoded = serde_ignored::deserialize(&mut deserializer, |_| {
        ignored = true;
    })
    .map_err(ProtocolError::Serialization)?;
    deserializer.end().map_err(ProtocolError::Serialization)?;
    let mut exact = ExactConsumerJson::new(payload);
    serde_json::to_writer(&mut exact, &decoded).map_err(ProtocolError::Serialization)?;
    if ignored || !exact.matches() {
        return Err(ProtocolError::InvalidWireValue);
    }
    Ok(decoded)
}

/// Compare the exact private wire encoding without retaining a second JSON
/// buffer or materializing generic value trees. Revision 2 is emitted only by
/// this module's private DTOs, so canonical bytes are part of the negotiated
/// contract; the borrowed/owned wire-equivalence tests seal both writers.
struct ExactConsumerJson<'a> {
    expected: &'a [u8],
    offset: usize,
    mismatch: bool,
}

impl<'a> ExactConsumerJson<'a> {
    const fn new(expected: &'a [u8]) -> Self {
        Self {
            expected,
            offset: 0,
            mismatch: false,
        }
    }

    fn matches(&self) -> bool {
        !self.mismatch && self.offset == self.expected.len()
    }
}

impl io::Write for ExactConsumerJson<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(end) = self.offset.checked_add(bytes.len()) else {
            self.mismatch = true;
            return Ok(bytes.len());
        };
        if self.expected.get(self.offset..end) != Some(bytes) {
            self.mismatch = true;
        }
        self.offset = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn read_consumer_frame_until<R, T>(
    reader: &mut R,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
) -> Result<T, ProtocolError>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de> + Serialize,
{
    if tokio::time::Instant::now() >= deadline {
        return Err(consumer_setup_timeout("consumer setup deadline elapsed"));
    }
    let frame = tokio::time::timeout_at(deadline, read_consumer_frame(reader, max_frame_size))
        .await
        .map_err(|_| consumer_setup_timeout("timed out reading consumer frame from peer"))??;
    if tokio::time::Instant::now() >= deadline {
        return Err(consumer_setup_timeout("consumer setup deadline elapsed"));
    }
    Ok(frame)
}

fn consumer_setup_timeout(message: &'static str) -> ProtocolError {
    ProtocolError::Io(io::Error::new(io::ErrorKind::TimedOut, message))
}

impl fmt::Debug for ConsumerWireRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello(_) => formatter.write_str("ConsumerWireRequest::Hello"),
            Self::Call(_) => formatter.write_str("ConsumerWireRequest::Call(<redacted>)"),
        }
    }
}

impl fmt::Debug for ConsumerWireResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HelloAck(_) => formatter.write_str("ConsumerWireResponse::HelloAck"),
            Self::HelloRejected(_) => formatter.write_str("ConsumerWireResponse::HelloRejected"),
            Self::Response(_) => formatter.write_str("ConsumerWireResponse::Response(<redacted>)"),
            Self::WatchEntry(_) => {
                formatter.write_str("ConsumerWireResponse::WatchEntry(<redacted>)")
            }
        }
    }
}

fn consumer_client_tls_config(config: Arc<opc_tls::ClientConfig>) -> Arc<opc_tls::ClientConfig> {
    let mut config = config.as_ref().clone();
    config.alpn_protocols = vec![SESSION_QUORUM_CONSUMER_ALPN.to_vec()];
    config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Arc::new(config)
}

fn consumer_server_tls_config(config: Arc<opc_tls::ServerConfig>) -> Arc<opc_tls::ServerConfig> {
    let mut config = config.as_ref().clone();
    config.alpn_protocols = vec![SESSION_QUORUM_CONSUMER_ALPN.to_vec()];
    config.session_storage = Arc::new(tokio_rustls::rustls::server::NoServerSessionStorage {});
    config.ticketer = Arc::new(DisabledConsumerSessionTickets);
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    Arc::new(config)
}

#[derive(Debug)]
struct DisabledConsumerSessionTickets;

impl tokio_rustls::rustls::server::ProducesTickets for DisabledConsumerSessionTickets {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// Pool-local no-more-I/O boundary for forced shutdown.
///
/// Each synchronous `poll_*` enters a tiny critical section. Forcing the
/// barrier first rejects every later poll, then waits only for an already
/// executing poll to return before shutdown publishes completion. The guard
/// never spans `Pending`, so an unpolled caller cannot delay forced shutdown.
struct PersistentConsumerIoBarrier {
    forced: AtomicBool,
    active_polls: AtomicUsize,
    quiescent: Notify,
}

impl PersistentConsumerIoBarrier {
    fn new() -> Self {
        Self {
            forced: AtomicBool::new(false),
            active_polls: AtomicUsize::new(0),
            quiescent: Notify::new(),
        }
    }

    fn is_forced(&self) -> bool {
        self.forced.load(Ordering::Acquire)
    }

    fn enter(&self) -> Option<PersistentConsumerIoPoll<'_>> {
        if self.is_forced() {
            return None;
        }
        self.active_polls.fetch_add(1, Ordering::AcqRel);
        if self.is_forced() {
            self.leave();
            return None;
        }
        Some(PersistentConsumerIoPoll { barrier: self })
    }

    fn leave(&self) {
        if self.active_polls.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.quiescent.notify_waiters();
        }
    }

    fn force(&self) {
        self.forced.store(true, Ordering::Release);
    }

    async fn wait_quiescent(&self) {
        loop {
            let quiescent = self.quiescent.notified();
            if self.active_polls.load(Ordering::Acquire) == 0 {
                return;
            }
            quiescent.await;
        }
    }
}

struct PersistentConsumerIoPoll<'a> {
    barrier: &'a PersistentConsumerIoBarrier,
}

impl Drop for PersistentConsumerIoPoll<'_> {
    fn drop(&mut self) {
        self.barrier.leave();
    }
}

fn forced_consumer_io_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "consumer pool shutting down",
    )
}

struct PersistentConsumerShutdownReader<R> {
    inner: R,
    barrier: Arc<PersistentConsumerIoBarrier>,
}

impl<R> AsyncRead for PersistentConsumerShutdownReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(_poll) = this.barrier.enter() else {
            return std::task::Poll::Ready(Err(forced_consumer_io_error()));
        };
        std::pin::Pin::new(&mut this.inner).poll_read(context, buffer)
    }
}

struct PersistentConsumerShutdownWriter<W> {
    inner: W,
    barrier: Arc<PersistentConsumerIoBarrier>,
}

impl<W> AsyncWrite for PersistentConsumerShutdownWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Some(_poll) = this.barrier.enter() else {
            return std::task::Poll::Ready(Err(forced_consumer_io_error()));
        };
        std::pin::Pin::new(&mut this.inner).poll_write(context, bytes)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(_poll) = this.barrier.enter() else {
            return std::task::Poll::Ready(Err(forced_consumer_io_error()));
        };
        std::pin::Pin::new(&mut this.inner).poll_flush(context)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(_poll) = this.barrier.enter() else {
            return std::task::Poll::Ready(Err(forced_consumer_io_error()));
        };
        std::pin::Pin::new(&mut this.inner).poll_shutdown(context)
    }
}

struct ConsumerConnection {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    lifecycle: ConnectionLifecycle,
    rotation_edge_key: opc_tls::TlsDirectedEdgeKey,
    next_correlation: NonZeroU32,
    calls: usize,
    idle_deadline: tokio::time::Instant,
    /// Exact server-advertised request-frame ceiling for this revision-2 lane.
    request_frame_size: usize,
    shutdown_io: Option<Arc<PersistentConsumerIoBarrier>>,
    /// Weak owner used only for exact physical request-lane accounting.
    /// Watch and stateless connections deliberately leave it empty.
    pool_connection: Option<Weak<PersistentSessionConsumerPool>>,
    _physical_admission: Option<OwnedSemaphorePermit>,
}

struct ConsumerRotationReceivers<'a> {
    reauthentication: &'a mut watch::Receiver<u64>,
    material: &'a mut Option<opc_tls::TlsMaterialStatusReceiver>,
}

impl Drop for ConsumerConnection {
    fn drop(&mut self) {
        if let Some(pool) = self.pool_connection.take().and_then(|pool| pool.upgrade()) {
            pool.counters.active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[derive(Clone)]
struct StatelessConsumerPhysicalAdmission {
    requests: Arc<Semaphore>,
    watches: Arc<Semaphore>,
}

impl StatelessConsumerPhysicalAdmission {
    fn new() -> Self {
        Self {
            requests: Arc::new(Semaphore::new(
                MAX_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS,
            )),
            watches: Arc::new(Semaphore::new(
                MAX_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            )),
        }
    }

    fn try_acquire(&self, watch: bool) -> Result<OwnedSemaphorePermit, SessionConsumerClientError> {
        let permits = if watch { &self.watches } else { &self.requests };
        Arc::clone(permits)
            .try_acquire_owned()
            .map_err(|_| SessionConsumerClientError::Overloaded)
    }
}

#[derive(Clone, Copy)]
enum ConsumerSetupPhase {
    Resolve,
    Tcp,
    Tls,
    Hello,
}

fn record_setup_phase_attempt(
    counters: Option<&PersistentConsumerCounters>,
    phase: ConsumerSetupPhase,
) {
    let Some(counters) = counters else {
        return;
    };
    let counter = match phase {
        ConsumerSetupPhase::Resolve => &counters.resolve_attempts,
        ConsumerSetupPhase::Tcp => &counters.tcp_attempts,
        ConsumerSetupPhase::Tls => &counters.tls_attempts,
        ConsumerSetupPhase::Hello => &counters.hello_attempts,
    };
    counter_increment(counter);
}

fn record_setup_phase_failure(
    counters: Option<&PersistentConsumerCounters>,
    phase: ConsumerSetupPhase,
) {
    let Some(counters) = counters else {
        return;
    };
    let counter = match phase {
        ConsumerSetupPhase::Resolve => &counters.resolve_failures,
        ConsumerSetupPhase::Tcp => &counters.tcp_failures,
        ConsumerSetupPhase::Tls => &counters.tls_failures,
        ConsumerSetupPhase::Hello => &counters.hello_failures,
    };
    counter_increment(counter);
}

/// Cancellation-safe terminal accounting for one physical setup phase.
/// Every started phase becomes either completed or failed exactly once even
/// when its future is dropped by prewarm sibling failure or shutdown.
struct ConsumerSetupPhaseAttempt<'a> {
    counters: Option<&'a PersistentConsumerCounters>,
    phase: ConsumerSetupPhase,
    completed: bool,
}

struct PersistentSetupAttempt<'a> {
    counters: &'a PersistentConsumerCounters,
    completed: bool,
}

impl<'a> PersistentSetupAttempt<'a> {
    fn begin(counters: &'a PersistentConsumerCounters) -> Self {
        counter_increment(&counters.setup_attempts);
        Self {
            counters,
            completed: false,
        }
    }

    fn succeed(mut self) {
        counter_increment(&self.counters.setup_successes);
        self.completed = true;
    }
}

impl Drop for PersistentSetupAttempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            counter_increment(&self.counters.setup_failures);
        }
    }
}

impl<'a> ConsumerSetupPhaseAttempt<'a> {
    fn begin(counters: Option<&'a PersistentConsumerCounters>, phase: ConsumerSetupPhase) -> Self {
        record_setup_phase_attempt(counters, phase);
        Self {
            counters,
            phase,
            completed: false,
        }
    }

    fn complete(mut self) {
        self.completed = true;
    }
}

impl Drop for ConsumerSetupPhaseAttempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            record_setup_phase_failure(self.counters, self.phase);
        }
    }
}

impl ConsumerConnection {
    fn current(
        &mut self,
        config: &opc_tls::AuthenticatedClientConfig,
        reauthentication: &SessionReauthenticationControl,
    ) -> bool {
        consumer_connection_current(
            &mut self.lifecycle,
            config,
            reauthentication,
            self.rotation_edge_key,
        )
    }

    fn take_correlation(&mut self) -> Result<NonZeroU32, SessionConsumerClientError> {
        if self.calls >= MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION {
            return Err(SessionConsumerClientError::Unavailable);
        }
        let correlation = self.next_correlation;
        self.next_correlation = NonZeroU32::new(
            self.next_correlation
                .get()
                .checked_add(1)
                .ok_or(SessionConsumerClientError::Unavailable)?,
        )
        .ok_or(SessionConsumerClientError::Unavailable)?;
        self.calls = self.calls.saturating_add(1);
        Ok(correlation)
    }

    fn returnable_after_authenticated_work(&mut self) -> bool {
        if self.calls >= MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION {
            return false;
        }
        let now = tokio::time::Instant::now();
        self.lifecycle.retirement(now).is_none()
    }

    fn reusable(&mut self) -> bool {
        if self.calls >= MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION {
            return false;
        }
        let now = tokio::time::Instant::now();
        let lifecycle_deadline = self.lifecycle.retire_at();
        if lifecycle_deadline <= self.idle_deadline && self.lifecycle.retirement(now).is_some() {
            return false;
        }
        if now >= self.idle_deadline {
            self.lifecycle
                .record_forced_retirement(RetirementReason::IdleTimeout);
            return false;
        }
        lifecycle_deadline > self.idle_deadline || self.lifecycle.retirement(now).is_none()
    }
}

fn observe_consumer_rotation(
    lifecycle: &mut ConnectionLifecycle,
    now: tokio::time::Instant,
    generation: u64,
    material_epoch: opc_tls::TlsMaterialEpoch,
    rotation_edge_key: opc_tls::TlsDirectedEdgeKey,
) {
    lifecycle.observe_authenticated_rotation(
        now,
        generation,
        Some(material_epoch),
        rotation_edge_key,
    );
    // Explicit reauthentication and zero-jitter material cutovers begin
    // draining immediately. Recording here keeps lifecycle gauges and reason
    // counters aligned while already-admitted bounded work uses the hard
    // deadline below.
    let _ = lifecycle.retirement(now);
}

fn consumer_connection_current(
    lifecycle: &mut ConnectionLifecycle,
    config: &opc_tls::AuthenticatedClientConfig,
    reauthentication: &SessionReauthenticationControl,
    rotation_edge_key: opc_tls::TlsDirectedEdgeKey,
) -> bool {
    let now = tokio::time::Instant::now();
    let current_generation = reauthentication.generation();
    let current_material_epoch = config.material_status().epoch();
    observe_consumer_rotation(
        lifecycle,
        now,
        current_generation,
        current_material_epoch,
        rotation_edge_key,
    );
    if lifecycle.retirement(now).is_some() {
        return false;
    }
    // Explicit generation changes schedule retirement at `now`. A material
    // publication is different: this already-admitted lane remains eligible
    // only until its stable per-edge retirement deadline, avoiding a
    // synchronized reconnect burst without allowing a stale *new* handshake
    // (checked by `consumer_fresh_admission_is_current`).
    true
}

fn record_consumer_hard_overrun(lifecycle: &ConnectionLifecycle) {
    let _ = lifecycle.retirement(tokio::time::Instant::now());
    lifecycle.record_hard_overrun();
}

fn server_connection_current(
    lifecycle: &mut ConnectionLifecycle,
    config: &opc_tls::AuthenticatedServerConfig,
    reauthentication: &SessionReauthenticationControl,
    rotation_edge_key: opc_tls::TlsDirectedEdgeKey,
) -> bool {
    let now = tokio::time::Instant::now();
    let current_generation = reauthentication.generation();
    let current_material_epoch = config.material_status().epoch();
    observe_consumer_rotation(
        lifecycle,
        now,
        current_generation,
        current_material_epoch,
        rotation_edge_key,
    );
    if lifecycle.retirement(now).is_some() {
        return false;
    }
    true
}

fn consumer_fresh_admission_is_current(
    admitted_generation: u64,
    admitted_material_epoch: opc_tls::TlsMaterialEpoch,
    current_generation: u64,
    current_material_epoch: opc_tls::TlsMaterialEpoch,
) -> bool {
    admitted_generation == current_generation && admitted_material_epoch == current_material_epoch
}

fn constant_address_resolver(address: SocketAddr) -> RemoteAddrResolver {
    Arc::new(move || Box::pin(async move { Ok(address) }))
}

/// Stateless mTLS client for the typed session-quorum consumer contract.
///
/// The type holds only an endpoint, expected service identity, mTLS material,
/// and scope. It owns no local database, replica directory, snapshot, quorum
/// member identity, voter/learner state, or consensus peer.
#[derive(Clone)]
pub struct StatelessSessionConsumerClient {
    resolve: RemoteAddrResolver,
    server_name: rustls_pki_types::ServerName<'static>,
    expected_server_identity: SpiffeId,
    scope: SessionConsumerScope,
    tls_config: opc_tls::AuthenticatedClientConfig,
    idle_timeout: Duration,
    operation_timeout: Duration,
    pre_request_connection_timeout: Option<Duration>,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
    physical_admission: StatelessConsumerPhysicalAdmission,
    #[cfg(test)]
    final_admission_test_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl fmt::Debug for StatelessSessionConsumerClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatelessSessionConsumerClient")
            .field("redacted", &true)
            .field("idle_timeout", &self.idle_timeout)
            .field("operation_timeout", &self.operation_timeout)
            .field(
                "pre_request_connection_timeout",
                &self.pre_request_connection_timeout,
            )
            .finish_non_exhaustive()
    }
}

impl StatelessSessionConsumerClient {
    /// Construct a production mTLS stateless consumer client.
    pub fn new(
        address: SocketAddr,
        server_name: rustls_pki_types::ServerName<'static>,
        expected_server_identity: SpiffeId,
        scope: SessionConsumerScope,
        tls_config: opc_tls::AuthenticatedClientConfig,
    ) -> Self {
        Self::new_with_resolver(
            constant_address_resolver(address),
            server_name,
            expected_server_identity,
            scope,
            tls_config,
        )
    }

    /// Construct a production mTLS client that resolves its endpoint for
    /// every new connection.
    ///
    /// A resolver failure is reported as [`SessionConsumerClientError::Unavailable`]
    /// before the application request is written. Each normal operation opens
    /// a fresh connection, so callers may update a stable DNS or service
    /// endpoint between calls without reconstructing the client. The TLS
    /// server name and expected SPIFFE identity remain fixed by this client
    /// and are never derived from the resolved address.
    pub fn new_with_resolver(
        resolve: RemoteAddrResolver,
        server_name: rustls_pki_types::ServerName<'static>,
        expected_server_identity: SpiffeId,
        scope: SessionConsumerScope,
        tls_config: opc_tls::AuthenticatedClientConfig,
    ) -> Self {
        Self {
            resolve,
            server_name,
            expected_server_identity,
            scope,
            tls_config,
            idle_timeout: DEFAULT_CONSUMER_IDLE_TIMEOUT,
            operation_timeout: DEFAULT_CONSUMER_OPERATION_TIMEOUT,
            pre_request_connection_timeout: None,
            lifecycle_policy: ConnectionLifecyclePolicy::default(),
            reauthentication: SessionReauthenticationControl::new(),
            physical_admission: StatelessConsumerPhysicalAdmission::new(),
            #[cfg(test)]
            final_admission_test_hook: None,
        }
    }

    #[cfg(test)]
    fn with_final_admission_test_hook(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.final_admission_test_hook = Some(hook);
        self
    }

    /// Set the finite bootstrap and active-frame idle timeout.
    ///
    /// Revision 2 accepts values in `(0, 5 seconds]`. Larger values are not
    /// silently clamped: connection setup fails with a typed protocol error,
    /// so deployments must explicitly drain and correct incompatible legacy
    /// configuration during the revision-2 cutover.
    #[must_use]
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the complete operation deadline including endpoint resolution,
    /// TCP, TLS, profile bootstrap, request, and response.
    #[must_use]
    pub fn with_operation_timeout(mut self, timeout: Duration) -> Self {
        self.operation_timeout = timeout;
        self
    }

    /// Set an opt-in bound for endpoint resolution, TCP, TLS, and the
    /// value-free Hello/HelloAck exchange before an application call is sent.
    ///
    /// The budget begins with each operation and is clipped to the complete
    /// operation deadline. If it expires before an application call frame is
    /// written, the operation is reported as unavailable and is safe to try at
    /// another admitted endpoint. It does not shorten the post-call response
    /// window, which remains governed by [`Self::with_operation_timeout`] and
    /// preserves the typed unknown-outcome rule.
    #[must_use]
    pub fn with_pre_request_connection_timeout(mut self, timeout: Duration) -> Self {
        self.pre_request_connection_timeout = Some(timeout);
        self
    }

    /// Set the bounded authentication-age and drain policy for connections.
    #[must_use]
    pub fn with_connection_lifecycle(mut self, policy: ConnectionLifecyclePolicy) -> Self {
        self.lifecycle_policy = policy;
        self
    }

    /// Share an explicit reauthentication control with this client.
    #[must_use]
    pub fn with_reauthentication_control(
        mut self,
        control: SessionReauthenticationControl,
    ) -> Self {
        self.reauthentication = control;
        self
    }

    /// Return the exact quorum scope carried on every request.
    pub const fn scope(&self) -> SessionConsumerScope {
        self.scope
    }

    /// Return redaction-safe current mTLS material health.
    #[must_use]
    pub fn credential_health(&self) -> opc_tls::TlsMaterialStatus {
        self.tls_config.material_status()
    }

    /// Request explicit reauthentication before the next operation.
    pub fn request_reauthentication(&self) -> Result<u64, crate::ConnectionLifecycleError> {
        self.reauthentication.request_reauthentication()
    }

    fn pre_request_deadline(
        &self,
        started_at: tokio::time::Instant,
        operation_deadline: tokio::time::Instant,
    ) -> (tokio::time::Instant, bool) {
        match self
            .pre_request_connection_timeout
            .and_then(|timeout| started_at.checked_add(timeout))
        {
            Some(deadline) if deadline < operation_deadline => (deadline, true),
            Some(_) | None => (operation_deadline, false),
        }
    }

    async fn connect(
        &self,
        pre_request_deadline: tokio::time::Instant,
        pre_request_budget_active: bool,
        setup_counters: Option<&PersistentConsumerCounters>,
        watch: bool,
        shutdown_io: Option<Arc<PersistentConsumerIoBarrier>>,
    ) -> Result<ConsumerConnection, SessionConsumerClientError> {
        if self.idle_timeout.is_zero()
            || self.idle_timeout > DEFAULT_CONSUMER_IDLE_TIMEOUT
            || !valid_consumer_operation_timeout(self.operation_timeout)
            || self
                .lifecycle_policy
                .validate_at(tokio::time::Instant::now())
                .is_err()
        {
            return Err(SessionConsumerClientError::Protocol);
        }
        let physical_admission = self.physical_admission.try_acquire(watch)?;
        let resolve_attempt =
            ConsumerSetupPhaseAttempt::begin(setup_counters, ConsumerSetupPhase::Resolve);
        let address = tokio::time::timeout_at(pre_request_deadline, (self.resolve)())
            .await
            .map_err(|_| SessionConsumerClientError::Unavailable)?
            .map_err(|_| SessionConsumerClientError::Unavailable)?;
        resolve_attempt.complete();
        let generation = self.reauthentication.generation();
        let tcp_attempt = ConsumerSetupPhaseAttempt::begin(setup_counters, ConsumerSetupPhase::Tcp);
        let tcp = tokio::time::timeout_at(pre_request_deadline, TcpStream::connect(address))
            .await
            .map_err(|_| pre_request_timeout_error(pre_request_budget_active))?
            .map_err(|_| SessionConsumerClientError::Unavailable)?;
        tcp.set_nodelay(true)
            .map_err(|_| SessionConsumerClientError::Unavailable)?;
        tcp_attempt.complete();
        let tls_attempt = ConsumerSetupPhaseAttempt::begin(setup_counters, ConsumerSetupPhase::Tls);
        let handshake = self
            .tls_config
            .begin_handshake()
            .map_err(|_| SessionConsumerClientError::Authentication)?;
        let connector =
            tokio_rustls::TlsConnector::from(consumer_client_tls_config(handshake.rustls_config()));
        let tls = tokio::time::timeout_at(
            pre_request_deadline,
            connector.connect(self.server_name.clone(), tcp),
        )
        .await
        .map_err(|_| pre_request_timeout_error(pre_request_budget_active))?
        .map_err(|error| SessionConsumerClientError::from(classify_tls_io_error(error)))
        .map_err(|error| pre_request_error(error, pre_request_budget_active))?;
        let established_at = tokio::time::Instant::now();
        if tls.get_ref().1.alpn_protocol() != Some(SESSION_QUORUM_CONSUMER_ALPN) {
            return Err(SessionConsumerClientError::Protocol);
        }
        let peer = opc_tls::peer_tls_identity_from_client_connection(tls.get_ref().1)
            .map_err(|_| SessionConsumerClientError::Authentication)?;
        if peer.spiffe_id() != &self.expected_server_identity {
            return Err(SessionConsumerClientError::Authentication);
        }
        let rotation_edge_key =
            handshake.directed_lifecycle_edge_key(b"consumer", peer.spiffe_id());
        let (mut reader, mut writer) = tokio::io::split(tls);
        tls_attempt.complete();
        let hello_attempt =
            ConsumerSetupPhaseAttempt::begin(setup_counters, ConsumerSetupPhase::Hello);
        let hello = ConsumerWireRequest::Hello(ConsumerHello {
            transport_revision: SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
            scope: self.scope,
            response_frame_size: consumer_wire_frame_size(MAX_NEGOTIATED_FRAME_SIZE)
                .map_err(SessionConsumerClientError::from)?,
        });
        write_frame_bounded_until(
            &mut writer,
            &hello,
            MAX_NEGOTIATED_FRAME_SIZE,
            pre_request_deadline,
        )
        .await
        .map_err(SessionConsumerClientError::from)
        .map_err(|error| pre_request_error(error, pre_request_budget_active))?;
        // The authenticated Hello exchange is bounded by the caller's setup
        // deadline, not by a lane's idle lifetime.  An idle lane does not
        // exist until the completed connection is published to the pool;
        // applying the short between-call timeout here can reject a slow but
        // valid authenticated setup before prewarm has a chance to publish it.
        let ack_deadline = pre_request_deadline;
        let ack = read_authenticated_consumer_frame_until::<_, ConsumerWireResponse>(
            &mut reader,
            MAX_NEGOTIATED_FRAME_SIZE,
            ack_deadline,
        )
        .await
        .map_err(SessionConsumerClientError::from)?
        // Once an authenticated HelloAck frame has started, preserve its
        // active-frame timeout classification. Only a no-byte setup expiry
        // below is eligible for pre-request Unavailable mapping.
        .ok_or_else(|| pre_request_timeout_error(pre_request_budget_active))?;
        let request_frame_size = match ack {
            ConsumerWireResponse::HelloAck(ack)
                if ack.transport_revision == SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION
                    && ack.scope == self.scope =>
            {
                checked_consumer_frame_size(ack.request_frame_size)
                    .map_err(SessionConsumerClientError::from)?
            }
            ConsumerWireResponse::HelloRejected(SessionConsumerRejection::ScopeMismatch) => {
                return Err(SessionConsumerClientError::Scope);
            }
            ConsumerWireResponse::HelloRejected(SessionConsumerRejection::Unauthorized) => {
                return Err(SessionConsumerClientError::Authentication);
            }
            _ => {
                return Err(SessionConsumerClientError::Protocol);
            }
        };
        let admission = handshake
            .admit()
            .map_err(|_| SessionConsumerClientError::Authentication)?;
        if !consumer_fresh_admission_is_current(
            generation,
            admission.epoch(),
            self.reauthentication.generation(),
            self.tls_config.material_status().epoch(),
        ) {
            return Err(SessionConsumerClientError::Deadline);
        }
        let lifecycle = ConnectionLifecycle::new(
            self.lifecycle_policy,
            established_at,
            Some(CertificateExpiryEvidence::capture(
                handshake.leaf_expires_at(),
                handshake.certificate_chain_expires_at(),
                established_at,
            )),
            Some(CertificateExpiryEvidence::capture(
                peer.leaf_expires_at(),
                peer.certificate_chain_expires_at(),
                established_at,
            )),
            generation,
            Some(admission.epoch()),
        )
        .map_err(|_| SessionConsumerClientError::Protocol)?;
        let reader: Box<dyn AsyncRead + Unpin + Send> = match shutdown_io.as_ref() {
            Some(barrier) => Box::new(PersistentConsumerShutdownReader {
                inner: reader,
                barrier: Arc::clone(barrier),
            }),
            None => Box::new(reader),
        };
        let writer: Box<dyn AsyncWrite + Unpin + Send> = match shutdown_io.as_ref() {
            Some(barrier) => Box::new(PersistentConsumerShutdownWriter {
                inner: writer,
                barrier: Arc::clone(barrier),
            }),
            None => Box::new(writer),
        };
        let mut connection = ConsumerConnection {
            reader,
            writer,
            lifecycle,
            rotation_edge_key,
            next_correlation: NonZeroU32::MIN,
            calls: 0,
            // A fresh lane is not idle yet. `return_idle` stamps the actual
            // bounded idle deadline at successful publication; direct calls
            // stamp their active-response deadline before writing.
            idle_deadline: pre_request_deadline,
            request_frame_size,
            shutdown_io,
            pool_connection: None,
            _physical_admission: Some(physical_admission),
        };
        if !connection.current(&self.tls_config, &self.reauthentication) {
            return Err(SessionConsumerClientError::Deadline);
        }
        // This is the fresh-lane publication boundary. A material change
        // observed after this exact sample belongs to an already-admitted
        // lane and follows cooperative per-edge retirement; a stale handshake
        // is never inserted into the pool or returned to a caller.
        #[cfg(test)]
        if let Some(hook) = &self.final_admission_test_hook {
            hook();
        }
        if !consumer_fresh_admission_is_current(
            generation,
            admission.epoch(),
            self.reauthentication.generation(),
            self.tls_config.material_status().epoch(),
        ) {
            return Err(SessionConsumerClientError::Deadline);
        }
        hello_attempt.complete();
        Ok(connection)
    }

    async fn execute_on_connection(
        &self,
        connection: &mut ConsumerConnection,
        request: &SessionConsumerRequest,
        pre_request_deadline: tokio::time::Instant,
        pre_request_budget_active: bool,
        deadline: tokio::time::Instant,
        force_shutdown: Option<(watch::Receiver<PersistentShutdownPhase>, &AtomicU8)>,
    ) -> Result<SessionConsumerResponse, SessionConsumerCallError> {
        let write_progress = FrameWriteProgress::new();
        self.execute_on_connection_with_progress(
            connection,
            request,
            pre_request_deadline,
            pre_request_budget_active,
            deadline,
            force_shutdown,
            &write_progress,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_on_connection_with_progress(
        &self,
        connection: &mut ConsumerConnection,
        request: &SessionConsumerRequest,
        pre_request_deadline: tokio::time::Instant,
        pre_request_budget_active: bool,
        deadline: tokio::time::Instant,
        force_shutdown: Option<(watch::Receiver<PersistentShutdownPhase>, &AtomicU8)>,
        write_progress: &FrameWriteProgress,
    ) -> Result<SessionConsumerResponse, SessionConsumerCallError> {
        let (mut force_shutdown, force_shutdown_state) = match force_shutdown {
            Some((receiver, state)) => (Some(receiver), Some(state)),
            None => (None, None),
        };
        let shutdown_io = connection.shutdown_io.clone();
        if consumer_forced_shutdown(force_shutdown_state, shutdown_io.as_ref()) {
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::ShuttingDown,
            ));
        }
        let mut reauthentication_changes = self.reauthentication.subscribe();
        let mut material_changes = Some(self.tls_config.subscribe_material_changes());
        let rotation_edge_key = connection.rotation_edge_key;
        if !connection.current(&self.tls_config, &self.reauthentication) {
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Unavailable,
            ));
        }
        if consumer_payload_fragments_exceed_frame(request, connection.request_frame_size) {
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Protocol,
            ));
        }
        let correlation = connection
            .take_correlation()
            .map_err(SessionConsumerCallError::BeforeCallWrite)?;
        let outbound = BorrowedConsumerWireRequest::Call(BorrowedConsumerCall {
            correlation,
            request,
        });
        // The peer's next-frame idle retirement starts after its response
        // write. Stamping before our call write is conservatively earlier and
        // prevents an idle FIN race from ever being recycled as a new call.
        connection.idle_deadline = tokio::time::Instant::now()
            .checked_add(self.idle_timeout)
            .ok_or(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Protocol,
            ))?;
        let write_result = {
            let lifecycle = &mut connection.lifecycle;
            let initial_hard_deadline = lifecycle.hard_deadline().map_err(|_| {
                SessionConsumerCallError::BeforeCallWrite(SessionConsumerClientError::Protocol)
            })?;
            let write_deadline = pre_request_deadline.min(initial_hard_deadline);
            let write = write_frame_bounded_until_classified_with_progress(
                &mut connection.writer,
                &outbound,
                connection.request_frame_size,
                write_deadline,
                write_progress,
            );
            tokio::pin!(write);
            loop {
                if consumer_forced_shutdown(force_shutdown_state, shutdown_io.as_ref()) {
                    return Err(classify_interrupted_call_write(
                        write_progress,
                        SessionConsumerClientError::ShuttingDown,
                    ));
                }
                let hard_deadline = lifecycle.hard_deadline().map_err(|_| {
                    classify_interrupted_call_write(
                        write_progress,
                        SessionConsumerClientError::Protocol,
                    )
                })?;
                tokio::select! {
                    biased;
                    _ = wait_for_optional_forced_shutdown(&mut force_shutdown, force_shutdown_state) => {
                        return Err(classify_interrupted_call_write(
                            write_progress,
                            SessionConsumerClientError::ShuttingDown,
                        ));
                    }
                    result = &mut write => {
                        if consumer_forced_shutdown(force_shutdown_state, shutdown_io.as_ref()) {
                            return Err(classify_interrupted_call_write(
                                write_progress,
                                SessionConsumerClientError::ShuttingDown,
                            ));
                        }
                        if hard_deadline <= write_deadline
                            && tokio::time::Instant::now() >= hard_deadline
                        {
                            record_consumer_hard_overrun(lifecycle);
                            if result.is_ok() {
                                return Err(classify_interrupted_call_write(
                                    write_progress,
                                    SessionConsumerClientError::Deadline,
                                ));
                            }
                        }
                        break result;
                    },
                    _ = wait_for_shortened_deadline(hard_deadline, write_deadline) => {
                        record_consumer_hard_overrun(lifecycle);
                        return Err(classify_interrupted_call_write(
                            write_progress,
                            SessionConsumerClientError::Deadline,
                        ));
                    }
                    _ = reauthentication_changes.changed() => {
                        observe_consumer_rotation(
                            lifecycle,
                            tokio::time::Instant::now(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status().epoch(),
                            rotation_edge_key,
                        );
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        observe_consumer_rotation(
                            lifecycle,
                            tokio::time::Instant::now(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status().epoch(),
                            rotation_edge_key,
                        );
                    }
                }
            }
        };
        write_result
            .map_err(|error| classify_call_write_error(error, pre_request_budget_active))?;
        if consumer_forced_shutdown(force_shutdown_state, shutdown_io.as_ref()) {
            return Err(SessionConsumerCallError::MayHaveSent(
                SessionConsumerClientError::ShuttingDown,
            ));
        }
        let response = {
            let lifecycle = &mut connection.lifecycle;
            let read_deadline = deadline.min(connection.idle_deadline);
            let read = read_authenticated_consumer_frame_until::<_, ConsumerWireResponse>(
                &mut connection.reader,
                MAX_NEGOTIATED_FRAME_SIZE,
                read_deadline,
            );
            tokio::pin!(read);
            loop {
                if consumer_forced_shutdown(force_shutdown_state, shutdown_io.as_ref()) {
                    return Err(SessionConsumerCallError::MayHaveSent(
                        SessionConsumerClientError::ShuttingDown,
                    ));
                }
                let hard_deadline = lifecycle.hard_deadline().map_err(|_| {
                    SessionConsumerCallError::MayHaveSent(SessionConsumerClientError::Protocol)
                })?;
                let response_deadline = read_deadline.min(hard_deadline);
                let response = tokio::select! {
                    biased;
                    _ = wait_for_optional_forced_shutdown(&mut force_shutdown, force_shutdown_state) => {
                        return Err(SessionConsumerCallError::MayHaveSent(
                            SessionConsumerClientError::ShuttingDown,
                        ));
                    }
                    response = &mut read => {
                        if consumer_forced_shutdown(force_shutdown_state, shutdown_io.as_ref()) {
                            return Err(SessionConsumerCallError::MayHaveSent(
                                SessionConsumerClientError::ShuttingDown,
                            ));
                        }
                        if tokio::time::Instant::now() >= response_deadline {
                            if hard_deadline <= read_deadline {
                                record_consumer_hard_overrun(lifecycle);
                            }
                            return Err(SessionConsumerCallError::MayHaveSent(
                                SessionConsumerClientError::Deadline,
                            ));
                        }
                        Some(response)
                    },
                    _ = tokio::time::sleep_until(response_deadline) => {
                        if hard_deadline <= read_deadline {
                            record_consumer_hard_overrun(lifecycle);
                        }
                        return Err(SessionConsumerCallError::MayHaveSent(
                            SessionConsumerClientError::Deadline,
                        ));
                    }
                    _ = reauthentication_changes.changed() => {
                        observe_consumer_rotation(
                            lifecycle,
                            tokio::time::Instant::now(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status().epoch(),
                            rotation_edge_key,
                        );
                        None
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        observe_consumer_rotation(
                            lifecycle,
                            tokio::time::Instant::now(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status().epoch(),
                            rotation_edge_key,
                        );
                        None
                    }
                };
                if let Some(response) = response {
                    break response
                        .map_err(SessionConsumerClientError::from)
                        .map_err(SessionConsumerCallError::MayHaveSent)?
                        .ok_or(SessionConsumerCallError::MayHaveSent(
                            SessionConsumerClientError::Deadline,
                        ))?;
                }
            }
        };
        if consumer_forced_shutdown(force_shutdown_state, shutdown_io.as_ref()) {
            return Err(SessionConsumerCallError::MayHaveSent(
                SessionConsumerClientError::ShuttingDown,
            ));
        }
        match response {
            ConsumerWireResponse::Response(ConsumerCallResponse {
                correlation: received,
                response,
            }) if exact_correlation(correlation, received).is_ok()
                && response_matches_request(request, response.as_ref()) =>
            {
                Ok(*response)
            }
            _ => Err(SessionConsumerCallError::MayHaveSent(
                SessionConsumerClientError::Protocol,
            )),
        }
    }

    /// Execute one caller-owned request exactly once.
    ///
    /// This method never performs automatic replay. If a request is cancelled,
    /// disconnected, or times out after transmission, the caller retains the
    /// request ID and may make its own recovery decision using an authoritative
    /// read; mutation helpers map that condition to their explicit unknown
    /// outcome errors.
    pub async fn execute(
        &self,
        request: SessionConsumerRequest,
    ) -> Result<SessionConsumerResponse, SessionConsumerClientError> {
        self.execute_classified(request)
            .await
            .map_err(SessionConsumerCallError::into_client_error)
    }

    async fn execute_classified(
        &self,
        request: SessionConsumerRequest,
    ) -> Result<SessionConsumerResponse, SessionConsumerCallError> {
        if request.scope() != self.scope {
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Scope,
            ));
        }
        if matches!(request.operation(), SessionConsumerOperation::Watch { .. }) {
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Protocol,
            ));
        }
        let started_at = tokio::time::Instant::now();
        let deadline = started_at.checked_add(self.operation_timeout).ok_or(
            SessionConsumerCallError::BeforeCallWrite(SessionConsumerClientError::Deadline),
        )?;
        let (pre_request_deadline, pre_request_budget_active) =
            self.pre_request_deadline(started_at, deadline);
        let mut connection = self
            .connect(
                pre_request_deadline,
                pre_request_budget_active,
                None,
                false,
                None,
            )
            .await
            .map_err(SessionConsumerCallError::BeforeCallWrite)?;
        ensure_pre_request_budget_remaining(pre_request_deadline, pre_request_budget_active)
            .map_err(SessionConsumerCallError::BeforeCallWrite)?;
        self.execute_on_connection(
            &mut connection,
            &request,
            pre_request_deadline,
            pre_request_budget_active,
            deadline,
            None,
        )
        .await
    }

    fn request(
        &self,
        request_id: SessionConsumerRequestId,
        operation: SessionConsumerOperation,
    ) -> SessionConsumerRequest {
        SessionConsumerRequest::new(self.scope, request_id, operation)
    }

    /// Read current capabilities from an authoritative quorum path.
    pub async fn capabilities(&self) -> Result<BackendCapabilities, SessionConsumerClientError> {
        match self
            .execute(self.request(
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::Capabilities,
            ))
            .await?
        {
            SessionConsumerResponse::Capabilities(capabilities) => Ok(capabilities),
            SessionConsumerResponse::Rejected(rejection) => {
                Err(consumer_rejection_into_client_error(rejection))
            }
            _ => Err(SessionConsumerClientError::Protocol),
        }
    }

    /// Perform an authoritative linearizable point read.
    pub async fn get(
        &self,
        key: opc_session_store::SessionKey,
    ) -> Result<Option<opc_session_store::StoredSessionRecord>, StoreError> {
        let response = self
            .execute(self.request(
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::Get { key },
            ))
            .await;
        match response {
            Ok(SessionConsumerResponse::Get(result)) => {
                result.map_err(SessionConsumerStoreError::into_store_error)
            }
            Ok(SessionConsumerResponse::Rejected(rejection)) => {
                Err(rejection_into_store_error(rejection))
            }
            Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
                "consumer authoritative read unavailable".into(),
            )),
        }
    }

    /// Validate finite record expiry against the leader's time authority.
    pub async fn preflight_record_expiry(
        &self,
        preflights: Vec<RecordExpiryPreflight>,
    ) -> Result<(), StoreError> {
        let response = self
            .execute(self.request(
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::PreflightRecordExpiry { preflights },
            ))
            .await;
        match response {
            Ok(SessionConsumerResponse::PreflightRecordExpiry(result)) => {
                result.map_err(SessionConsumerStoreError::into_store_error)
            }
            Ok(SessionConsumerResponse::Rejected(rejection)) => {
                Err(rejection_into_store_error(rejection))
            }
            Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
                "consumer expiry authority unavailable".into(),
            )),
        }
    }

    /// Execute a fenced compare-and-set once under a caller-retained ID.
    pub async fn compare_and_set_with_id(
        &self,
        request_id: SessionConsumerRequestId,
        op: CompareAndSet,
    ) -> Result<CompareAndSetResult, SessionConsumerMutationError> {
        let response = self
            .execute_classified(self.request(
                request_id,
                SessionConsumerOperation::CompareAndSet { op: Box::new(op) },
            ))
            .await;
        mutation_response(request_id, response, |response| match response {
            SessionConsumerResponse::CompareAndSet(result) => Some(result),
            _ => None,
        })
    }

    /// Execute a fenced deletion once under a caller-retained ID.
    pub async fn delete_fenced_with_id(
        &self,
        request_id: SessionConsumerRequestId,
        lease: LeaseGuard,
    ) -> Result<(), SessionConsumerMutationError> {
        let response = self
            .execute_classified(
                self.request(request_id, SessionConsumerOperation::DeleteFenced { lease }),
            )
            .await;
        mutation_response(request_id, response, |response| match response {
            SessionConsumerResponse::DeleteFenced(result) => Some(result),
            _ => None,
        })
    }

    /// Execute a fenced TTL refresh once under a caller-retained ID.
    pub async fn refresh_ttl_with_id(
        &self,
        request_id: SessionConsumerRequestId,
        lease: LeaseGuard,
        ttl: Duration,
    ) -> Result<(), SessionConsumerMutationError> {
        let response = self
            .execute_classified(self.request(
                request_id,
                SessionConsumerOperation::RefreshTtl { lease, ttl },
            ))
            .await;
        mutation_response(request_id, response, |response| match response {
            SessionConsumerResponse::RefreshTtl(result) => Some(result),
            _ => None,
        })
    }

    /// Execute a bounded sequential application batch once under a
    /// caller-retained ID.
    pub async fn batch_with_id(
        &self,
        request_id: SessionConsumerRequestId,
        ops: Vec<SessionOp>,
    ) -> Result<Vec<SessionOpResult>, SessionConsumerMutationError> {
        let response = self
            .execute_classified(self.request(request_id, SessionConsumerOperation::Batch { ops }))
            .await;
        mutation_response(request_id, response, |response| match response {
            SessionConsumerResponse::Batch(Ok(result))
                if result.iter().any(batch_result_is_outcome_unknown) =>
            {
                Some(Err(SessionConsumerStoreError::OutcomeUnavailable))
            }
            SessionConsumerResponse::Batch(result) => Some(result),
            _ => None,
        })
        .map(|result| {
            result
                .into_iter()
                .map(session_consumer_batch_result_into_store)
                .collect()
        })
    }

    /// Return one bounded restore page from the quorum's authoritative state.
    pub async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        let response = self
            .execute(self.request(
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::ScanRestoreRecords { request },
            ))
            .await;
        match response {
            Ok(SessionConsumerResponse::ScanRestoreRecords(result)) => {
                result.map_err(SessionConsumerStoreError::into_store_error)
            }
            Ok(SessionConsumerResponse::Rejected(rejection)) => {
                Err(rejection_into_store_error(rejection))
            }
            Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
                "consumer restore unavailable".into(),
            )),
        }
    }

    /// Acquire a lease once under a caller-retained durable request ID.
    pub async fn acquire_with_id(
        &self,
        request_id: SessionConsumerRequestId,
        key: opc_session_store::SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, SessionConsumerLeaseMutationError> {
        let response = self
            .execute_classified(self.request(
                request_id,
                SessionConsumerOperation::AcquireLease { key, owner, ttl },
            ))
            .await;
        lease_response(request_id, response, |response| match response {
            SessionConsumerResponse::AcquireLease(result) => {
                Some(result.map(SessionConsumerLeaseGrant::into_guard))
            }
            _ => None,
        })
    }

    /// Renew a lease once under a caller-retained durable request ID.
    pub async fn renew_with_id(
        &self,
        request_id: SessionConsumerRequestId,
        lease: LeaseGuard,
        ttl: Duration,
    ) -> Result<LeaseGuard, SessionConsumerLeaseMutationError> {
        let response = self
            .execute_classified(self.request(
                request_id,
                SessionConsumerOperation::RenewLease { lease, ttl },
            ))
            .await;
        lease_response(request_id, response, |response| match response {
            SessionConsumerResponse::RenewLease(result) => {
                Some(result.map(SessionConsumerLeaseGrant::into_guard))
            }
            _ => None,
        })
    }

    /// Release a lease once under a caller-retained durable request ID.
    pub async fn release_with_id(
        &self,
        request_id: SessionConsumerRequestId,
        lease: LeaseGuard,
    ) -> Result<(), SessionConsumerLeaseMutationError> {
        let response = self
            .execute_classified(
                self.request(request_id, SessionConsumerOperation::ReleaseLease { lease }),
            )
            .await;
        lease_response(request_id, response, |response| match response {
            SessionConsumerResponse::ReleaseLease(result) => Some(result),
            _ => None,
        })
    }

    /// Open a bounded committed-change watch without exposing a raw log-read,
    /// append, or rebuild API.
    pub async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<BoxStream<'static, Result<SessionConsumerChange, StoreError>>, StoreError> {
        let write_progress = FrameWriteProgress::new();
        self.watch_with_counters(start_sequence, None, None, &write_progress)
            .await
            .map_err(|_| StoreError::BackendUnavailable("consumer watch unavailable".into()))
    }

    #[cfg(test)]
    async fn write_watch_call_on_connection(
        &self,
        connection: &mut ConsumerConnection,
        request: &SessionConsumerRequest,
        pre_request_deadline: tokio::time::Instant,
        pre_request_budget_active: bool,
        reauthentication_changes: &mut watch::Receiver<u64>,
        material_changes: &mut Option<opc_tls::TlsMaterialStatusReceiver>,
    ) -> Result<NonZeroU32, SessionConsumerClientError> {
        let write_progress = FrameWriteProgress::new();
        self.write_watch_call_on_connection_classified(
            connection,
            request,
            pre_request_deadline,
            pre_request_budget_active,
            ConsumerRotationReceivers {
                reauthentication: reauthentication_changes,
                material: material_changes,
            },
            &write_progress,
        )
        .await
        .map_err(SessionConsumerCallError::into_client_error)
    }

    async fn write_watch_call_on_connection_classified(
        &self,
        connection: &mut ConsumerConnection,
        request: &SessionConsumerRequest,
        pre_request_deadline: tokio::time::Instant,
        pre_request_budget_active: bool,
        rotation: ConsumerRotationReceivers<'_>,
        write_progress: &FrameWriteProgress,
    ) -> Result<NonZeroU32, SessionConsumerCallError> {
        // The receivers are constructed before this check. A rotation between
        // connect's final check and subscription is visible in the synchronous
        // epoch snapshot; a later rotation is visible to the supervised write.
        let shutdown_io = connection.shutdown_io.clone();
        if shutdown_io
            .as_ref()
            .is_some_and(|barrier| barrier.is_forced())
        {
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::ShuttingDown,
            ));
        }
        if !connection.current(&self.tls_config, &self.reauthentication) {
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Unavailable,
            ));
        }
        let rotation_edge_key = connection.rotation_edge_key;
        let correlation = connection
            .take_correlation()
            .map_err(SessionConsumerCallError::BeforeCallWrite)?;
        connection.idle_deadline = tokio::time::Instant::now()
            .checked_add(self.idle_timeout)
            .ok_or(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Protocol,
            ))?;
        let outbound = BorrowedConsumerWireRequest::Call(BorrowedConsumerCall {
            correlation,
            request,
        });
        {
            let lifecycle = &mut connection.lifecycle;
            let initial_hard_deadline = lifecycle.hard_deadline().map_err(|_| {
                SessionConsumerCallError::BeforeCallWrite(SessionConsumerClientError::Protocol)
            })?;
            let write_deadline = pre_request_deadline.min(initial_hard_deadline);
            let write = write_frame_bounded_until_classified_with_progress(
                &mut connection.writer,
                &outbound,
                connection.request_frame_size,
                write_deadline,
                write_progress,
            );
            tokio::pin!(write);
            loop {
                if shutdown_io
                    .as_ref()
                    .is_some_and(|barrier| barrier.is_forced())
                {
                    return Err(classify_interrupted_call_write(
                        write_progress,
                        SessionConsumerClientError::ShuttingDown,
                    ));
                }
                let hard_deadline = lifecycle.hard_deadline().map_err(|_| {
                    SessionConsumerCallError::BeforeCallWrite(SessionConsumerClientError::Protocol)
                })?;
                let result = tokio::select! {
                    biased;
                    result = &mut write => {
                        if shutdown_io
                            .as_ref()
                            .is_some_and(|barrier| barrier.is_forced())
                        {
                            return Err(classify_interrupted_call_write(
                                write_progress,
                                SessionConsumerClientError::ShuttingDown,
                            ));
                        }
                        if hard_deadline <= write_deadline
                            && tokio::time::Instant::now() >= hard_deadline
                        {
                            record_consumer_hard_overrun(lifecycle);
                            return Err(classify_interrupted_call_write(
                                write_progress,
                                SessionConsumerClientError::Deadline,
                            ));
                        }
                        Some(result)
                    },
                    _ = wait_for_shortened_deadline(hard_deadline, write_deadline) => {
                        record_consumer_hard_overrun(lifecycle);
                        return Err(classify_interrupted_call_write(
                            write_progress,
                            SessionConsumerClientError::Deadline,
                        ));
                    }
                    _ = rotation.reauthentication.changed() => {
                        observe_consumer_rotation(
                            lifecycle,
                            tokio::time::Instant::now(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status().epoch(),
                            rotation_edge_key,
                        );
                        None
                    }
                    _ = wait_consumer_material_change(rotation.material) => {
                        observe_consumer_rotation(
                            lifecycle,
                            tokio::time::Instant::now(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status().epoch(),
                            rotation_edge_key,
                        );
                        None
                    }
                };
                if let Some(result) = result {
                    if shutdown_io
                        .as_ref()
                        .is_some_and(|barrier| barrier.is_forced())
                    {
                        return Err(classify_interrupted_call_write(
                            write_progress,
                            SessionConsumerClientError::ShuttingDown,
                        ));
                    }
                    result.map_err(|error| {
                        classify_call_write_error(error, pre_request_budget_active)
                    })?;
                    break;
                }
            }
        }
        // A rotation notification may race a write that completes in the same
        // poll. Never publish a watch admitted on a connection that is no
        // longer current, even though Watch itself has no mutation effect.
        if shutdown_io
            .as_ref()
            .is_some_and(|barrier| barrier.is_forced())
        {
            return Err(classify_interrupted_call_write(
                write_progress,
                SessionConsumerClientError::ShuttingDown,
            ));
        }
        if !connection.current(&self.tls_config, &self.reauthentication) {
            return Err(classify_interrupted_call_write(
                write_progress,
                SessionConsumerClientError::Unavailable,
            ));
        }
        Ok(correlation)
    }

    async fn open_watch_connection_with_counters(
        &self,
        start_sequence: u64,
        setup_counters: Option<&PersistentConsumerCounters>,
        shutdown_io: Option<Arc<PersistentConsumerIoBarrier>>,
    ) -> Result<(ConsumerConnection, NonZeroU32), SessionConsumerClientError> {
        let write_progress = FrameWriteProgress::new();
        self.open_watch_connection_with_counters_classified(
            start_sequence,
            setup_counters,
            shutdown_io,
            &write_progress,
        )
        .await
        .map_err(SessionConsumerCallError::into_client_error)
    }

    async fn open_watch_connection_with_counters_classified(
        &self,
        start_sequence: u64,
        setup_counters: Option<&PersistentConsumerCounters>,
        shutdown_io: Option<Arc<PersistentConsumerIoBarrier>>,
        write_progress: &FrameWriteProgress,
    ) -> Result<(ConsumerConnection, NonZeroU32), SessionConsumerCallError> {
        let started_at = tokio::time::Instant::now();
        let deadline = started_at.checked_add(self.operation_timeout).ok_or(
            SessionConsumerCallError::BeforeCallWrite(SessionConsumerClientError::Protocol),
        )?;
        let (pre_request_deadline, pre_request_budget_active) =
            self.pre_request_deadline(started_at, deadline);
        let mut connection = self
            .connect(
                pre_request_deadline,
                pre_request_budget_active,
                setup_counters,
                true,
                shutdown_io,
            )
            .await
            .map_err(SessionConsumerCallError::BeforeCallWrite)?;
        let mut reauthentication_changes = self.reauthentication.subscribe();
        let mut material_changes = Some(self.tls_config.subscribe_material_changes());
        ensure_pre_request_budget_remaining(pre_request_deadline, pre_request_budget_active)
            .map_err(SessionConsumerCallError::BeforeCallWrite)?;
        let request = self.request(
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::Watch { start_sequence },
        );
        let correlation = self
            .write_watch_call_on_connection_classified(
                &mut connection,
                &request,
                pre_request_deadline,
                pre_request_budget_active,
                ConsumerRotationReceivers {
                    reauthentication: &mut reauthentication_changes,
                    material: &mut material_changes,
                },
                write_progress,
            )
            .await?;
        let response = {
            let watch_response_deadline = deadline.min(connection.idle_deadline);
            let response_read = read_authenticated_consumer_frame_until::<_, ConsumerWireResponse>(
                &mut connection.reader,
                MAX_NEGOTIATED_FRAME_SIZE,
                watch_response_deadline,
            );
            tokio::pin!(response_read);
            loop {
                let now = tokio::time::Instant::now();
                if now >= watch_response_deadline
                    || !consumer_connection_current(
                        &mut connection.lifecycle,
                        &self.tls_config,
                        &self.reauthentication,
                        connection.rotation_edge_key,
                    )
                {
                    let _ = connection.lifecycle.retirement(now);
                    return Err(SessionConsumerCallError::MayHaveSent(if now >= watch_response_deadline {
                        SessionConsumerClientError::Deadline
                    } else {
                        SessionConsumerClientError::Unavailable
                    }));
                }
                let response = tokio::select! {
                    biased;
                    response = &mut response_read => {
                        let now = tokio::time::Instant::now();
                        if now >= watch_response_deadline
                            || !consumer_connection_current(
                                &mut connection.lifecycle,
                                &self.tls_config,
                                &self.reauthentication,
                                connection.rotation_edge_key,
                            )
                        {
                            let _ = connection.lifecycle.retirement(now);
                            return Err(SessionConsumerCallError::MayHaveSent(if now >= watch_response_deadline {
                                SessionConsumerClientError::Deadline
                            } else {
                                SessionConsumerClientError::Unavailable
                            }));
                        }
                        Some(response)
                    },
                    _ = tokio::time::sleep_until(connection.lifecycle.retire_at()) => {
                        let _ = connection
                            .lifecycle
                            .retirement(tokio::time::Instant::now());
                        return Err(SessionConsumerCallError::MayHaveSent(
                            SessionConsumerClientError::Unavailable,
                        ));
                    }
                    _ = reauthentication_changes.changed() => {
                        if !consumer_connection_current(
                            &mut connection.lifecycle,
                            &self.tls_config,
                            &self.reauthentication,
                            connection.rotation_edge_key,
                        ) {
                            return Err(SessionConsumerCallError::MayHaveSent(
                                SessionConsumerClientError::Unavailable,
                            ));
                        }
                        None
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        if !consumer_connection_current(
                            &mut connection.lifecycle,
                            &self.tls_config,
                            &self.reauthentication,
                            connection.rotation_edge_key,
                        ) {
                            return Err(SessionConsumerCallError::MayHaveSent(
                                SessionConsumerClientError::Unavailable,
                            ));
                        }
                        None
                    }
                };
                if let Some(response) = response {
                    break response;
                }
            }
        }
        .map_err(|error| SessionConsumerCallError::MayHaveSent(error.into()))?
        .ok_or(SessionConsumerCallError::MayHaveSent(
            SessionConsumerClientError::Deadline,
        ))?;
        let response = match response {
            ConsumerWireResponse::Response(ConsumerCallResponse {
                correlation: received,
                response,
            }) if exact_correlation(correlation, received).is_ok() => *response,
            _ => {
                return Err(SessionConsumerCallError::MayHaveSent(
                    SessionConsumerClientError::Protocol,
                ))
            }
        };
        match response {
            SessionConsumerResponse::WatchOpened => Ok((connection, correlation)),
            SessionConsumerResponse::Rejected(rejection) => {
                Err(SessionConsumerCallError::MayHaveSent(
                    consumer_rejection_into_client_error(rejection),
                ))
            }
            _ => Err(SessionConsumerCallError::MayHaveSent(
                SessionConsumerClientError::Protocol,
            )),
        }
    }

    async fn watch_with_counters(
        &self,
        start_sequence: u64,
        setup_counters: Option<&PersistentConsumerCounters>,
        persistent_runtime: Option<PersistentWatchRuntime>,
        write_progress: &FrameWriteProgress,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, StoreError>>,
        SessionConsumerCallError,
    > {
        // The typed store contract is an inclusive 1-based watch cursor: the
        // empty-head sentinel zero is exactly sequence one. Normalize once at
        // the consumer boundary so both the initial Watch and every reconnect
        // retain the same checked caller-visible cursor.
        let start_sequence = normalized_consumer_watch_cursor(start_sequence);
        let shutdown_io = persistent_runtime
            .as_ref()
            .map(|runtime| Arc::clone(&runtime._lease.pool.shutdown_io));
        let (mut connection, mut correlation) = self
            .open_watch_connection_with_counters_classified(
                start_sequence,
                setup_counters,
                shutdown_io,
                write_progress,
            )
            .await?;
        let (tx, rx) = mpsc::channel(CONSUMER_WATCH_CHANNEL_CAPACITY);
        let byte_budget = Arc::new(Semaphore::new(CONSUMER_WATCH_CHANNEL_MAX_BYTES));
        let tls_config = self.tls_config.clone();
        let reauthentication = self.reauthentication.clone();
        let reconnect_client = self.clone();
        let persistent_pool = persistent_runtime
            .as_ref()
            .map(|runtime| Arc::clone(&runtime._lease.pool));
        let terminal = Arc::new(ConsumerWatchTerminalSlot::new(persistent_pool.as_ref()));
        let reader_terminal = Arc::clone(&terminal);
        let active_frame_timeout = self.idle_timeout;
        tokio::spawn(async move {
            let mut force_shutdown = persistent_runtime
                .as_ref()
                .map(|runtime| runtime.shutdown.clone());
            // The runtime owns the fixed watch permit. Keeping it in the
            // physical reader task releases capacity on peer close, rotation,
            // forced shutdown, or caller stream drop even if the caller never
            // polls its returned stream again.
            let _persistent_runtime = persistent_runtime;
            let force_shutdown_state = _persistent_runtime
                .as_ref()
                .map(|runtime| &runtime._lease.pool.shutdown_phase);
            let mut reauthentication_changes = reauthentication.subscribe();
            let mut material_changes = Some(tls_config.subscribe_material_changes());
            let mut expected_sequence = start_sequence;
            let mut recovery = PersistentWatchRecovery::default();
            'watch_reader: loop {
                macro_rules! reconnect_or_terminal {
                    () => {{
                        // A full caller-visible item queue has already lost
                        // the capacity required to make progress. Do not keep
                        // the sole persistent watch lease alive reconnecting
                        // behind an unpolled consumer.
                        if tx.capacity() == 0 {
                            reader_terminal.store(ConsumerWatchTerminal::Unavailable);
                            return;
                        }
                        let Some(pool) = persistent_pool.as_ref() else {
                            reader_terminal.store(ConsumerWatchTerminal::Unavailable);
                            return;
                        };
                        // Release the old authenticated socket before the
                        // replacement handshake: a single-slot peer can wait
                        // for this EOF before accepting a new Watch request.
                        drop(connection);
                        match reconnect_persistent_consumer_watch(
                            &reconnect_client,
                            pool,
                            expected_sequence,
                            &tx,
                            &mut recovery,
                        )
                        .await
                        {
                            Ok(Some((reconnected, reconnected_correlation))) => {
                                connection = reconnected;
                                correlation = reconnected_correlation;
                                continue 'watch_reader;
                            }
                            Ok(None) | Err(SessionConsumerClientError::ShuttingDown) => return,
                            Err(_) => {
                                reader_terminal.store(ConsumerWatchTerminal::Unavailable);
                                return;
                            }
                        }
                    }};
                }
                macro_rules! terminate_stalled_watch {
                    () => {{
                        // Once a decoded item is blocked on local byte or
                        // queue capacity, it has not crossed the delivery
                        // boundary. Reconnecting would retain the fixed watch
                        // lease behind a slow/unpolled caller, so fail closed
                        // and release it instead.
                        reader_terminal.store(ConsumerWatchTerminal::Unavailable);
                        return;
                    }};
                }
                if !connection.current(&tls_config, &reauthentication) {
                    reconnect_or_terminal!();
                }
                // A quiet, healthy watch is normal. Frame sizing still bounds
                // any received item, while reauthentication, material
                // rotation, lifecycle retirement, and stream drop can all
                // interrupt this otherwise unbounded wait.
                let response = {
                    let active_frame_deadline = tokio::time::Instant::now()
                        .checked_add(active_frame_timeout)
                        .expect("validated consumer idle timeout has an active-frame deadline");
                    let response_read =
                        read_authenticated_consumer_frame_until::<_, ConsumerWireResponse>(
                            &mut connection.reader,
                            MAX_NEGOTIATED_FRAME_SIZE,
                            active_frame_deadline,
                        );
                    tokio::pin!(response_read);
                    loop {
                        let event = tokio::select! {
                            biased;
                            _ = wait_for_optional_forced_shutdown(&mut force_shutdown, force_shutdown_state) => return,
                            _ = tx.closed() => return,
                            response = &mut response_read => match response {
                                Ok(Some(response)) => ConsumerWatchRead::Frame(Ok(response)),
                                Ok(None) => ConsumerWatchRead::Idle,
                                Err(error) => ConsumerWatchRead::Frame(Err(error)),
                            },
                            _ = tokio::time::sleep_until(connection.lifecycle.retire_at()) => {
                                let _ = connection
                                    .lifecycle
                                    .retirement(tokio::time::Instant::now());
                                ConsumerWatchRead::Reconnect
                            },
                            _ = reauthentication_changes.changed() => {
                                if !consumer_connection_current(
                                    &mut connection.lifecycle,
                                    &tls_config,
                                    &reauthentication,
                                    connection.rotation_edge_key,
                                ) {
                                    ConsumerWatchRead::Reconnect
                                } else {
                                    continue;
                                }
                            },
                            _ = wait_consumer_material_change(&mut material_changes) => {
                                if !consumer_connection_current(
                                    &mut connection.lifecycle,
                                    &tls_config,
                                    &reauthentication,
                                    connection.rotation_edge_key,
                                ) {
                                    ConsumerWatchRead::Reconnect
                                } else {
                                    continue;
                                }
                            },
                        };
                        match event {
                            ConsumerWatchRead::Frame(_) | ConsumerWatchRead::Reconnect => {
                                break event
                            }
                            ConsumerWatchRead::Idle => continue 'watch_reader,
                        }
                    }
                };
                if matches!(response, ConsumerWatchRead::Reconnect) {
                    reconnect_or_terminal!();
                }
                let ConsumerWatchRead::Frame(response) = response else {
                    unreachable!("idle reads continue the outer watch loop");
                };
                if !connection.current(&tls_config, &reauthentication) {
                    reconnect_or_terminal!();
                }
                let entry = match response {
                    Ok(ConsumerWireResponse::WatchEntry(ConsumerWatchEntry {
                        correlation: received,
                        entry,
                    })) if exact_correlation(correlation, received).is_ok() => match *entry {
                        Ok(entry) if entry.sequence() == expected_sequence => entry,
                        Ok(_) => {
                            reader_terminal.store(ConsumerWatchTerminal::Protocol);
                            return;
                        }
                        Err(error) if consumer_watch_error_is_legal(error) => {
                            // A typed watch error does not name a committed
                            // change and therefore cannot consume
                            // `expected_sequence`. Deliver it terminally: a
                            // reconnect is permitted only after a successful
                            // sequence-bearing entry crosses the queue.
                            reader_terminal.store(ConsumerWatchTerminal::Store(error));
                            return;
                        }
                        Err(_) => {
                            reader_terminal.store(ConsumerWatchTerminal::Protocol);
                            return;
                        }
                    },
                    Ok(_) => {
                        // Correlation and frame-kind violations are ambiguous:
                        // never replay a cursor after a peer could have mixed
                        // two watch lifetimes.
                        reader_terminal.store(ConsumerWatchTerminal::Protocol);
                        return;
                    }
                    Err(error) if consumer_watch_transport_lost(&error) => {
                        reconnect_or_terminal!();
                    }
                    Err(_) => {
                        reader_terminal.store(ConsumerWatchTerminal::Protocol);
                        return;
                    }
                };
                match serde_json::to_vec(&entry) {
                    Ok(encoded) if encoded.len() <= CONSUMER_WATCH_CHANNEL_MAX_BYTES => {
                        drop(encoded);
                    }
                    // Local encoding and size failures do not consume a
                    // committed sequence either. They are terminal rather
                    // than a reason to reconnect from the successor.
                    Ok(encoded) => {
                        reader_terminal.store(ConsumerWatchTerminal::PayloadTooLarge {
                            actual: encoded.len(),
                            max: CONSUMER_WATCH_CHANNEL_MAX_BYTES,
                        });
                        return;
                    }
                    Err(_) => {
                        reader_terminal.store(ConsumerWatchTerminal::Unavailable);
                        return;
                    }
                };
                let Some(byte_count) = consumer_watch_item_byte_count(&Ok(entry.clone())) else {
                    return;
                };
                let acquire_permit = Arc::clone(&byte_budget).acquire_many_owned(byte_count);
                tokio::pin!(acquire_permit);
                let permit = loop {
                    let permit = tokio::select! {
                        biased;
                        _ = wait_for_optional_forced_shutdown(&mut force_shutdown, force_shutdown_state) => return,
                        _ = tx.closed() => return,
                        permit = &mut acquire_permit => {
                            match permit {
                                Ok(permit) => Some(permit),
                                Err(_) => return,
                            }
                        }
                        _ = tokio::time::sleep_until(connection.lifecycle.retire_at()) => {
                            let _ = connection
                                .lifecycle
                                .retirement(tokio::time::Instant::now());
                            terminate_stalled_watch!();
                        },
                        _ = reauthentication_changes.changed() => {
                            if !consumer_connection_current(
                                &mut connection.lifecycle,
                                &tls_config,
                                &reauthentication,
                                connection.rotation_edge_key,
                            ) {
                                terminate_stalled_watch!();
                            }
                            None
                        },
                        _ = wait_consumer_material_change(&mut material_changes) => {
                            if !consumer_connection_current(
                                &mut connection.lifecycle,
                                &tls_config,
                                &reauthentication,
                                connection.rotation_edge_key,
                            ) {
                                terminate_stalled_watch!();
                            }
                            None
                        },
                    };
                    if let Some(permit) = permit {
                        break permit;
                    }
                };
                if !connection.current(&tls_config, &reauthentication) {
                    reconnect_or_terminal!();
                }
                if let Some(pool) = persistent_pool.as_ref() {
                    counter_increment(&pool.counters.watch_buffered);
                }
                let send = tx.send(QueuedConsumerWatchItem {
                    item: Some(Ok(entry)),
                    _byte_permit: permit,
                    watch_pool: persistent_pool.clone(),
                });
                tokio::pin!(send);
                let sent = loop {
                    let sent = tokio::select! {
                        biased;
                        _ = wait_for_optional_forced_shutdown(&mut force_shutdown, force_shutdown_state) => return,
                        result = &mut send => Some(result),
                        _ = tokio::time::sleep_until(connection.lifecycle.retire_at()) => {
                            let _ = connection
                                .lifecycle
                                .retirement(tokio::time::Instant::now());
                            terminate_stalled_watch!();
                        },
                        _ = reauthentication_changes.changed() => {
                            if !consumer_connection_current(
                                &mut connection.lifecycle,
                                &tls_config,
                                &reauthentication,
                                connection.rotation_edge_key,
                            ) {
                                terminate_stalled_watch!();
                            }
                            None
                        },
                        _ = wait_consumer_material_change(&mut material_changes) => {
                            if !consumer_connection_current(
                                &mut connection.lifecycle,
                                &tls_config,
                                &reauthentication,
                                connection.rotation_edge_key,
                            ) {
                                terminate_stalled_watch!();
                            }
                            None
                        },
                    };
                    if let Some(sent) = sent {
                        break sent;
                    }
                };
                if sent.is_err() {
                    return;
                }
                // The cursor advances only after this item has crossed the
                // bounded stream queue. A loss before then replays it; a loss
                // after then resumes at the exact checked successor.
                let Some(next_sequence) = expected_sequence.checked_add(1) else {
                    reader_terminal.store(ConsumerWatchTerminal::Protocol);
                    return;
                };
                expected_sequence = next_sequence;
                // Only caller-visible progress clears the watch-level loss
                // budget. A peer that repeatedly authenticates and returns
                // WatchOpened without one validated queued entry cannot reset
                // the bounded recovery attempts/window.
                recovery.reset();
                if !connection.current(&tls_config, &reauthentication) {
                    reconnect_or_terminal!();
                }
            }
        });
        Ok(queued_consumer_watch_stream(rx, terminal))
    }
}

impl StatelessSessionConsumer for StatelessSessionConsumerClient {}

/// Reopen a persistent watch at the caller-visible cursor.  This is kept
/// separate from the stateless client because a stateless watch deliberately
/// has no pool-owned retry budget or shutdown authority.
#[derive(Default)]
struct PersistentWatchRecovery {
    attempts: usize,
    deadline: Option<tokio::time::Instant>,
}

impl PersistentWatchRecovery {
    fn reset(&mut self) {
        self.attempts = 0;
        self.deadline = None;
    }

    fn deadline(
        &mut self,
        setup_timeout: Duration,
    ) -> Result<tokio::time::Instant, SessionConsumerClientError> {
        match self.deadline {
            Some(deadline) => Ok(deadline),
            None => {
                let deadline = tokio::time::Instant::now()
                    .checked_add(setup_timeout)
                    .ok_or(SessionConsumerClientError::Deadline)?;
                self.deadline = Some(deadline);
                Ok(deadline)
            }
        }
    }

    fn next_attempt_at(
        &mut self,
        setup_timeout: Duration,
        maximum_attempts: usize,
        delay: Duration,
    ) -> Result<(tokio::time::Instant, tokio::time::Instant), SessionConsumerClientError> {
        if self.attempts >= maximum_attempts {
            return Err(SessionConsumerClientError::Unavailable);
        }
        let deadline = self.deadline(setup_timeout)?;
        let attempt_at = tokio::time::Instant::now()
            .checked_add(delay)
            .ok_or(SessionConsumerClientError::Deadline)?;
        if attempt_at >= deadline {
            return Err(SessionConsumerClientError::Deadline);
        }
        Ok((attempt_at, deadline))
    }
}

async fn reconnect_persistent_consumer_watch(
    client: &StatelessSessionConsumerClient,
    pool: &Arc<PersistentSessionConsumerPool>,
    start_sequence: u64,
    sender: &mpsc::Sender<QueuedConsumerWatchItem>,
    recovery: &mut PersistentWatchRecovery,
) -> Result<Option<(ConsumerConnection, NonZeroU32)>, SessionConsumerClientError> {
    let mut shutdown = pool.shutdown_tx.subscribe();
    let mut last_error = SessionConsumerClientError::Unavailable;
    while recovery.attempts < pool.config.connect_attempts {
        if pool.phase() != PersistentShutdownPhase::Running {
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        let delay = pool.reconnect_delay();
        let (attempt_at, recovery_deadline) = recovery.next_attempt_at(
            pool.config.setup_timeout,
            pool.config.connect_attempts,
            delay,
        )?;
        if !delay.is_zero() {
            tokio::select! {
                biased;
                _ = sender.closed() => return Ok(None),
                _ = wait_for_forced_shutdown(&mut shutdown, &pool.shutdown_phase) => {
                    return Err(SessionConsumerClientError::ShuttingDown);
                }
                _ = tokio::time::sleep_until(attempt_at) => {}
            }
        }
        if tokio::time::Instant::now() >= recovery_deadline {
            return Err(SessionConsumerClientError::Deadline);
        }
        recovery.attempts = recovery.attempts.saturating_add(1);
        counter_increment(&pool.counters.reconnects);
        // A reconnect repeats the complete resolve/TLS/Hello/watch-open setup
        // boundary. Account it exactly like the initial setup, but do not
        // classify it as not-transmitted: this watch had already crossed its
        // original call-write boundary before the transport was lost.
        let setup_attempt = PersistentSetupAttempt::begin(&pool.counters);
        let open = client.open_watch_connection_with_counters(
            start_sequence,
            Some(&pool.counters),
            Some(Arc::clone(&pool.shutdown_io)),
        );
        tokio::pin!(open);
        let result = tokio::select! {
            biased;
            _ = sender.closed() => {
                return Ok(None);
            },
            _ = wait_for_forced_shutdown(&mut shutdown, &pool.shutdown_phase) => {
                return Err(SessionConsumerClientError::ShuttingDown);
            }
            _ = tokio::time::sleep_until(recovery_deadline) => {
                Err(SessionConsumerClientError::Deadline)
            }
            result = &mut open => result,
        };
        match result {
            Ok(connection)
                if pool.phase() == PersistentShutdownPhase::Running
                    && tokio::time::Instant::now() < recovery_deadline =>
            {
                setup_attempt.succeed();
                return Ok(Some(connection));
            }
            Ok(_) => {
                pool.record_failure(SessionConsumerClientError::ShuttingDown);
                return Err(SessionConsumerClientError::ShuttingDown);
            }
            Err(
                error @ (SessionConsumerClientError::Unavailable
                | SessionConsumerClientError::Deadline),
            ) if recovery.attempts < pool.config.connect_attempts
                && tokio::time::Instant::now() < recovery_deadline =>
            {
                pool.record_failure(error);
                last_error = error;
            }
            Err(error) => {
                pool.record_failure(error);
                return Err(error);
            }
        }
    }
    Err(last_error)
}

#[derive(Default)]
struct PersistentConsumerCounters {
    setup_attempts: AtomicU64,
    setup_failures: AtomicU64,
    setup_successes: AtomicU64,
    resolve_attempts: AtomicU64,
    resolve_failures: AtomicU64,
    tcp_attempts: AtomicU64,
    tcp_failures: AtomicU64,
    tls_attempts: AtomicU64,
    tls_failures: AtomicU64,
    hello_attempts: AtomicU64,
    hello_failures: AtomicU64,
    pool_wait_current: AtomicU64,
    pool_wait_max: AtomicU64,
    pool_wait_count: AtomicU64,
    pool_wait_max_duration_millis: AtomicU64,
    active: AtomicU64,
    max_active: AtomicU64,
    reused: AtomicU64,
    reconnects: AtomicU64,
    failures: AtomicU64,
    queued: AtomicU64,
    inflight: AtomicU64,
    max_inflight: AtomicU64,
    watch_active: AtomicU64,
    max_watch_active: AtomicU64,
    watch_buffered: AtomicU64,
    successes: AtomicU64,
    not_transmitted: AtomicU64,
    outcome_unknown: AtomicU64,
    overload: AtomicU64,
    shutdown: AtomicU64,
    authentication: AtomicU64,
    scope: AtomicU64,
    protocol: AtomicU64,
    deadline: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum PersistentShutdownPhase {
    Running = 0,
    Draining = 1,
    Forced = 2,
}

impl PersistentShutdownPhase {
    fn load(value: &AtomicU8) -> Self {
        match value.load(Ordering::Acquire) {
            0 => Self::Running,
            1 => Self::Draining,
            _ => Self::Forced,
        }
    }
}

fn advance_monotonic_shutdown_phase(
    state: &AtomicU8,
    requested: PersistentShutdownPhase,
) -> PersistentShutdownPhase {
    let requested = requested as u8;
    let mut observed = state.load(Ordering::Acquire);
    while observed < requested {
        match state.compare_exchange_weak(observed, requested, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => break,
            Err(current) => observed = current,
        }
    }
    PersistentShutdownPhase::load(state)
}

fn publish_monotonic_shutdown_phase(
    state: &AtomicU8,
    sender: &watch::Sender<PersistentShutdownPhase>,
    requested: PersistentShutdownPhase,
) -> PersistentShutdownPhase {
    advance_monotonic_shutdown_phase(state, requested);
    // `send_modify` serializes concurrent publishers under the watch
    // channel's write lock. Re-read the atomic inside that critical section
    // and only advance the visible value, so a preempted Draining publisher
    // can never overwrite a concurrently published Forced phase.
    sender.send_modify(|visible| {
        let published = PersistentShutdownPhase::load(state);
        if (*visible as u8) < published as u8 {
            *visible = published;
        }
    });
    PersistentShutdownPhase::load(state)
}

async fn wait_for_forced_shutdown(
    receiver: &mut watch::Receiver<PersistentShutdownPhase>,
    state: &AtomicU8,
) {
    loop {
        if PersistentShutdownPhase::load(state) == PersistentShutdownPhase::Forced
            || *receiver.borrow_and_update() == PersistentShutdownPhase::Forced
        {
            return;
        }
        if receiver.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

async fn wait_for_optional_forced_shutdown(
    receiver: &mut Option<watch::Receiver<PersistentShutdownPhase>>,
    state: Option<&AtomicU8>,
) {
    match (receiver, state) {
        (Some(receiver), Some(state)) => wait_for_forced_shutdown(receiver, state).await,
        (None, _) => std::future::pending::<()>().await,
        (Some(_), None) => std::future::pending::<()>().await,
    }
}

fn consumer_forced_shutdown(
    state: Option<&AtomicU8>,
    io: Option<&Arc<PersistentConsumerIoBarrier>>,
) -> bool {
    state.is_some_and(|state| {
        PersistentShutdownPhase::load(state) == PersistentShutdownPhase::Forced
    }) || io.is_some_and(|barrier| barrier.is_forced())
}

async fn wait_for_shortened_deadline(
    candidate: tokio::time::Instant,
    original: tokio::time::Instant,
) {
    if candidate < original {
        tokio::time::sleep_until(candidate).await;
    } else {
        std::future::pending::<()>().await;
    }
}

async fn wait_for_shutdown(receiver: &mut watch::Receiver<PersistentShutdownPhase>) {
    loop {
        if *receiver.borrow_and_update() != PersistentShutdownPhase::Running {
            return;
        }
        if receiver.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
struct ArmedIdleReaperDeadline<'a> {
    slot: &'a StdMutex<Option<tokio::time::Instant>>,
    deadline: tokio::time::Instant,
    armed: bool,
}

#[cfg(test)]
impl ArmedIdleReaperDeadline<'_> {
    fn arm(&mut self) {
        if self.armed {
            return;
        }
        *self
            .slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(self.deadline);
        self.armed = true;
    }
}

#[cfg(test)]
impl Drop for ArmedIdleReaperDeadline<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut slot = self
            .slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *slot == Some(self.deadline) {
            *slot = None;
        }
    }
}

async fn wait_for_optional_deadline(
    deadline: Option<tokio::time::Instant>,
    #[cfg(test)] armed_deadline: &StdMutex<Option<tokio::time::Instant>>,
) {
    match deadline {
        Some(deadline) => {
            let sleeper = tokio::time::sleep_until(deadline);
            tokio::pin!(sleeper);
            #[cfg(test)]
            {
                let mut armed = ArmedIdleReaperDeadline {
                    slot: armed_deadline,
                    deadline,
                    armed: false,
                };
                std::future::poll_fn(|context| {
                    let result = std::future::Future::poll(sleeper.as_mut(), context);
                    armed.arm();
                    result
                })
                .await
            }
            #[cfg(not(test))]
            sleeper.await
        }
        None => {
            #[cfg(test)]
            {
                *armed_deadline
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            }
            std::future::pending::<()>().await
        }
    }
}

struct PersistentPoolWait<'a> {
    counters: &'a PersistentConsumerCounters,
    wait_started: &'a StdMutex<Vec<Option<tokio::time::Instant>>>,
    slot: Option<usize>,
    started: tokio::time::Instant,
}

impl Drop for PersistentPoolWait<'_> {
    fn drop(&mut self) {
        if let Some(slot) = self.slot {
            let mut wait_started = self
                .wait_started
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            wait_started[slot] = None;
        }
        self.counters
            .pool_wait_current
            .fetch_sub(1, Ordering::Relaxed);
        self.counters.queued.fetch_sub(1, Ordering::Relaxed);
        counter_max(
            &self.counters.pool_wait_max_duration_millis,
            duration_millis(self.started.elapsed()),
        );
    }
}

fn counter_increment(counter: &AtomicU64) -> u64 {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_add(1))
        })
        .unwrap_or(u64::MAX)
        .saturating_add(1)
}

fn counter_max(counter: &AtomicU64, value: u64) {
    counter.fetch_max(value, Ordering::Relaxed);
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

struct PersistentIdleReaper {
    changed: Arc<Notify>,
    task: StdMutex<Option<tokio::task::JoinHandle<()>>>,
}

#[cfg(test)]
struct PersistentConsumerTestHooks {
    material_reaper_processed: Arc<Notify>,
    idle_reaper_armed_deadline: Arc<StdMutex<Option<tokio::time::Instant>>>,
}

#[cfg(test)]
impl PersistentConsumerTestHooks {
    fn new() -> Self {
        Self {
            material_reaper_processed: Arc::new(Notify::new()),
            idle_reaper_armed_deadline: Arc::new(StdMutex::new(None)),
        }
    }
}

impl PersistentIdleReaper {
    fn new() -> Self {
        Self {
            changed: Arc::new(Notify::new()),
            task: StdMutex::new(None),
        }
    }

    fn stop(&self) {
        if let Some(task) = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }
}

impl Drop for PersistentIdleReaper {
    fn drop(&mut self) {
        if let Some(task) = self
            .task
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }
}

struct PersistentSessionConsumerPool {
    client: StatelessSessionConsumerClient,
    config: PersistentSessionConsumerConfig,
    lanes: Arc<Semaphore>,
    pending: Arc<Semaphore>,
    watches: Arc<Semaphore>,
    prewarm: Arc<Semaphore>,
    idle: StdMutex<VecDeque<ConsumerConnection>>,
    idle_reaper: PersistentIdleReaper,
    wait_started: StdMutex<Vec<Option<tokio::time::Instant>>>,
    activity: StdMutex<PersistentActivityState>,
    shutdown_phase: AtomicU8,
    shutdown_tx: watch::Sender<PersistentShutdownPhase>,
    shutdown_io: Arc<PersistentConsumerIoBarrier>,
    shutdown_started: AtomicBool,
    shutdown_report: StdMutex<Option<PersistentSessionConsumerShutdownReport>>,
    shutdown_complete: Notify,
    reconnect_sequence: AtomicU64,
    counters: PersistentConsumerCounters,
    active_calls: AtomicUsize,
    active_watches: AtomicUsize,
    drained_notify: Notify,
    #[cfg(test)]
    test_hooks: PersistentConsumerTestHooks,
}

async fn reap_persistent_consumer_idle(
    pool: Weak<PersistentSessionConsumerPool>,
    changed: Arc<Notify>,
    mut shutdown: watch::Receiver<PersistentShutdownPhase>,
    mut reauthentication_changes: watch::Receiver<u64>,
    mut material_changes: Option<opc_tls::TlsMaterialStatusReceiver>,
    #[cfg(test)] material_reaper_processed: Arc<Notify>,
    #[cfg(test)] idle_reaper_armed_deadline: Arc<StdMutex<Option<tokio::time::Instant>>>,
) {
    #[cfg(test)]
    let mut material_notification_pending = false;
    loop {
        if *shutdown.borrow_and_update() != PersistentShutdownPhase::Running {
            return;
        }
        // Register before inspecting. A concurrent return_idle notification is
        // then either delivered to this waiter or retained as Notify's single
        // permit, so the earliest deadline is never lost.
        let idle_changed = changed.notified();
        tokio::pin!(idle_changed);
        let next_deadline = {
            let Some(pool) = pool.upgrade() else {
                return;
            };
            if pool.phase() != PersistentShutdownPhase::Running {
                return;
            }
            let mut idle = pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pool.prune_idle(&mut idle);
            #[cfg(test)]
            if std::mem::take(&mut material_notification_pending) {
                // Unlike notify_waiters, notify_one retains a permit if the
                // test's Notified future has not reached its first poll yet.
                // The acknowledgement is still exact: it is emitted only
                // after this selected material event has reached prune_idle.
                material_reaper_processed.notify_one();
            }
            idle.iter()
                .map(|connection| {
                    connection
                        .idle_deadline
                        .min(connection.lifecycle.retire_at())
                })
                .min()
        };
        tokio::select! {
            biased;
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow_and_update() != PersistentShutdownPhase::Running {
                    return;
                }
            }
            result = reauthentication_changes.changed() => {
                if result.is_err() {
                    return;
                }
            }
            _ = wait_consumer_material_change(&mut material_changes) => {
                #[cfg(test)]
                {
                    material_notification_pending = true;
                }
            }
            _ = &mut idle_changed => {}
            _ = wait_for_optional_deadline(
                next_deadline,
                #[cfg(test)]
                &idle_reaper_armed_deadline,
            ) => {}
        }
    }
}

struct PersistentActivityState {
    phase: PersistentShutdownPhase,
    calls: usize,
    watches: usize,
    prewarms: usize,
}

struct PersistentWatchLease {
    _permit: OwnedSemaphorePermit,
    pool: Arc<PersistentSessionConsumerPool>,
}

struct PersistentWatchRuntime {
    _lease: PersistentWatchLease,
    shutdown: watch::Receiver<PersistentShutdownPhase>,
}

struct PersistentCallActivity {
    pool: Arc<PersistentSessionConsumerPool>,
}

/// Cancellation-safe terminal outcome accounting for one admitted call.
/// Normal completion disarms the guard before the ordinary result path
/// records its exact cause. Dropping the caller future instead records one
/// conservative outcome from the shared positive-byte write token.
struct PersistentCallOutcome<'a> {
    pool: Arc<PersistentSessionConsumerPool>,
    write_progress: &'a FrameWriteProgress,
    effectful: bool,
    completed: bool,
}

impl<'a> PersistentCallOutcome<'a> {
    fn new(
        pool: Arc<PersistentSessionConsumerPool>,
        write_progress: &'a FrameWriteProgress,
        effectful: bool,
    ) -> Self {
        Self {
            pool,
            write_progress,
            effectful,
            completed: false,
        }
    }

    fn complete(mut self) {
        self.completed = true;
    }
}

impl Drop for PersistentCallOutcome<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.pool
            .record_failure(SessionConsumerClientError::Unavailable);
        if self.write_progress.accepted_any() && self.effectful {
            counter_increment(&self.pool.counters.outcome_unknown);
        } else if !self.write_progress.accepted_any() {
            counter_increment(&self.pool.counters.not_transmitted);
        }
    }
}

/// A physical request lane is either returned to the idle pool or counted
/// exactly once as a discarded lane, including when its caller future is
/// cancelled while a protocol operation is pending.
struct PersistentCheckedOutConnection {
    pool: Arc<PersistentSessionConsumerPool>,
    connection: Option<ConsumerConnection>,
}

impl PersistentCheckedOutConnection {
    fn new(pool: Arc<PersistentSessionConsumerPool>, connection: ConsumerConnection) -> Self {
        Self {
            pool,
            connection: Some(connection),
        }
    }

    fn connection_mut(&mut self) -> &mut ConsumerConnection {
        self.connection
            .as_mut()
            .expect("checked-out consumer connection is returned at most once")
    }

    fn return_idle(mut self) {
        if let Some(connection) = self.connection.take() {
            if let Some(connection) = self.pool.try_return_idle(connection) {
                self.connection = Some(connection);
            }
        }
    }
}

impl Drop for PersistentCheckedOutConnection {
    fn drop(&mut self) {
        if self.connection.take().is_some() {
            counter_increment(&self.pool.counters.reconnects);
        }
    }
}

struct PersistentPrewarmActivity {
    pool: Arc<PersistentSessionConsumerPool>,
}

impl Drop for PersistentCallActivity {
    fn drop(&mut self) {
        let mut activity = self
            .pool
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        activity.calls = activity.calls.saturating_sub(1);
        drop(activity);
        self.pool.active_calls.fetch_sub(1, Ordering::Relaxed);
        self.pool.counters.inflight.fetch_sub(1, Ordering::Relaxed);
        self.pool.drained_notify.notify_waiters();
    }
}

impl Drop for PersistentWatchLease {
    fn drop(&mut self) {
        let mut activity = self
            .pool
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        activity.watches = activity.watches.saturating_sub(1);
        drop(activity);
        self.pool.active_watches.fetch_sub(1, Ordering::Relaxed);
        self.pool
            .counters
            .watch_active
            .fetch_sub(1, Ordering::Relaxed);
        self.pool.drained_notify.notify_waiters();
    }
}

impl Drop for PersistentPrewarmActivity {
    fn drop(&mut self) {
        let mut activity = self
            .pool
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        activity.prewarms = activity.prewarms.saturating_sub(1);
        drop(activity);
        self.pool.drained_notify.notify_waiters();
    }
}

impl PersistentSessionConsumerPool {
    fn phase(&self) -> PersistentShutdownPhase {
        PersistentShutdownPhase::load(&self.shutdown_phase)
    }

    fn ensure_idle_reaper(self: &Arc<Self>) {
        if self.phase() != PersistentShutdownPhase::Running {
            return;
        }
        let mut task = self
            .idle_reaper
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if task.is_some() || self.phase() != PersistentShutdownPhase::Running {
            return;
        }
        let weak = Arc::downgrade(self);
        let changed = Arc::clone(&self.idle_reaper.changed);
        let shutdown = self.shutdown_tx.subscribe();
        let reauthentication_changes = self.client.reauthentication.subscribe();
        let material_changes = Some(self.client.tls_config.subscribe_material_changes());
        *task = Some(tokio::spawn(reap_persistent_consumer_idle(
            weak,
            changed,
            shutdown,
            reauthentication_changes,
            material_changes,
            #[cfg(test)]
            Arc::clone(&self.test_hooks.material_reaper_processed),
            #[cfg(test)]
            Arc::clone(&self.test_hooks.idle_reaper_armed_deadline),
        )));
    }

    fn register_call(
        self: &Arc<Self>,
    ) -> Result<PersistentCallActivity, SessionConsumerClientError> {
        let mut activity = self
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if activity.phase != PersistentShutdownPhase::Running {
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        activity.calls = activity.calls.saturating_add(1);
        drop(activity);
        self.active_calls.fetch_add(1, Ordering::Relaxed);
        let inflight = counter_increment(&self.counters.inflight);
        counter_max(&self.counters.max_inflight, inflight);
        Ok(PersistentCallActivity {
            pool: Arc::clone(self),
        })
    }

    fn register_watch(
        self: &Arc<Self>,
        permit: OwnedSemaphorePermit,
    ) -> Result<PersistentWatchLease, SessionConsumerClientError> {
        let mut activity = self
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if activity.phase != PersistentShutdownPhase::Running {
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        activity.watches = activity.watches.saturating_add(1);
        drop(activity);
        let active = self
            .active_watches
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let current = counter_increment(&self.counters.watch_active);
        counter_max(
            &self.counters.max_watch_active,
            u64::try_from(active).unwrap_or(u64::MAX).max(current),
        );
        Ok(PersistentWatchLease {
            _permit: permit,
            pool: Arc::clone(self),
        })
    }

    fn register_prewarm(
        self: &Arc<Self>,
    ) -> Result<PersistentPrewarmActivity, SessionConsumerClientError> {
        let mut activity = self
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if activity.phase != PersistentShutdownPhase::Running {
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        activity.prewarms = activity.prewarms.saturating_add(1);
        Ok(PersistentPrewarmActivity {
            pool: Arc::clone(self),
        })
    }

    fn record_failure(&self, error: SessionConsumerClientError) {
        counter_increment(&self.counters.failures);
        match error {
            SessionConsumerClientError::Authentication => {
                counter_increment(&self.counters.authentication);
            }
            SessionConsumerClientError::Scope => {
                counter_increment(&self.counters.scope);
            }
            SessionConsumerClientError::Protocol => {
                counter_increment(&self.counters.protocol);
            }
            SessionConsumerClientError::Deadline => {
                counter_increment(&self.counters.deadline);
            }
            SessionConsumerClientError::Overloaded => {
                counter_increment(&self.counters.overload);
            }
            SessionConsumerClientError::ShuttingDown => {
                counter_increment(&self.counters.shutdown);
            }
            SessionConsumerClientError::Unavailable => {}
        }
    }

    fn record_error(&self, error: SessionConsumerClientError, may_have_sent: bool) {
        self.record_failure(error);
        if may_have_sent {
            counter_increment(&self.counters.outcome_unknown);
        } else {
            counter_increment(&self.counters.not_transmitted);
        }
    }

    async fn admit_call(
        &self,
        started: tokio::time::Instant,
        operation_deadline: tokio::time::Instant,
    ) -> Result<(OwnedSemaphorePermit, OwnedSemaphorePermit), SessionConsumerClientError> {
        if self.phase() != PersistentShutdownPhase::Running {
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        // This immediate total-admission acquisition structurally bounds
        // active plus queued caller futures. Lane acquisition always joins
        // Tokio's FIFO waiter queue; `try_acquire_owned` would let a late
        // caller take a released permit ahead of an already queued caller.
        let pending = Arc::clone(&self.pending)
            .try_acquire_owned()
            .map_err(|_| SessionConsumerClientError::Overloaded)?;
        let pool_wait_deadline = started
            .checked_add(self.config.pool_wait_timeout)
            .ok_or(SessionConsumerClientError::Overloaded)?;
        let (wait_deadline, late_error) = if operation_deadline <= pool_wait_deadline {
            (operation_deadline, SessionConsumerClientError::Deadline)
        } else {
            (pool_wait_deadline, SessionConsumerClientError::Overloaded)
        };
        if tokio::time::Instant::now() >= wait_deadline {
            return Err(late_error);
        }
        let lane_wait = Arc::clone(&self.lanes).acquire_owned();
        tokio::pin!(lane_wait);
        let lane = match lane_wait.as_mut().now_or_never() {
            Some(result) => complete_before_deadline(
                result.map_err(|_| SessionConsumerClientError::ShuttingDown)?,
                wait_deadline,
                late_error,
            )?,
            None => {
                let mut shutdown = self.shutdown_tx.subscribe();
                if self.phase() != PersistentShutdownPhase::Running {
                    return Err(SessionConsumerClientError::ShuttingDown);
                }
                counter_increment(&self.counters.queued);
                let current = counter_increment(&self.counters.pool_wait_current);
                counter_max(&self.counters.pool_wait_max, current);
                counter_increment(&self.counters.pool_wait_count);
                let slot = {
                    let mut wait_started = self
                        .wait_started
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let slot = wait_started.iter().position(Option::is_none);
                    if let Some(slot) = slot {
                        wait_started[slot] = Some(started);
                    }
                    slot
                };
                let wait = PersistentPoolWait {
                    counters: &self.counters,
                    wait_started: &self.wait_started,
                    slot,
                    started,
                };
                let lane = tokio::select! {
                    biased;
                    _ = wait_for_shutdown(&mut shutdown) => {
                        Err(SessionConsumerClientError::ShuttingDown)
                    }
                    lane = tokio::time::timeout_at(wait_deadline, &mut lane_wait) => {
                        lane.ok().and_then(Result::ok)
                            .ok_or(late_error)
                    }
                };
                drop(wait);
                let lane = lane?;
                // `timeout_at` polls the semaphore first. Do not admit a permit
                // that became ready only after either fixed wait cap or the
                // original complete-operation deadline.
                complete_before_deadline(lane, wait_deadline, late_error)?
            }
        };
        if self.phase() != PersistentShutdownPhase::Running {
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        Ok((pending, lane))
    }

    fn take_idle(&self) -> Option<ConsumerConnection> {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while let Some(mut connection) = idle.pop_front() {
            if connection.reusable()
                && connection.current(&self.client.tls_config, &self.client.reauthentication)
            {
                return Some(connection);
            }
            counter_increment(&self.counters.reconnects);
        }
        None
    }

    fn try_return_idle(
        self: &Arc<Self>,
        mut connection: ConsumerConnection,
    ) -> Option<ConsumerConnection> {
        if self.phase() != PersistentShutdownPhase::Running {
            return Some(connection);
        }
        // A returned lane must still be authenticated and within its absolute
        // lifecycle. A fresh prewarmed connection has not yet established a
        // peer between-call deadline, so its first publication starts one
        // bounded idle interval. After any Call, however, the conservative
        // deadline was stamped before the request write; never widen it from
        // the later response/return instant because the peer may already be
        // counting its own (possibly shorter) idle interval.
        if !connection.returnable_after_authenticated_work()
            || !connection.current(&self.client.tls_config, &self.client.reauthentication)
        {
            return Some(connection);
        }
        if connection.calls == 0 {
            connection.idle_deadline = tokio::time::Instant::now()
                .checked_add(self.client.idle_timeout)
                .expect("validated consumer idle timeout has a bounded deadline");
        }
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.phase() != PersistentShutdownPhase::Running {
            return Some(connection);
        }
        if !connection.reusable()
            || !connection.current(&self.client.tls_config, &self.client.reauthentication)
        {
            return Some(connection);
        }
        if idle.len() < self.config.request_connections {
            idle.push_back(connection);
        } else {
            return Some(connection);
        }
        drop(idle);
        self.ensure_idle_reaper();
        self.idle_reaper.changed.notify_one();
        None
    }

    fn return_idle(self: &Arc<Self>, connection: ConsumerConnection) {
        if let Some(connection) = self.try_return_idle(connection) {
            counter_increment(&self.counters.reconnects);
            drop(connection);
        }
    }

    fn clear_idle(&self) {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let discarded = idle.len();
        idle.clear();
        for _ in 0..discarded {
            counter_increment(&self.counters.reconnects);
        }
    }

    fn prune_idle(&self, idle: &mut VecDeque<ConsumerConnection>) {
        let before = idle.len();
        idle.retain_mut(|connection| {
            connection.reusable()
                && connection.current(&self.client.tls_config, &self.client.reauthentication)
        });
        for _ in idle.len()..before {
            counter_increment(&self.counters.reconnects);
        }
    }

    fn start_shutdown(self: &Arc<Self>) {
        if self
            .shutdown_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        // Everything through task publication is synchronous. Cancelling the
        // caller can occur only at its later await, after this pool-owned
        // driver has inherited the complete bounded drain-to-force sequence.
        let deadline = tokio::time::Instant::now()
            .checked_add(self.config.shutdown_drain)
            .expect("validated shutdown drain has a bounded deadline");
        let (initial_calls, initial_watches) = {
            let mut activity = self
                .activity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let phase = advance_monotonic_shutdown_phase(
                &self.shutdown_phase,
                PersistentShutdownPhase::Draining,
            );
            activity.phase = phase;
            (activity.calls, activity.watches)
        };
        publish_monotonic_shutdown_phase(
            &self.shutdown_phase,
            &self.shutdown_tx,
            PersistentShutdownPhase::Draining,
        );
        self.pending.close();
        self.lanes.close();
        self.watches.close();
        self.prewarm.close();
        self.clear_idle();
        self.idle_reaper.stop();

        let pool = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let notified = pool.drained_notify.notified();
                let drained = {
                    let activity = pool
                        .activity
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    activity.calls == 0 && activity.watches == 0 && activity.prewarms == 0
                };
                if drained || tokio::time::Instant::now() >= deadline {
                    break;
                }
                if tokio::time::timeout_at(deadline, notified).await.is_err() {
                    break;
                }
            }

            // Stop every later transport poll before publishing Forced. An
            // already executing synchronous poll is allowed to return, but
            // shutdown completion waits for that finite critical section.
            pool.shutdown_io.force();
            let (forced_calls, forced_watches) = {
                let mut activity = pool
                    .activity
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let phase = publish_monotonic_shutdown_phase(
                    &pool.shutdown_phase,
                    &pool.shutdown_tx,
                    PersistentShutdownPhase::Forced,
                );
                activity.phase = phase;
                (activity.calls, activity.watches)
            };
            pool.shutdown_io.wait_quiescent().await;
            let report = PersistentSessionConsumerShutdownReport {
                drained_calls: u64::try_from(initial_calls.saturating_sub(forced_calls))
                    .unwrap_or(u64::MAX),
                forced_calls: u64::try_from(forced_calls).unwrap_or(u64::MAX),
                drained_watches: u64::try_from(initial_watches.saturating_sub(forced_watches))
                    .unwrap_or(u64::MAX),
                forced_watches: u64::try_from(forced_watches).unwrap_or(u64::MAX),
            };
            *pool
                .shutdown_report
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(report);
            pool.shutdown_complete.notify_waiters();
        });
    }

    async fn shutdown_report(&self) -> PersistentSessionConsumerShutdownReport {
        loop {
            let completed = self.shutdown_complete.notified();
            if let Some(report) = *self
                .shutdown_report
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
            {
                return report;
            }
            completed.await;
        }
    }

    fn reconnect_delay(&self) -> Duration {
        let maximum_millis = duration_millis(self.config.reconnect_jitter);
        let jitter = if maximum_millis == 0 {
            Duration::ZERO
        } else {
            let sequence = self
                .reconnect_sequence
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            let mixed = sequence.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17)
                ^ sequence.rotate_right(11);
            Duration::from_millis(mixed % maximum_millis.saturating_add(1))
        };
        self.client
            .lifecycle_policy
            .reconnect_backoff_min()
            .checked_add(jitter)
            .unwrap_or_else(|| self.client.lifecycle_policy.reconnect_backoff_max())
            .min(self.client.lifecycle_policy.reconnect_backoff_max())
    }

    async fn connect(
        self: &Arc<Self>,
        operation_deadline: tokio::time::Instant,
    ) -> Result<ConsumerConnection, SessionConsumerClientError> {
        let setup_started = tokio::time::Instant::now();
        let mut setup_deadline = setup_started
            .checked_add(self.config.setup_timeout)
            .map(|deadline| deadline.min(operation_deadline))
            .ok_or(SessionConsumerClientError::Deadline)?;
        if let Some(inherited_deadline) = self
            .client
            .pre_request_connection_timeout
            .and_then(|timeout| setup_started.checked_add(timeout))
        {
            setup_deadline = setup_deadline.min(inherited_deadline);
        }
        let setup_attempt = PersistentSetupAttempt::begin(&self.counters);
        let result = self
            .client
            .connect(
                setup_deadline,
                true,
                Some(&self.counters),
                false,
                Some(Arc::clone(&self.shutdown_io)),
            )
            .await;
        // Tokio polls a timed inner future before its deadline future. Reject
        // setup that completed while this task was descheduled before the
        // connection can carry an application frame.
        match result.and_then(|connection| {
            complete_before_deadline(
                connection,
                setup_deadline,
                SessionConsumerClientError::Unavailable,
            )
        }) {
            Ok(mut connection) => {
                connection.pool_connection = Some(Arc::downgrade(self));
                let active = counter_increment(&self.counters.active);
                counter_max(&self.counters.max_active, active);
                setup_attempt.succeed();
                Ok(connection)
            }
            Err(error) => Err(error),
        }
    }

    fn snapshot(&self, idle: u64) -> PersistentSessionConsumerDiagnostics {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let now = tokio::time::Instant::now();
        let pool_wait_oldest_age_millis = self
            .wait_started
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .flatten()
            .map(|started| duration_millis(now.saturating_duration_since(*started)))
            .max()
            .unwrap_or(0);
        PersistentSessionConsumerDiagnostics {
            setup_attempts: load(&self.counters.setup_attempts),
            setup_failures: load(&self.counters.setup_failures),
            setup_successes: load(&self.counters.setup_successes),
            resolve_attempts: load(&self.counters.resolve_attempts),
            resolve_failures: load(&self.counters.resolve_failures),
            tcp_attempts: load(&self.counters.tcp_attempts),
            tcp_failures: load(&self.counters.tcp_failures),
            tls_attempts: load(&self.counters.tls_attempts),
            tls_failures: load(&self.counters.tls_failures),
            hello_attempts: load(&self.counters.hello_attempts),
            hello_failures: load(&self.counters.hello_failures),
            pool_wait_current: load(&self.counters.pool_wait_current),
            pool_wait_max: load(&self.counters.pool_wait_max),
            pool_wait_count: load(&self.counters.pool_wait_count),
            pool_wait_max_duration_millis: load(&self.counters.pool_wait_max_duration_millis),
            pool_wait_oldest_age_millis,
            active: load(&self.counters.active),
            max_active: load(&self.counters.max_active),
            idle,
            reused: load(&self.counters.reused),
            reconnects: load(&self.counters.reconnects),
            failures: load(&self.counters.failures),
            queued: load(&self.counters.queued),
            inflight: load(&self.counters.inflight),
            max_inflight: load(&self.counters.max_inflight),
            watch_active: load(&self.counters.watch_active),
            max_watch_active: load(&self.counters.max_watch_active),
            watch_buffered: load(&self.counters.watch_buffered),
            successes: load(&self.counters.successes),
            not_transmitted: load(&self.counters.not_transmitted),
            outcome_unknown: load(&self.counters.outcome_unknown),
            overload: load(&self.counters.overload),
            shutdown: load(&self.counters.shutdown),
            authentication: load(&self.counters.authentication),
            scope: load(&self.counters.scope),
            protocol: load(&self.counters.protocol),
            deadline: load(&self.counters.deadline),
        }
    }
}

/// Fixed-capacity, least-authority persistent session-consumer client.
///
/// Clones share one bounded pool; they never silently serialize all work onto
/// a clone-local socket. A socket is returned to the pool only after one exact
/// correlated response completes, so cancellation after write drops it.
#[derive(Clone)]
pub struct PersistentSessionConsumerClient {
    pool: Arc<PersistentSessionConsumerPool>,
}

impl fmt::Debug for PersistentSessionConsumerClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentSessionConsumerClient")
            .field("redacted", &true)
            .field("config", &self.pool.config)
            .finish_non_exhaustive()
    }
}

impl PersistentSessionConsumerClient {
    /// Construct a default bounded pool from an already configured stateless
    /// client, retaining its TLS, resolver, timeout, and lifecycle policy.
    pub fn from_stateless(client: StatelessSessionConsumerClient) -> Self {
        Self::try_from_stateless(client, PersistentSessionConsumerConfig::default())
            .expect("default persistent consumer configuration is valid")
    }

    /// Construct a bounded pool from a configured stateless client.
    pub fn try_from_stateless(
        client: StatelessSessionConsumerClient,
        config: PersistentSessionConsumerConfig,
    ) -> Result<Self, PersistentSessionConsumerConfigError> {
        config.validate()?;
        if !valid_consumer_operation_timeout(client.operation_timeout) {
            return Err(PersistentSessionConsumerConfigError::Timing);
        }
        let (shutdown_tx, _) = watch::channel(PersistentShutdownPhase::Running);
        // A per-pool random starting point prevents independently constructed
        // clients from aligning their otherwise bounded reconnect sequences.
        // The seed is local-only and is never included in diagnostics.
        let (jitter_seed_high, jitter_seed_low) = uuid::Uuid::new_v4().as_u64_pair();
        Ok(Self {
            pool: Arc::new(PersistentSessionConsumerPool {
                client,
                config,
                lanes: Arc::new(Semaphore::new(config.request_connections)),
                // Includes active lane owners so `pending_calls == 0` is
                // fail-fast only once every request lane is occupied.
                pending: Arc::new(Semaphore::new(
                    config
                        .request_connections
                        .saturating_add(config.pending_calls),
                )),
                watches: Arc::new(Semaphore::new(config.watch_connections)),
                prewarm: Arc::new(Semaphore::new(1)),
                idle: StdMutex::new(VecDeque::with_capacity(config.request_connections)),
                idle_reaper: PersistentIdleReaper::new(),
                wait_started: StdMutex::new(vec![None; config.pending_calls]),
                activity: StdMutex::new(PersistentActivityState {
                    phase: PersistentShutdownPhase::Running,
                    calls: 0,
                    watches: 0,
                    prewarms: 0,
                }),
                shutdown_phase: AtomicU8::new(PersistentShutdownPhase::Running as u8),
                shutdown_tx,
                shutdown_io: Arc::new(PersistentConsumerIoBarrier::new()),
                shutdown_started: AtomicBool::new(false),
                shutdown_report: StdMutex::new(None),
                shutdown_complete: Notify::new(),
                reconnect_sequence: AtomicU64::new(jitter_seed_high ^ jitter_seed_low),
                counters: PersistentConsumerCounters::default(),
                active_calls: AtomicUsize::new(0),
                active_watches: AtomicUsize::new(0),
                drained_notify: Notify::new(),
                #[cfg(test)]
                test_hooks: PersistentConsumerTestHooks::new(),
            }),
        })
    }

    /// Return this pool's validated fixed configuration.
    pub fn config(&self) -> PersistentSessionConsumerConfig {
        self.pool.config
    }

    /// Return the fixed consumer scope bound to this pool.
    pub fn scope(&self) -> SessionConsumerScope {
        self.pool.client.scope()
    }

    /// Return redaction-safe current client material health.
    #[must_use]
    pub fn credential_health(&self) -> opc_tls::TlsMaterialStatus {
        self.pool.client.credential_health()
    }

    /// Request reauthentication; stale idle lanes fail the current check and
    /// are never leased again.
    pub fn request_reauthentication(&self) -> Result<u64, crate::ConnectionLifecycleError> {
        let generation = self.pool.client.request_reauthentication()?;
        let mut idle = self
            .pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.pool.prune_idle(&mut idle);
        Ok(generation)
    }

    fn request(
        &self,
        request_id: SessionConsumerRequestId,
        operation: SessionConsumerOperation,
    ) -> SessionConsumerRequest {
        SessionConsumerRequest::new(self.scope(), request_id, operation)
    }

    /// Execute one complete typed request on a fair fixed request lane while
    /// retaining its transport effect boundary. The request is borrowed so
    /// an ambiguous outcome always leaves the exact durable ID and body in
    /// caller ownership for authoritative recovery.
    pub async fn execute(
        &self,
        request: &SessionConsumerRequest,
    ) -> Result<SessionConsumerResponse, PersistentSessionConsumerExecuteError> {
        match self.execute_classified(request).await {
            Ok(response) => Ok(response),
            Err(error) => Err(persistent_execute_error_for_request(request, error)),
        }
    }

    async fn execute_read(
        &self,
        request: SessionConsumerRequest,
    ) -> Result<SessionConsumerResponse, SessionConsumerClientError> {
        self.execute_classified(&request)
            .await
            .map_err(SessionConsumerCallError::into_client_error)
    }

    async fn execute_classified(
        &self,
        request: &SessionConsumerRequest,
    ) -> Result<SessionConsumerResponse, SessionConsumerCallError> {
        let started = tokio::time::Instant::now();
        let deadline = started
            .checked_add(self.pool.client.operation_timeout)
            .ok_or(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Deadline,
            ))?;
        if request.scope() != self.pool.client.scope {
            self.pool
                .record_error(SessionConsumerClientError::Scope, false);
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Scope,
            ));
        }
        if matches!(request.operation(), SessionConsumerOperation::Watch { .. }) {
            self.pool
                .record_error(SessionConsumerClientError::Protocol, false);
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Protocol,
            ));
        }
        if request.validate().is_err() {
            self.pool
                .record_error(SessionConsumerClientError::Protocol, false);
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Protocol,
            ));
        }
        let (_pending, _lane) = self
            .pool
            .admit_call(started, deadline)
            .await
            .map_err(|error| {
                self.pool.record_error(error, false);
                SessionConsumerCallError::BeforeCallWrite(error)
            })?;
        let _activity = self.pool.register_call().map_err(|error| {
            self.pool.record_error(error, false);
            SessionConsumerCallError::BeforeCallWrite(error)
        })?;
        let write_progress = FrameWriteProgress::new();
        let outcome = PersistentCallOutcome::new(
            Arc::clone(&self.pool),
            &write_progress,
            consumer_operation_is_effectful(request.operation()),
        );
        let result = self
            .execute_admitted(request, started, deadline, &write_progress)
            .await;
        outcome.complete();
        match result {
            Ok(response) => {
                match &response {
                    SessionConsumerResponse::Rejected(rejection) => self
                        .pool
                        .record_failure(consumer_rejection_into_client_error(*rejection)),
                    _ if response_is_outcome_unknown(request.operation(), &response) => {
                        // The complete typed response proves the request left
                        // this process, but not whether its effect reached the
                        // quorum. Nested ambiguity is a failure too.
                        self.pool
                            .record_failure(SessionConsumerClientError::Unavailable);
                        counter_increment(&self.pool.counters.outcome_unknown);
                    }
                    _ if response_is_known_failure(&response) => {
                        self.pool
                            .record_failure(SessionConsumerClientError::Unavailable);
                    }
                    _ => {
                        counter_increment(&self.pool.counters.successes);
                    }
                }
                Ok(response)
            }
            Err(error) => {
                self.pool.record_error(
                    error.into_client_error(),
                    matches!(error, SessionConsumerCallError::MayHaveSent(_)),
                );
                Err(error)
            }
        }
    }

    /// Read current capabilities through a retained request lane.
    pub async fn capabilities(&self) -> Result<BackendCapabilities, SessionConsumerClientError> {
        match self
            .execute_read(self.request(
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::Capabilities,
            ))
            .await?
        {
            SessionConsumerResponse::Capabilities(value) => Ok(value),
            SessionConsumerResponse::Rejected(rejection) => {
                Err(consumer_rejection_into_client_error(rejection))
            }
            _ => Err(SessionConsumerClientError::Protocol),
        }
    }

    pub async fn get(
        &self,
        key: opc_session_store::SessionKey,
    ) -> Result<Option<opc_session_store::StoredSessionRecord>, StoreError> {
        match self
            .execute_read(self.request(
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::Get { key },
            ))
            .await
        {
            Ok(SessionConsumerResponse::Get(value)) => {
                value.map_err(SessionConsumerStoreError::into_store_error)
            }
            Ok(SessionConsumerResponse::Rejected(value)) => Err(rejection_into_store_error(value)),
            Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
                "consumer authoritative read unavailable".into(),
            )),
        }
    }

    pub async fn preflight_record_expiry(
        &self,
        preflights: Vec<RecordExpiryPreflight>,
    ) -> Result<(), StoreError> {
        match self
            .execute_read(self.request(
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::PreflightRecordExpiry { preflights },
            ))
            .await
        {
            Ok(SessionConsumerResponse::PreflightRecordExpiry(value)) => {
                value.map_err(SessionConsumerStoreError::into_store_error)
            }
            Ok(SessionConsumerResponse::Rejected(value)) => Err(rejection_into_store_error(value)),
            Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
                "consumer expiry authority unavailable".into(),
            )),
        }
    }

    pub async fn compare_and_set_with_id(
        &self,
        request_id: SessionConsumerRequestId,
        op: &CompareAndSet,
    ) -> Result<CompareAndSetResult, SessionConsumerMutationError> {
        mutation_response(
            request_id,
            self.execute_classified(&self.request(
                request_id,
                SessionConsumerOperation::CompareAndSet {
                    op: Box::new(op.clone()),
                },
            ))
            .await,
            |response| match response {
                SessionConsumerResponse::CompareAndSet(value) => Some(value),
                _ => None,
            },
        )
    }

    pub async fn delete_fenced_with_id(
        &self,
        request_id: SessionConsumerRequestId,
        lease: &LeaseGuard,
    ) -> Result<(), SessionConsumerMutationError> {
        mutation_response(
            request_id,
            self.execute_classified(&self.request(
                request_id,
                SessionConsumerOperation::DeleteFenced {
                    lease: lease.clone(),
                },
            ))
            .await,
            |response| match response {
                SessionConsumerResponse::DeleteFenced(value) => Some(value),
                _ => None,
            },
        )
    }

    pub async fn refresh_ttl_with_id(
        &self,
        request_id: SessionConsumerRequestId,
        lease: &LeaseGuard,
        ttl: Duration,
    ) -> Result<(), SessionConsumerMutationError> {
        mutation_response(
            request_id,
            self.execute_classified(&self.request(
                request_id,
                SessionConsumerOperation::RefreshTtl {
                    lease: lease.clone(),
                    ttl,
                },
            ))
            .await,
            |response| match response {
                SessionConsumerResponse::RefreshTtl(value) => Some(value),
                _ => None,
            },
        )
    }

    pub async fn batch_with_id(
        &self,
        request_id: SessionConsumerRequestId,
        ops: &[SessionOp],
    ) -> Result<Vec<SessionOpResult>, SessionConsumerMutationError> {
        mutation_response(
            request_id,
            self.execute_classified(&self.request(
                request_id,
                SessionConsumerOperation::Batch { ops: ops.to_vec() },
            ))
            .await,
            |response| match response {
                SessionConsumerResponse::Batch(Ok(value))
                    if value.iter().any(batch_result_is_outcome_unknown) =>
                {
                    Some(Err(SessionConsumerStoreError::OutcomeUnavailable))
                }
                SessionConsumerResponse::Batch(value) => Some(value),
                _ => None,
            },
        )
        .map(|value| {
            value
                .into_iter()
                .map(session_consumer_batch_result_into_store)
                .collect()
        })
    }

    pub async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        match self
            .execute_read(self.request(
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::ScanRestoreRecords { request },
            ))
            .await
        {
            Ok(SessionConsumerResponse::ScanRestoreRecords(value)) => {
                value.map_err(SessionConsumerStoreError::into_store_error)
            }
            Ok(SessionConsumerResponse::Rejected(value)) => Err(rejection_into_store_error(value)),
            Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
                "consumer restore unavailable".into(),
            )),
        }
    }

    pub async fn acquire_with_id(
        &self,
        request_id: SessionConsumerRequestId,
        key: &opc_session_store::SessionKey,
        owner: &OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, SessionConsumerLeaseMutationError> {
        lease_response(
            request_id,
            self.execute_classified(&self.request(
                request_id,
                SessionConsumerOperation::AcquireLease {
                    key: key.clone(),
                    owner: owner.clone(),
                    ttl,
                },
            ))
            .await,
            |response| match response {
                SessionConsumerResponse::AcquireLease(value) => {
                    Some(value.map(SessionConsumerLeaseGrant::into_guard))
                }
                _ => None,
            },
        )
    }

    pub async fn renew_with_id(
        &self,
        request_id: SessionConsumerRequestId,
        lease: &LeaseGuard,
        ttl: Duration,
    ) -> Result<LeaseGuard, SessionConsumerLeaseMutationError> {
        lease_response(
            request_id,
            self.execute_classified(&self.request(
                request_id,
                SessionConsumerOperation::RenewLease {
                    lease: lease.clone(),
                    ttl,
                },
            ))
            .await,
            |response| match response {
                SessionConsumerResponse::RenewLease(value) => {
                    Some(value.map(SessionConsumerLeaseGrant::into_guard))
                }
                _ => None,
            },
        )
    }

    pub async fn release_with_id(
        &self,
        request_id: SessionConsumerRequestId,
        lease: &LeaseGuard,
    ) -> Result<(), SessionConsumerLeaseMutationError> {
        lease_response(
            request_id,
            self.execute_classified(&self.request(
                request_id,
                SessionConsumerOperation::ReleaseLease {
                    lease: lease.clone(),
                },
            ))
            .await,
            |response| match response {
                SessionConsumerResponse::ReleaseLease(value) => Some(value),
                _ => None,
            },
        )
    }

    /// Open a watch using slots isolated from normal request lanes.
    ///
    /// Exhaustion of either this pool's watch slots or the shared physical
    /// admission for its stateless clone lineage is reported as
    /// [`SessionConsumerClientError::Overloaded`].
    pub async fn open_watch(
        &self,
        start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, StoreError>>,
        SessionConsumerClientError,
    > {
        if self.pool.phase() != PersistentShutdownPhase::Running {
            self.pool
                .record_error(SessionConsumerClientError::ShuttingDown, false);
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        let permit = Arc::clone(&self.pool.watches)
            .try_acquire_owned()
            .map_err(|_| {
                self.pool
                    .record_error(SessionConsumerClientError::Overloaded, false);
                SessionConsumerClientError::Overloaded
            })?;
        let lease = self.pool.register_watch(permit).inspect_err(|&error| {
            self.pool.record_error(error, false);
        })?;
        let mut shutdown = self.pool.shutdown_tx.subscribe();
        let mut watch_client = self.pool.client.clone();
        watch_client.pre_request_connection_timeout = Some(
            watch_client
                .pre_request_connection_timeout
                .map_or(self.pool.config.setup_timeout, |timeout| {
                    timeout.min(self.pool.config.setup_timeout)
                }),
        );
        let setup_attempt = PersistentSetupAttempt::begin(&self.pool.counters);
        let runtime = PersistentWatchRuntime {
            _lease: lease,
            shutdown: shutdown.clone(),
        };
        let write_progress = FrameWriteProgress::new();
        let outcome = PersistentCallOutcome::new(Arc::clone(&self.pool), &write_progress, false);
        let upstream = tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => {
                Err(SessionConsumerCallError::BeforeCallWrite(
                    SessionConsumerClientError::ShuttingDown,
                ))
            }
            upstream = watch_client.watch_with_counters(
                start_sequence,
                Some(&self.pool.counters),
                Some(runtime),
                &write_progress,
            ) => upstream,
        };
        outcome.complete();
        let upstream = upstream.map_err(|error| {
            match error {
                SessionConsumerCallError::BeforeCallWrite(error) => {
                    self.pool.record_error(error, false);
                    error
                }
                // Watch setup has no store mutation to recover, but a
                // completed call write proves it was not a local
                // not-transmitted failure. Retain its typed diagnostics only.
                SessionConsumerCallError::MayHaveSent(error) => {
                    self.pool.record_failure(error);
                    error
                }
            }
        })?;
        setup_attempt.succeed();
        if self.pool.phase() != PersistentShutdownPhase::Running {
            self.pool
                .record_error(SessionConsumerClientError::ShuttingDown, false);
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        Ok(stream::unfold(
            (upstream, shutdown),
            |(mut upstream, mut shutdown)| async move {
                tokio::select! {
                    _ = wait_for_shutdown(&mut shutdown) => None,
                    item = upstream.next() => item.map(|item| (item, (upstream, shutdown))),
                }
            },
        )
        .boxed())
    }

    pub async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<BoxStream<'static, Result<SessionConsumerChange, StoreError>>, StoreError> {
        self.open_watch(start_sequence)
            .await
            .map_err(|_| StoreError::BackendUnavailable("consumer watch unavailable".into()))
    }

    async fn execute_admitted(
        &self,
        request: &SessionConsumerRequest,
        started: tokio::time::Instant,
        deadline: tokio::time::Instant,
        write_progress: &FrameWriteProgress,
    ) -> Result<SessionConsumerResponse, SessionConsumerCallError> {
        let (pre_request_deadline, pre_request_budget_active) =
            self.pool.client.pre_request_deadline(started, deadline);
        let mut shutdown = self.pool.shutdown_tx.subscribe();
        let mut attempt = 0_usize;
        loop {
            if self.pool.phase() == PersistentShutdownPhase::Forced {
                return Err(SessionConsumerCallError::BeforeCallWrite(
                    SessionConsumerClientError::ShuttingDown,
                ));
            }
            attempt = attempt.saturating_add(1);
            let connection = match self.pool.take_idle() {
                Some(connection) => {
                    counter_increment(&self.pool.counters.reused);
                    Ok(connection)
                }
                None => tokio::select! {
                    biased;
                    _ = wait_for_forced_shutdown(&mut shutdown, &self.pool.shutdown_phase) => {
                        Err(SessionConsumerClientError::ShuttingDown)
                    }
                    result = self.pool.connect(pre_request_deadline) => result,
                },
            };
            let connection = match connection {
                Ok(connection) => connection,
                Err(error)
                    if attempt < self.pool.config.connect_attempts
                        && matches!(
                            error,
                            SessionConsumerClientError::Unavailable
                                | SessionConsumerClientError::Deadline
                        ) =>
                {
                    counter_increment(&self.pool.counters.reconnects);
                    let delay = self.pool.reconnect_delay();
                    if !delay.is_zero() && tokio::time::Instant::now() < deadline {
                        tokio::select! {
                            biased;
                            _ = wait_for_forced_shutdown(&mut shutdown, &self.pool.shutdown_phase) => {
                                return Err(SessionConsumerCallError::BeforeCallWrite(
                                    SessionConsumerClientError::ShuttingDown,
                                ));
                            }
                            _ = tokio::time::sleep_until(
                                (tokio::time::Instant::now() + delay).min(deadline),
                            ) => {}
                        }
                    }
                    continue;
                }
                Err(error) => return Err(SessionConsumerCallError::BeforeCallWrite(error)),
            };
            let mut connection =
                PersistentCheckedOutConnection::new(Arc::clone(&self.pool), connection);
            ensure_pre_request_budget_remaining(pre_request_deadline, pre_request_budget_active)
                .map_err(SessionConsumerCallError::BeforeCallWrite)?;
            let result = self
                .pool
                .client
                .execute_on_connection_with_progress(
                    connection.connection_mut(),
                    request,
                    pre_request_deadline,
                    pre_request_budget_active,
                    deadline,
                    Some((shutdown.clone(), &self.pool.shutdown_phase)),
                    write_progress,
                )
                .await;
            match result {
                Ok(response) => {
                    if !response_retires_connection_authority(&response) {
                        connection.return_idle();
                    }
                    return Ok(response);
                }
                Err(SessionConsumerCallError::BeforeCallWrite(error))
                    if attempt < self.pool.config.connect_attempts
                        && matches!(
                            error,
                            SessionConsumerClientError::Unavailable
                                | SessionConsumerClientError::Deadline
                        ) =>
                {
                    drop(connection);
                    let delay = self.pool.reconnect_delay();
                    if !delay.is_zero() && tokio::time::Instant::now() < deadline {
                        tokio::select! {
                            biased;
                            _ = wait_for_forced_shutdown(&mut shutdown, &self.pool.shutdown_phase) => {
                                return Err(SessionConsumerCallError::BeforeCallWrite(
                                    SessionConsumerClientError::ShuttingDown,
                                ));
                            }
                            _ = tokio::time::sleep_until(
                                (tokio::time::Instant::now() + delay).min(deadline),
                            ) => {}
                        }
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Concurrently establish all configured request lanes without dispatching
    /// an application operation. Only one prewarm may run at a time.
    pub async fn prewarm(
        &self,
    ) -> Result<PersistentSessionConsumerReadiness, SessionConsumerClientError> {
        if self.pool.phase() != PersistentShutdownPhase::Running {
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        let _gate = Arc::clone(&self.pool.prewarm)
            .try_acquire_owned()
            .map_err(|_| SessionConsumerClientError::Overloaded)?;
        let _activity = self.pool.register_prewarm()?;
        let mut shutdown = self.pool.shutdown_tx.subscribe();
        let reservation_deadline = tokio::time::Instant::now()
            .checked_add(self.pool.config.pool_wait_timeout)
            .ok_or(SessionConsumerClientError::Overloaded)?;
        // Reserve the active-width share of total admission before taking all
        // lanes. Calls already admitted can finish; after this completes, at
        // most the configured additional pending callers can wait behind this
        // administrative operation.
        let admission_permits = futures_util::future::try_join_all(
            (0..self.pool.config.request_connections).map(|_| async {
                match tokio::time::timeout_at(
                    reservation_deadline,
                    Arc::clone(&self.pool.pending).acquire_owned(),
                )
                .await
                {
                    Ok(Ok(permit)) => complete_before_deadline(
                        permit,
                        reservation_deadline,
                        SessionConsumerClientError::Overloaded,
                    ),
                    Ok(Err(_)) if self.pool.phase() != PersistentShutdownPhase::Running => {
                        Err(SessionConsumerClientError::ShuttingDown)
                    }
                    Ok(Err(_)) | Err(_) => Err(SessionConsumerClientError::Overloaded),
                }
            }),
        )
        .await?;
        // Reserve every fixed lane before replacing idles; prewarm can never
        // transiently exceed the configured physical connection width.
        let lane_permits = futures_util::future::try_join_all(
            (0..self.pool.config.request_connections).map(|_| async {
                match tokio::time::timeout_at(
                    reservation_deadline,
                    Arc::clone(&self.pool.lanes).acquire_owned(),
                )
                .await
                {
                    Ok(Ok(permit)) => complete_before_deadline(
                        permit,
                        reservation_deadline,
                        SessionConsumerClientError::Overloaded,
                    ),
                    Ok(Err(_)) if self.pool.phase() != PersistentShutdownPhase::Running => {
                        Err(SessionConsumerClientError::ShuttingDown)
                    }
                    Ok(Err(_)) | Err(_) => Err(SessionConsumerClientError::Overloaded),
                }
            }),
        )
        .await?;
        let retained = {
            let mut idle = self
                .pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.pool.prune_idle(&mut idle);
            idle.len()
        };
        let deficit = self
            .pool
            .config
            .request_connections
            .saturating_sub(retained);
        let deadline = tokio::time::Instant::now()
            .checked_add(self.pool.config.setup_timeout)
            .ok_or(SessionConsumerClientError::Deadline)?;
        let established = tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => {
                return Err(SessionConsumerClientError::ShuttingDown);
            }
            established = futures_util::future::try_join_all(
                (0..deficit).map(|_| self.pool.connect(deadline)),
            ) => established?,
        };
        for connection in established {
            self.pool.return_idle(connection);
        }
        drop(lane_permits);
        drop(admission_permits);
        if self.pool.phase() != PersistentShutdownPhase::Running {
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        Ok(self.readiness().await)
    }

    /// Return a conservative authenticated-idle-capacity snapshot.
    pub async fn readiness(&self) -> PersistentSessionConsumerReadiness {
        let lane_count = u32::try_from(self.pool.config.request_connections)
            .expect("validated persistent request width fits u32");
        // Holding every request-lane permit closes the checkout/return race:
        // readiness is true only for fixed authenticated capacity that is
        // idle for the complete snapshot, never for a merely leased lane.
        let all_lanes_idle = Arc::clone(&self.pool.lanes)
            .try_acquire_many_owned(lane_count)
            .ok();
        let mut idle = self
            .pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.pool.prune_idle(&mut idle);
        let ready_request_connections = idle.len();
        PersistentSessionConsumerReadiness {
            ready: self.pool.phase() == PersistentShutdownPhase::Running
                && all_lanes_idle.is_some()
                && ready_request_connections == self.pool.config.request_connections,
            configured_request_connections: self.pool.config.request_connections,
            ready_request_connections,
        }
    }

    /// Return a nonidentifying fixed numeric diagnostics snapshot.
    pub async fn diagnostics(&self) -> PersistentSessionConsumerDiagnostics {
        let mut idle_connections = self
            .pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.pool.prune_idle(&mut idle_connections);
        let idle = u64::try_from(idle_connections.len()).unwrap_or(u64::MAX);
        self.pool.snapshot(idle)
    }

    /// Stop admission, bound the drain, and force idle transport closure.
    pub async fn shutdown(&self) -> PersistentSessionConsumerShutdownReport {
        self.pool.start_shutdown();
        self.pool.shutdown_report().await
    }
}

impl StatelessSessionConsumer for PersistentSessionConsumerClient {}

fn rejection_into_store_error(rejection: SessionConsumerRejection) -> StoreError {
    match rejection {
        SessionConsumerRejection::ScopeMismatch | SessionConsumerRejection::Unauthorized => {
            StoreError::BackendUnavailable("consumer authorization rejected".into())
        }
        SessionConsumerRejection::MalformedRequest => {
            StoreError::InvalidKey("consumer request rejected".into())
        }
        SessionConsumerRejection::Unavailable => {
            StoreError::BackendUnavailable("consumer quorum unavailable".into())
        }
    }
}

/// A complete typed rejection is proof that the server did not dispatch the
/// lease mutation.  Preserve that known-safe boundary instead of turning a
/// peer-declared rejection into an ambiguous lease loss.
fn rejection_into_lease_error(rejection: SessionConsumerRejection) -> LeaseError {
    match rejection {
        SessionConsumerRejection::ScopeMismatch | SessionConsumerRejection::Unauthorized => {
            // The caller's current authority is no longer usable.
            LeaseError::StaleFence
        }
        SessionConsumerRejection::MalformedRequest => {
            LeaseError::Backend("consumer request rejected".into())
        }
        SessionConsumerRejection::Unavailable => {
            LeaseError::Backend("consumer quorum unavailable".into())
        }
    }
}

fn mutation_response<T>(
    request_id: SessionConsumerRequestId,
    response: Result<SessionConsumerResponse, SessionConsumerCallError>,
    expected: impl FnOnce(SessionConsumerResponse) -> Option<Result<T, SessionConsumerStoreError>>,
) -> Result<T, SessionConsumerMutationError> {
    match response {
        Ok(SessionConsumerResponse::Rejected(rejection)) => Err(
            SessionConsumerMutationError::Store(rejection_into_store_error(rejection)),
        ),
        Ok(response) => match expected(response) {
            Some(Ok(result)) => Ok(result),
            Some(Err(SessionConsumerStoreError::OutcomeUnavailable)) => {
                Err(SessionConsumerMutationError::OutcomeUnknown { request_id })
            }
            Some(Err(error)) => Err(SessionConsumerMutationError::Store(
                error.into_store_error(),
            )),
            None => Err(SessionConsumerMutationError::OutcomeUnknown { request_id }),
        },
        Err(SessionConsumerCallError::BeforeCallWrite(cause)) => {
            Err(SessionConsumerMutationError::NotTransmitted { cause })
        }
        Err(SessionConsumerCallError::MayHaveSent(_)) => {
            Err(SessionConsumerMutationError::OutcomeUnknown { request_id })
        }
    }
}

fn lease_response<T>(
    request_id: SessionConsumerRequestId,
    response: Result<SessionConsumerResponse, SessionConsumerCallError>,
    expected: impl FnOnce(
        SessionConsumerResponse,
    ) -> Option<Result<T, opc_session_store::SessionConsumerLeaseError>>,
) -> Result<T, SessionConsumerLeaseMutationError> {
    match response {
        Ok(SessionConsumerResponse::OutcomeUnknown(SessionConsumerOutcomeUnknown::Lease))
        | Err(SessionConsumerCallError::MayHaveSent(_)) => {
            Err(SessionConsumerLeaseMutationError::OutcomeUnknown { request_id })
        }
        Err(SessionConsumerCallError::BeforeCallWrite(cause)) => {
            Err(SessionConsumerLeaseMutationError::NotTransmitted { cause })
        }
        Ok(SessionConsumerResponse::Rejected(rejection)) => Err(
            SessionConsumerLeaseMutationError::Lease(rejection_into_lease_error(rejection)),
        ),
        Ok(response) => match expected(response) {
            Some(Ok(result)) => Ok(result),
            Some(Err(opc_session_store::SessionConsumerLeaseError::OutcomeUnavailable)) => {
                Err(SessionConsumerLeaseMutationError::OutcomeUnknown { request_id })
            }
            Some(Err(error)) => Err(SessionConsumerLeaseMutationError::Lease(
                error.into_lease_error(),
            )),
            None => Err(SessionConsumerLeaseMutationError::OutcomeUnknown { request_id }),
        },
    }
}

/// Dedicated server for typed session-quorum consumers.
///
/// The constructor accepts only the typed [`SessionQuorumConsumer`] port. It
/// cannot be wired to a generic backend or a compatibility replication
/// listener, preserving the authority separation in its public type
/// signature.
#[cfg(test)]
struct ConsumerServerSetupTestHooks {
    accepted: Notify,
    continue_after_accept: Notify,
    tls_complete: Notify,
    continue_after_tls: Notify,
}

#[cfg(test)]
impl ConsumerServerSetupTestHooks {
    fn new() -> Self {
        Self {
            accepted: Notify::new(),
            continue_after_accept: Notify::new(),
            tls_complete: Notify::new(),
            continue_after_tls: Notify::new(),
        }
    }
}

pub struct SessionQuorumConsumerServer {
    service: Arc<dyn SessionQuorumConsumer>,
    tls_config: opc_tls::AuthenticatedServerConfig,
    authorizer: SessionConsumerAuthorizer,
    max_connections: usize,
    max_frame_size: usize,
    idle_timeout: Duration,
    operation_timeout: Duration,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
    #[cfg(test)]
    final_admission_test_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    setup_test_hooks: Option<Arc<ConsumerServerSetupTestHooks>>,
    #[cfg(test)]
    expire_at_final_ack_boundary: bool,
}

impl fmt::Debug for SessionQuorumConsumerServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionQuorumConsumerServer")
            .field("authenticated", &true)
            .field("authorizer", &self.authorizer)
            .field("max_connections", &self.max_connections)
            .field("max_frame_size", &self.max_frame_size)
            .field("idle_timeout", &self.idle_timeout)
            .field("operation_timeout", &self.operation_timeout)
            .finish_non_exhaustive()
    }
}

impl SessionQuorumConsumerServer {
    /// Construct one mTLS-only typed consumer listener.
    pub fn new(
        service: Arc<dyn SessionQuorumConsumer>,
        tls_config: opc_tls::AuthenticatedServerConfig,
        authorizer: SessionConsumerAuthorizer,
    ) -> Self {
        Self {
            service,
            tls_config,
            authorizer,
            max_connections: DEFAULT_CONSUMER_MAX_CONNECTIONS,
            max_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            idle_timeout: DEFAULT_CONSUMER_IDLE_TIMEOUT,
            operation_timeout: DEFAULT_CONSUMER_OPERATION_TIMEOUT,
            lifecycle_policy: ConnectionLifecyclePolicy::default(),
            reauthentication: SessionReauthenticationControl::new(),
            #[cfg(test)]
            final_admission_test_hook: None,
            #[cfg(test)]
            setup_test_hooks: None,
            #[cfg(test)]
            expire_at_final_ack_boundary: false,
        }
    }

    #[cfg(test)]
    fn with_final_admission_test_hook(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.final_admission_test_hook = Some(hook);
        self
    }

    #[cfg(test)]
    fn with_setup_test_hooks(mut self, hooks: Arc<ConsumerServerSetupTestHooks>) -> Self {
        self.setup_test_hooks = Some(hooks);
        self
    }

    #[cfg(test)]
    fn with_expiry_at_final_ack_boundary(mut self) -> Self {
        self.expire_at_final_ack_boundary = true;
        self
    }

    /// Set the maximum simultaneous live consumer connections, including TLS
    /// handshakes. Values above the fixed 256-slot listener ceiling fail
    /// validation before bind.
    #[must_use]
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Set the fixed encoded frame budget for this dedicated ALPN.
    #[must_use]
    pub fn with_max_frame_size(mut self, max_frame_size: usize) -> Self {
        self.max_frame_size = max_frame_size;
        self
    }

    /// Set the active authenticated-frame idle deadline, capped at five
    /// seconds by listener validation. TLS and the value-free Hello/HelloAck
    /// bootstrap use the separately configured operation deadline, because a
    /// lane does not become idle until that exchange succeeds.
    #[must_use]
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the complete server dispatch deadline for one typed request.
    #[must_use]
    pub fn with_operation_timeout(mut self, timeout: Duration) -> Self {
        self.operation_timeout = timeout;
        self
    }

    /// Set the finite certificate and reauthentication lifecycle policy.
    #[must_use]
    pub fn with_connection_lifecycle(mut self, policy: ConnectionLifecyclePolicy) -> Self {
        self.lifecycle_policy = policy;
        self
    }

    /// Share an explicit reauthentication control with the listener.
    #[must_use]
    pub fn with_reauthentication_control(
        mut self,
        control: SessionReauthenticationControl,
    ) -> Self {
        self.reauthentication = control;
        self
    }

    /// Return the listener's explicit reauthentication control.
    pub fn reauthentication_control(&self) -> SessionReauthenticationControl {
        self.reauthentication.clone()
    }

    /// Bind and serve the dedicated consumer ALPN.
    pub async fn listen(
        self,
        bind_address: SocketAddr,
    ) -> io::Result<(SessionQuorumConsumerServerHandle, SocketAddr)> {
        self.validate()?;
        let listener = TcpListener::bind(bind_address).await?;
        let address = listener.local_addr()?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let permits = Arc::new(Semaphore::new(self.max_connections));
        let connection_tasks = Arc::new(tokio::sync::Mutex::new(JoinSet::new()));
        let service = self.service;
        let tls_config = self.tls_config;
        let authorizer = self.authorizer;
        let max_frame_size = self.max_frame_size;
        let idle_timeout = self.idle_timeout;
        let operation_timeout = self.operation_timeout;
        let lifecycle_policy = self.lifecycle_policy;
        let reauthentication = self.reauthentication;
        #[cfg(test)]
        let final_admission_test_hook = self.final_admission_test_hook;
        #[cfg(test)]
        let setup_test_hooks = self.setup_test_hooks;
        #[cfg(test)]
        let expire_at_final_ack_boundary = self.expire_at_final_ack_boundary;
        let accept_cancellation = Arc::clone(&cancellation);
        let accept_connection_tasks = Arc::clone(&connection_tasks);
        let accept_handle = tokio::spawn(async move {
            loop {
                let permit = match permits.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => return,
                };
                let accepted = listener.accept().await;
                let Ok((stream, _)) = accepted else {
                    continue;
                };
                // Capture the one setup boundary at kernel acceptance, before
                // task bookkeeping or scheduling. TLS, Hello, rejection/Ack,
                // and publication all consume this same finite budget.
                let setup_deadline = tokio::time::Instant::now()
                    .checked_add(operation_timeout)
                    .expect("validated consumer setup has a bounded deadline");
                let service = Arc::clone(&service);
                let tls_config = tls_config.clone();
                let authorizer = authorizer.clone();
                let cancellation = Arc::clone(&accept_cancellation);
                let reauthentication = reauthentication.clone();
                #[cfg(test)]
                let final_admission_test_hook = final_admission_test_hook.clone();
                #[cfg(test)]
                let setup_test_hooks = setup_test_hooks.clone();
                #[cfg(test)]
                let expire_at_final_ack_boundary = expire_at_final_ack_boundary;
                let mut connection_tasks = accept_connection_tasks.lock().await;
                // The semaphore limits live connections, but a JoinSet keeps
                // completed task records until reaped. Drain those records on
                // every admission so sequential short connections cannot turn
                // into an unbounded listener-side allocation.
                while connection_tasks.try_join_next().is_some() {}
                connection_tasks.spawn(async move {
                    let _permit = permit;
                    let _ = handle_server_connection(
                        stream,
                        service,
                        tls_config,
                        authorizer,
                        max_frame_size,
                        idle_timeout,
                        operation_timeout,
                        setup_deadline,
                        lifecycle_policy,
                        reauthentication,
                        cancellation,
                        #[cfg(test)]
                        final_admission_test_hook,
                        #[cfg(test)]
                        setup_test_hooks,
                        #[cfg(test)]
                        expire_at_final_ack_boundary,
                    )
                    .await;
                });
            }
        });
        Ok((
            SessionQuorumConsumerServerHandle {
                accept_handle,
                cancellation,
                connection_tasks,
            },
            address,
        ))
    }

    fn validate(&self) -> io::Result<()> {
        if self.max_connections == 0
            || self.max_connections > DEFAULT_CONSUMER_MAX_CONNECTIONS
            || self.max_frame_size < MIN_SESSION_CONSUMER_RESPONSE_FRAME_SIZE
            || self.max_frame_size > MAX_NEGOTIATED_FRAME_SIZE
            || self.idle_timeout.is_zero()
            || self.idle_timeout > DEFAULT_CONSUMER_IDLE_TIMEOUT
            || !valid_consumer_operation_timeout(self.operation_timeout)
            || self
                .lifecycle_policy
                .validate_at(tokio::time::Instant::now())
                .is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid typed consumer listener configuration",
            ));
        }
        Ok(())
    }
}

/// Handle for a running typed consumer listener.
#[derive(Debug)]
pub struct SessionQuorumConsumerServerHandle {
    accept_handle: tokio::task::JoinHandle<()>,
    cancellation: Arc<AtomicBool>,
    connection_tasks: Arc<tokio::sync::Mutex<JoinSet<()>>>,
}

impl SessionQuorumConsumerServerHandle {
    /// Return whether the listener accept task has terminated.
    ///
    /// Product supervisors use this health signal to revoke readiness instead
    /// of leaving a management-live process falsely advertising a vanished
    /// consumer boundary.
    pub fn is_finished(&self) -> bool {
        self.accept_handle.is_finished()
    }

    /// Stop accepting new consumer connections.
    pub fn abort(&self) {
        self.cancellation.store(true, Ordering::Release);
        self.accept_handle.abort();
    }

    /// Stop the listener and wait for its accept task.
    pub async fn abort_and_wait(mut self) {
        self.abort();
        let _ = (&mut self.accept_handle).await;
        self.connection_tasks.lock().await.shutdown().await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_server_connection(
    stream: TcpStream,
    service: Arc<dyn SessionQuorumConsumer>,
    tls_config: opc_tls::AuthenticatedServerConfig,
    authorizer: SessionConsumerAuthorizer,
    max_frame_size: usize,
    idle_timeout: Duration,
    operation_timeout: Duration,
    setup_deadline: tokio::time::Instant,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
    cancellation: Arc<AtomicBool>,
    #[cfg(test)] final_admission_test_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)] setup_test_hooks: Option<Arc<ConsumerServerSetupTestHooks>>,
    #[cfg(test)] expire_at_final_ack_boundary: bool,
) -> Result<(), ProtocolError> {
    // Revision 2 reuses a socket for small request/response frames. Disable
    // Nagle on both peers so a warm exchange cannot inherit the platform's
    // delayed-ACK cadence and consume the bounded fair-pool wait budget.
    stream.set_nodelay(true).map_err(ProtocolError::Io)?;
    #[cfg(test)]
    if let Some(hooks) = &setup_test_hooks {
        hooks.accepted.notify_one();
        hooks.continue_after_accept.notified().await;
    }
    let generation = reauthentication.generation();
    let handshake = tls_config
        .begin_handshake()
        .map_err(|_| ProtocolError::Authentication)?;
    let acceptor =
        tokio_rustls::TlsAcceptor::from(consumer_server_tls_config(handshake.rustls_config()));
    // An idle authenticated lane does not exist until the HelloAck is sent.
    // Bound TLS and the value-free bootstrap with the listener's finite
    // operation deadline, rather than applying a short active-frame idle
    // interval to slow but valid authenticated setup.
    if tokio::time::Instant::now() >= setup_deadline {
        return Err(consumer_setup_timeout("consumer setup deadline elapsed"));
    }
    let tls = tokio::time::timeout_at(setup_deadline, acceptor.accept(stream))
        .await
        .map_err(|_| consumer_setup_timeout("consumer TLS handshake timed out"))?
        .map_err(classify_tls_io_error)?;
    if tokio::time::Instant::now() >= setup_deadline {
        return Err(consumer_setup_timeout("consumer setup deadline elapsed"));
    }
    #[cfg(test)]
    if let Some(hooks) = &setup_test_hooks {
        hooks.tls_complete.notify_one();
        hooks.continue_after_tls.notified().await;
    }
    let established_at = tokio::time::Instant::now();
    if tls.get_ref().1.alpn_protocol() != Some(SESSION_QUORUM_CONSUMER_ALPN) {
        return Err(ProtocolError::UnexpectedResponse);
    }
    let peer = opc_tls::peer_tls_identity_from_server_connection(tls.get_ref().1)
        .map_err(|_| ProtocolError::Authentication)?;
    let identity = authorizer
        .authorize(peer.spiffe_id())
        .map_err(|_| ProtocolError::Authentication)?;
    let rotation_edge_key = handshake.directed_lifecycle_edge_key(b"consumer", peer.spiffe_id());
    let (mut reader, mut writer) = tokio::io::split(tls);
    let hello = read_consumer_frame_until::<_, ConsumerWireRequest>(
        &mut reader,
        max_frame_size,
        setup_deadline,
    )
    .await?;
    let ConsumerWireRequest::Hello(hello) = hello else {
        return Err(ProtocolError::UnexpectedResponse);
    };
    if hello.transport_revision != SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION {
        return Err(ProtocolError::UnexpectedResponse);
    }
    let response_frame_size =
        checked_consumer_frame_size(hello.response_frame_size)?.min(max_frame_size);
    if hello.scope != authorizer.scope() {
        let _ = write_consumer_response_until(
            &mut writer,
            ConsumerWireResponse::HelloRejected(SessionConsumerRejection::ScopeMismatch),
            response_frame_size,
            setup_deadline,
        )
        .await;
        return Err(ProtocolError::UnexpectedResponse);
    }
    let admission = handshake
        .admit()
        .map_err(|_| ProtocolError::Authentication)?;
    if !consumer_fresh_admission_is_current(
        generation,
        admission.epoch(),
        reauthentication.generation(),
        tls_config.material_status().epoch(),
    ) {
        return Err(ProtocolError::Authentication);
    }
    let mut lifecycle = ConnectionLifecycle::new(
        lifecycle_policy,
        established_at,
        Some(CertificateExpiryEvidence::capture(
            handshake.leaf_expires_at(),
            handshake.certificate_chain_expires_at(),
            established_at,
        )),
        Some(CertificateExpiryEvidence::capture(
            peer.leaf_expires_at(),
            peer.certificate_chain_expires_at(),
            established_at,
        )),
        generation,
        Some(admission.epoch()),
    )
    .map_err(|_| ProtocolError::InvalidWireValue)?;
    let mut reauthentication_changes = reauthentication.subscribe();
    let mut material_changes = Some(tls_config.subscribe_material_changes());
    // Linearize fresh server admission immediately before publishing
    // HelloAck. A later rotation applies to an admitted lane and is observed
    // through the subscribed lifecycle path below; stale fresh handshakes are
    // closed without an acknowledgement.
    #[cfg(test)]
    if let Some(hook) = &final_admission_test_hook {
        hook();
    }
    if !consumer_fresh_admission_is_current(
        generation,
        admission.epoch(),
        reauthentication.generation(),
        tls_config.material_status().epoch(),
    ) {
        return Err(ProtocolError::Authentication);
    }
    #[cfg(test)]
    if expire_at_final_ack_boundary {
        lifecycle.expire_at_final_ack_boundary_for_test();
    }
    if lifecycle.retirement(tokio::time::Instant::now()).is_some() {
        return Err(ProtocolError::Authentication);
    }
    // Pin one Ack write while lifecycle notifications are observed. A benign
    // same-epoch publication cannot restart the write or its absolute setup
    // deadline; an explicit rotation or a cooperative material deadline
    // closes before a complete acknowledgement is published.
    {
        let hello_ack = write_consumer_response_until(
            &mut writer,
            ConsumerWireResponse::HelloAck(ConsumerHelloAck {
                transport_revision: SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
                scope: authorizer.scope(),
                request_frame_size: consumer_wire_frame_size(max_frame_size)?,
            }),
            response_frame_size,
            setup_deadline.min(lifecycle.retire_at()),
        );
        tokio::pin!(hello_ack);
        loop {
            let lifecycle_deadline = lifecycle.retire_at();
            let ack_deadline = setup_deadline.min(lifecycle_deadline);
            let now = tokio::time::Instant::now();
            if now >= setup_deadline || lifecycle.retirement(now).is_some() {
                return Err(consumer_setup_timeout("consumer HelloAck deadline elapsed"));
            }
            let acknowledged = tokio::select! {
                biased;
                _ = tokio::time::sleep_until(ack_deadline) => {
                    let _ = lifecycle.retirement(tokio::time::Instant::now());
                    return Err(consumer_setup_timeout("consumer HelloAck deadline elapsed"));
                }
                _ = reauthentication_changes.changed() => {
                    if !server_connection_current(
                        &mut lifecycle,
                        &tls_config,
                        &reauthentication,
                        rotation_edge_key,
                    ) {
                        return Err(ProtocolError::Authentication);
                    }
                    continue;
                }
                _ = wait_consumer_material_change(&mut material_changes) => {
                    if !server_connection_current(
                        &mut lifecycle,
                        &tls_config,
                        &reauthentication,
                        rotation_edge_key,
                    ) {
                        return Err(ProtocolError::Authentication);
                    }
                    continue;
                }
                result = &mut hello_ack => result,
            };
            acknowledged?;
            let now = tokio::time::Instant::now();
            if now >= setup_deadline || lifecycle.retirement(now).is_some() {
                return Err(consumer_setup_timeout("consumer HelloAck deadline elapsed"));
            }
            break;
        }
    }
    let mut expected_correlation = NonZeroU32::MIN;
    for _ in 0..MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION {
        if cancellation.load(Ordering::Acquire) {
            return Ok(());
        }
        let call = {
            // Keep one exact-decoding read and its absolute idle deadline
            // across benign material-source publications. Dropping and
            // recreating this future could lose an already-consumed prefix.
            let idle_deadline = tokio::time::Instant::now()
                .checked_add(idle_timeout)
                .ok_or(ProtocolError::InvalidWireValue)?;
            let read_call = read_authenticated_consumer_frame_until::<_, ConsumerWireRequest>(
                &mut reader,
                max_frame_size,
                idle_deadline,
            );
            tokio::pin!(read_call);
            loop {
                let lifecycle_deadline = lifecycle.retire_at();
                let now = tokio::time::Instant::now();
                if cancellation.load(Ordering::Acquire) {
                    return Ok(());
                }
                // When lifecycle retirement is the first boundary it may
                // close the lane directly. When byte-idle is earlier, the
                // pinned read must be polled first: only its `Ok(None)` proves
                // that no partial authenticated frame was in progress.
                if lifecycle_deadline <= idle_deadline && now >= lifecycle_deadline {
                    let _ = lifecycle.retirement(now);
                    return Ok(());
                }
                let call = tokio::select! {
                    biased;
                    request = &mut read_call => {
                        let now = tokio::time::Instant::now();
                        if lifecycle_deadline <= idle_deadline && now >= lifecycle_deadline {
                            let _ = lifecycle.retirement(now);
                            return Ok(());
                        }
                        match request? {
                            Some(request) => Some(request),
                            None => {
                                lifecycle.record_forced_retirement(RetirementReason::IdleTimeout);
                                return Ok(());
                            }
                        }
                    },
                    _ = tokio::time::sleep_until(lifecycle_deadline) => {
                        let _ = lifecycle.retirement(tokio::time::Instant::now());
                        return Ok(());
                    },
                    _ = tokio::time::sleep(CONSUMER_WATCH_CANCELLATION_RECHECK_INTERVAL) => {
                        if cancellation.load(Ordering::Acquire) {
                            return Ok(());
                        }
                        None
                    }
                    _ = reauthentication_changes.changed() => {
                        if !server_connection_current(
                            &mut lifecycle,
                            &tls_config,
                            &reauthentication,
                            rotation_edge_key,
                        ) {
                            return Ok(());
                        }
                        None
                    },
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        if !server_connection_current(
                            &mut lifecycle,
                            &tls_config,
                            &reauthentication,
                            rotation_edge_key,
                        ) {
                            return Ok(());
                        }
                        None
                    },
                };
                if let Some(call) = call {
                    break call;
                }
            }
        };
        let ConsumerWireRequest::Call(ConsumerCall {
            correlation,
            request,
        }) = call
        else {
            return Err(ProtocolError::UnexpectedResponse);
        };
        // A connection admits exactly one ordered sequence. Zero, duplicate,
        // future, and late call IDs all close it before dispatch.
        exact_correlation(expected_correlation, correlation)?;
        if !server_connection_current(
            &mut lifecycle,
            &tls_config,
            &reauthentication,
            rotation_edge_key,
        ) {
            return Ok(());
        }
        if request.scope() != authorizer.scope() {
            write_consumer_response(
                &mut writer,
                ConsumerWireResponse::Response(ConsumerCallResponse {
                    correlation,
                    response: Box::new(SessionConsumerResponse::Rejected(
                        SessionConsumerRejection::ScopeMismatch,
                    )),
                }),
                response_frame_size,
                idle_timeout,
            )
            .await?;
            return Ok(());
        }
        if let Err(rejection) = request.validate() {
            write_consumer_response(
                &mut writer,
                ConsumerWireResponse::Response(ConsumerCallResponse {
                    correlation,
                    response: Box::new(SessionConsumerResponse::Rejected(rejection)),
                }),
                response_frame_size,
                idle_timeout,
            )
            .await?;
            return Ok(());
        }
        let watch_start = match request.operation() {
            SessionConsumerOperation::Watch { start_sequence } => Some(*start_sequence),
            _ => None,
        };
        let restore_request = match request.operation() {
            SessionConsumerOperation::ScanRestoreRecords { request } => Some(request.clone()),
            _ => None,
        };
        let operation = ConsumerOperationKind::from_operation(request.operation());
        let scope = request.scope();
        let request_deadline = tokio::time::Instant::now()
            .checked_add(operation_timeout)
            .ok_or(ProtocolError::InvalidWireValue)?;
        let execute = service.execute(&identity, *request);
        tokio::pin!(execute);
        let mut response = loop {
            let hard_deadline = lifecycle
                .hard_deadline()
                .map_err(|_| ProtocolError::InvalidWireValue)?;
            let admitted_deadline = request_deadline.min(hard_deadline);
            let now = tokio::time::Instant::now();
            if cancellation.load(Ordering::Acquire) {
                return Ok(());
            }
            if now >= admitted_deadline {
                if hard_deadline <= request_deadline {
                    record_consumer_hard_overrun(&lifecycle);
                    return Ok(());
                }
                break consumer_timeout_response(operation);
            }
            let response = tokio::select! {
                biased;
                response = &mut execute => {
                    let now = tokio::time::Instant::now();
                    if now >= admitted_deadline {
                        if hard_deadline <= request_deadline {
                            record_consumer_hard_overrun(&lifecycle);
                            return Ok(());
                        }
                        Some(consumer_timeout_response(operation))
                    } else {
                        Some(response)
                    }
                },
                _ = tokio::time::sleep_until(admitted_deadline) => {
                    if hard_deadline <= request_deadline {
                        record_consumer_hard_overrun(&lifecycle);
                        return Ok(());
                    }
                    Some(consumer_timeout_response(operation))
                }
                _ = tokio::time::sleep(CONSUMER_WATCH_CANCELLATION_RECHECK_INTERVAL) => {
                    if cancellation.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    None
                }
                _ = reauthentication_changes.changed() => {
                    observe_consumer_rotation(
                        &mut lifecycle,
                        tokio::time::Instant::now(),
                        reauthentication.generation(),
                        tls_config.material_status().epoch(),
                        rotation_edge_key,
                    );
                    None
                }
                _ = wait_consumer_material_change(&mut material_changes) => {
                    observe_consumer_rotation(
                        &mut lifecycle,
                        tokio::time::Instant::now(),
                        reauthentication.generation(),
                        tls_config.material_status().epoch(),
                        rotation_edge_key,
                    );
                    None
                }
            };
            if let Some(response) = response {
                break response;
            }
        };
        observe_consumer_rotation(
            &mut lifecycle,
            tokio::time::Instant::now(),
            reauthentication.generation(),
            tls_config.material_status().epoch(),
            rotation_edge_key,
        );
        let hard_deadline = lifecycle
            .hard_deadline()
            .map_err(|_| ProtocolError::InvalidWireValue)?;
        if tokio::time::Instant::now() >= hard_deadline {
            record_consumer_hard_overrun(&lifecycle);
            return Ok(());
        }
        if cancellation.load(Ordering::Acquire) {
            return Ok(());
        }
        if !response_matches_operation(operation, &response) {
            return Err(ProtocolError::UnexpectedResponse);
        }
        if let (Some(request), SessionConsumerResponse::ScanRestoreRecords(Ok(page))) =
            (&restore_request, &response)
        {
            // Keep #684's page validation and response-fit replacement before
            // writing a frame; revision-2 only adds the small correlation
            // envelope to the fit calculation.
            if page.validate_for_request(request).is_err()
                || !consumer_response_fits_for_correlation(
                    correlation,
                    &response,
                    response_frame_size,
                )
            {
                response = SessionConsumerResponse::ScanRestoreRecords(Err(
                    SessionConsumerStoreError::RestoreBudgetExceeded,
                ));
            }
        }
        // A watch admission has exactly one correlated response. Resolve the
        // backend stream before writing WatchOpened so a backend rejection can
        // replace that response instead of emitting a duplicate correlation.
        let mut opened_watch = None;
        if let Some(start_sequence) = watch_start {
            if matches!(response, SessionConsumerResponse::WatchOpened) {
                let watch_setup = service.watch(&identity, scope, start_sequence);
                tokio::pin!(watch_setup);
                let watch_result = loop {
                    let hard_deadline = lifecycle
                        .hard_deadline()
                        .map_err(|_| ProtocolError::InvalidWireValue)?;
                    let admitted_deadline = request_deadline.min(hard_deadline);
                    let now = tokio::time::Instant::now();
                    if cancellation.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    if now >= admitted_deadline {
                        if hard_deadline <= request_deadline {
                            record_consumer_hard_overrun(&lifecycle);
                        }
                        return Ok(());
                    }
                    let result = tokio::select! {
                        biased;
                        result = &mut watch_setup => {
                            let now = tokio::time::Instant::now();
                            if now >= admitted_deadline {
                                if hard_deadline <= request_deadline {
                                    record_consumer_hard_overrun(&lifecycle);
                                }
                                return Ok(());
                            }
                            Some(result)
                        },
                        _ = tokio::time::sleep_until(admitted_deadline) => {
                            if hard_deadline <= request_deadline {
                                record_consumer_hard_overrun(&lifecycle);
                            }
                            return Ok(());
                        }
                        _ = tokio::time::sleep(CONSUMER_WATCH_CANCELLATION_RECHECK_INTERVAL) => {
                            if cancellation.load(Ordering::Acquire) {
                                return Ok(());
                            }
                            None
                        }
                        _ = reauthentication_changes.changed() => {
                            observe_consumer_rotation(
                                &mut lifecycle,
                                tokio::time::Instant::now(),
                                reauthentication.generation(),
                        tls_config.material_status().epoch(),
                        rotation_edge_key,
                    );
                            None
                        }
                        _ = wait_consumer_material_change(&mut material_changes) => {
                            observe_consumer_rotation(
                                &mut lifecycle,
                                tokio::time::Instant::now(),
                                reauthentication.generation(),
                        tls_config.material_status().epoch(),
                        rotation_edge_key,
                    );
                            None
                        }
                    };
                    if let Some(result) = result {
                        break result;
                    }
                };
                match watch_result {
                    Ok(watch) => opened_watch = Some(watch),
                    Err(rejection) => {
                        response = SessionConsumerResponse::Rejected(rejection);
                    }
                }
            }
            observe_consumer_rotation(
                &mut lifecycle,
                tokio::time::Instant::now(),
                reauthentication.generation(),
                tls_config.material_status().epoch(),
                rotation_edge_key,
            );
            let hard_deadline = lifecycle
                .hard_deadline()
                .map_err(|_| ProtocolError::InvalidWireValue)?;
            if cancellation.load(Ordering::Acquire) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= hard_deadline {
                record_consumer_hard_overrun(&lifecycle);
                return Ok(());
            }
        }
        let watch_opened = matches!(response, SessionConsumerResponse::WatchOpened);
        let retire_after_response = response_retires_connection_authority(&response);
        {
            let initial_hard_deadline = lifecycle
                .hard_deadline()
                .map_err(|_| ProtocolError::InvalidWireValue)?;
            let active_frame_deadline = tokio::time::Instant::now()
                .checked_add(idle_timeout)
                .ok_or(ProtocolError::InvalidWireValue)?;
            let response_write_deadline = request_deadline
                .min(initial_hard_deadline)
                .min(active_frame_deadline);
            let response_write = write_consumer_response_until(
                &mut writer,
                ConsumerWireResponse::Response(ConsumerCallResponse {
                    correlation,
                    response: Box::new(response),
                }),
                response_frame_size,
                response_write_deadline,
            );
            tokio::pin!(response_write);
            loop {
                let hard_deadline = lifecycle
                    .hard_deadline()
                    .map_err(|_| ProtocolError::InvalidWireValue)?;
                if cancellation.load(Ordering::Acquire) {
                    return Ok(());
                }
                if hard_deadline <= response_write_deadline
                    && tokio::time::Instant::now() >= hard_deadline
                {
                    record_consumer_hard_overrun(&lifecycle);
                    return Ok(());
                }
                let result = tokio::select! {
                    biased;
                    result = &mut response_write => {
                        if hard_deadline <= response_write_deadline
                            && tokio::time::Instant::now() >= hard_deadline
                        {
                            record_consumer_hard_overrun(&lifecycle);
                            return Ok(());
                        }
                        Some(result)
                    },
                    _ = wait_for_shortened_deadline(hard_deadline, response_write_deadline) => {
                        record_consumer_hard_overrun(&lifecycle);
                        return Ok(());
                    }
                    _ = tokio::time::sleep(CONSUMER_WATCH_CANCELLATION_RECHECK_INTERVAL) => {
                        if cancellation.load(Ordering::Acquire) {
                            return Ok(());
                        }
                        None
                    }
                    _ = reauthentication_changes.changed() => {
                        observe_consumer_rotation(
                            &mut lifecycle,
                            tokio::time::Instant::now(),
                            reauthentication.generation(),
                        tls_config.material_status().epoch(),
                        rotation_edge_key,
                    );
                        None
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        observe_consumer_rotation(
                            &mut lifecycle,
                            tokio::time::Instant::now(),
                            reauthentication.generation(),
                        tls_config.material_status().epoch(),
                        rotation_edge_key,
                    );
                        None
                    }
                };
                if let Some(result) = result {
                    result?;
                    break;
                }
            }
        }
        if retire_after_response {
            return Ok(());
        }
        if watch_start.is_none() {
            expected_correlation = expected_correlation
                .get()
                .checked_add(1)
                .and_then(NonZeroU32::new)
                .ok_or(ProtocolError::InvalidWireValue)?;
            continue;
        }
        if !watch_opened {
            return Ok(());
        }
        // A watch is terminal: no subsequent call is decoded after opening it.
        let mut watch = opened_watch.ok_or(ProtocolError::UnexpectedResponse)?;
        let mut peer_probe = [0_u8; 1];
        loop {
            if cancellation.load(Ordering::Acquire)
                || !server_connection_current(
                    &mut lifecycle,
                    &tls_config,
                    &reauthentication,
                    rotation_edge_key,
                )
            {
                return Ok(());
            }
            let entry = tokio::select! {
                biased;
                entry = watch.next() => entry,
                _ = reader.read(&mut peer_probe) => return Ok(()),
                _ = tokio::time::sleep_until(lifecycle.retire_at()) => {
                    let _ = lifecycle.retirement(tokio::time::Instant::now());
                    return Ok(());
                },
                _ = tokio::time::sleep(CONSUMER_WATCH_CANCELLATION_RECHECK_INTERVAL) => {
                    if cancellation.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    continue;
                }
                _ = reauthentication_changes.changed() => {
                    if !server_connection_current(
                        &mut lifecycle,
                        &tls_config,
                        &reauthentication,
                            rotation_edge_key,
                        ) {
                        return Ok(());
                    }
                    continue;
                },
                _ = wait_consumer_material_change(&mut material_changes) => {
                    if !server_connection_current(
                        &mut lifecycle,
                        &tls_config,
                        &reauthentication,
                            rotation_edge_key,
                        ) {
                        return Ok(());
                    }
                    continue;
                },
            };
            let Some(entry) = entry else {
                return Ok(());
            };
            if entry
                .as_ref()
                .err()
                .is_some_and(|error| !consumer_watch_error_is_legal(*error))
            {
                return Ok(());
            }
            if cancellation.load(Ordering::Acquire)
                || !server_connection_current(
                    &mut lifecycle,
                    &tls_config,
                    &reauthentication,
                    rotation_edge_key,
                )
            {
                return Ok(());
            }
            let watch_write_deadline = tokio::time::Instant::now()
                .checked_add(operation_timeout)
                .ok_or(ProtocolError::InvalidWireValue)?
                .min(
                    tokio::time::Instant::now()
                        .checked_add(idle_timeout)
                        .ok_or(ProtocolError::InvalidWireValue)?,
                )
                .min(
                    lifecycle
                        .hard_deadline()
                        .map_err(|_| ProtocolError::InvalidWireValue)?,
                );
            let watch_write = write_consumer_response_until(
                &mut writer,
                ConsumerWireResponse::WatchEntry(ConsumerWatchEntry {
                    correlation,
                    entry: Box::new(entry),
                }),
                response_frame_size,
                watch_write_deadline,
            );
            tokio::pin!(watch_write);
            loop {
                let hard_deadline = lifecycle
                    .hard_deadline()
                    .map_err(|_| ProtocolError::InvalidWireValue)?;
                if cancellation.load(Ordering::Acquire)
                    || !server_connection_current(
                        &mut lifecycle,
                        &tls_config,
                        &reauthentication,
                        rotation_edge_key,
                    )
                {
                    return Ok(());
                }
                if hard_deadline <= watch_write_deadline
                    && tokio::time::Instant::now() >= hard_deadline
                {
                    record_consumer_hard_overrun(&lifecycle);
                    return Ok(());
                }
                let result = tokio::select! {
                    biased;
                    result = &mut watch_write => {
                        if hard_deadline <= watch_write_deadline
                            && tokio::time::Instant::now() >= hard_deadline
                        {
                            record_consumer_hard_overrun(&lifecycle);
                            return Ok(());
                        }
                        Some(result)
                    },
                    _ = wait_for_shortened_deadline(hard_deadline, watch_write_deadline) => {
                        record_consumer_hard_overrun(&lifecycle);
                        return Ok(());
                    }
                    _ = tokio::time::sleep(CONSUMER_WATCH_CANCELLATION_RECHECK_INTERVAL) => {
                        if cancellation.load(Ordering::Acquire) {
                            return Ok(());
                        }
                        None
                    }
                    _ = reader.read(&mut peer_probe) => return Ok(()),
                    _ = reauthentication_changes.changed() => {
                        observe_consumer_rotation(
                            &mut lifecycle,
                            tokio::time::Instant::now(),
                            reauthentication.generation(),
                        tls_config.material_status().epoch(),
                        rotation_edge_key,
                    );
                        None
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        observe_consumer_rotation(
                            &mut lifecycle,
                            tokio::time::Instant::now(),
                            reauthentication.generation(),
                        tls_config.material_status().epoch(),
                        rotation_edge_key,
                    );
                        None
                    }
                };
                if let Some(result) = result {
                    result?;
                    if !server_connection_current(
                        &mut lifecycle,
                        &tls_config,
                        &reauthentication,
                        rotation_edge_key,
                    ) {
                        return Ok(());
                    }
                    break;
                }
            }
        }
    }
    Ok(())
}

fn consumer_timeout_response(operation: ConsumerOperationKind) -> SessionConsumerResponse {
    let mutation_may_have_been_accepted = match operation {
        ConsumerOperationKind::CompareAndSet
        | ConsumerOperationKind::DeleteFenced
        | ConsumerOperationKind::RefreshTtl
        | ConsumerOperationKind::UnknownEffectful => Some(SessionConsumerOutcomeUnknown::Mutation),
        ConsumerOperationKind::AcquireLease
        | ConsumerOperationKind::RenewLease
        | ConsumerOperationKind::ReleaseLease => Some(SessionConsumerOutcomeUnknown::Lease),
        ConsumerOperationKind::Batch {
            contains_mutation: true,
        } => Some(SessionConsumerOutcomeUnknown::Mutation),
        ConsumerOperationKind::Capabilities
        | ConsumerOperationKind::Get
        | ConsumerOperationKind::PreflightRecordExpiry
        | ConsumerOperationKind::Batch {
            contains_mutation: false,
        }
        | ConsumerOperationKind::ScanRestoreRecords
        | ConsumerOperationKind::Watch => None,
    };
    mutation_may_have_been_accepted.map_or(
        SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable),
        SessionConsumerResponse::OutcomeUnknown,
    )
}

#[cfg(test)]
fn consumer_response_fits(response: &SessionConsumerResponse, max_frame_size: usize) -> bool {
    consumer_response_fits_for_correlation(NonZeroU32::MIN, response, max_frame_size)
}

fn consumer_response_fits_for_correlation(
    correlation: NonZeroU32,
    response: &SessionConsumerResponse,
    max_frame_size: usize,
) -> bool {
    struct BoundedResponseSize {
        encoded: usize,
        maximum: usize,
    }

    impl io::Write for BoundedResponseSize {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let encoded = self.encoded.checked_add(bytes.len()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "consumer response size overflow",
                )
            })?;
            if encoded > self.maximum {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "consumer response exceeds negotiated frame size",
                ));
            }
            self.encoded = encoded;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut size = BoundedResponseSize {
        encoded: 0,
        maximum: max_frame_size,
    };
    serde_json::to_writer(
        &mut size,
        &BorrowedConsumerWireResponse::Response(BorrowedConsumerCallResponse {
            correlation,
            response: SerializableConsumerResponse(response),
        }),
    )
    .is_ok()
}

async fn write_consumer_response<W>(
    writer: &mut W,
    response: ConsumerWireResponse,
    max_frame_size: usize,
    timeout: Duration,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or(ProtocolError::InvalidWireValue)?;
    write_consumer_response_until(writer, response, max_frame_size, deadline).await
}

async fn wait_consumer_material_change(receiver: &mut Option<opc_tls::TlsMaterialStatusReceiver>) {
    loop {
        let Some(status) = receiver.as_mut() else {
            std::future::pending::<()>().await;
            continue;
        };
        if status.changed().await.is_ok() {
            return;
        }
        *receiver = None;
    }
}

async fn write_consumer_response_until<W>(
    writer: &mut W,
    response: ConsumerWireResponse,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    write_frame_bounded_until(writer, &response, max_frame_size, deadline).await
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::num::NonZeroU32;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use super::{
        classify_call_write_error, complete_before_deadline, consumer_fresh_admission_is_current,
        consumer_payload_fragments_exceed_frame, consumer_response_fits,
        consumer_watch_error_is_legal, decode_consumer_frame_payload,
        ensure_pre_request_budget_remaining, exact_correlation, lease_error_matches_operation,
        lease_response, mutation_response, persistent_execute_error,
        publish_monotonic_shutdown_phase, queued_consumer_watch_stream,
        read_authenticated_consumer_frame_within, response_is_outcome_unknown,
        response_matches_operation, response_matches_request,
        response_retires_connection_authority, server_connection_current,
        store_error_matches_operation, valid_consumer_operation_timeout, wait_for_forced_shutdown,
        BorrowedConsumerCall, BorrowedConsumerCallResponse, BorrowedConsumerWireRequest,
        BorrowedConsumerWireResponse, BoxStream, ConsumerCall, ConsumerCallResponse,
        ConsumerConnection, ConsumerOperationKind, ConsumerServerSetupTestHooks,
        ConsumerSetupPhase, ConsumerSetupPhaseAttempt, ConsumerWatchTerminal,
        ConsumerWatchTerminalSlot, ConsumerWireRequest, ConsumerWireResponse,
        PersistentCheckedOutConnection, PersistentConsumerCounters, PersistentConsumerIoBarrier,
        PersistentConsumerShutdownReader, PersistentConsumerShutdownWriter,
        PersistentSessionConsumerClient, PersistentSessionConsumerConfig,
        PersistentSessionConsumerConfigError, PersistentSessionConsumerExecuteError,
        PersistentSetupAttempt, PersistentShutdownPhase, PersistentWatchRecovery,
        QueuedConsumerWatchItem, SerializableConsumerResponse, SessionConsumerAuthorizationError,
        SessionConsumerAuthorizer, SessionConsumerCallError, SessionConsumerChange,
        SessionConsumerClientError, SessionConsumerIdentity, SessionConsumerLeaseMutationError,
        SessionConsumerMutationError, SessionConsumerRejection, SessionQuorumConsumer,
        SessionQuorumConsumerServer, StatelessSessionConsumerClient,
        DEFAULT_CONSUMER_OPERATION_TIMEOUT, DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
        DEFAULT_PERSISTENT_SESSION_CONSUMER_PENDING_CALLS,
        DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
        DEFAULT_PERSISTENT_SESSION_CONSUMER_RECONNECT_JITTER,
        DEFAULT_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS,
        DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
        DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
        MAX_PERSISTENT_SESSION_CONSUMER_PENDING_CALLS,
        MAX_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS,
        MAX_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
    };
    use bytes::Bytes;
    use futures_util::StreamExt;
    use opc_session_store::{
        checked_session_deadline, BackendCapabilities, CompareAndSet, CompareAndSetResult,
        EncryptedSessionPayload, FakeSessionBackend, FenceToken, Generation, LeaseGuard, OwnerId,
        RestoreScanCursorProfile, RestoreScanPage, RestoreScanRequest, SessionConsensusClusterId,
        SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
        SessionConsensusIdentity, SessionConsumerBatchResult, SessionConsumerLeaseError,
        SessionConsumerLeaseGrant, SessionConsumerOperation, SessionConsumerOutcomeUnknown,
        SessionConsumerRequest, SessionConsumerRequestId, SessionConsumerResponse,
        SessionConsumerScope, SessionConsumerStoreError, SessionKey, SessionKeyType,
        SessionLeaseManager, SessionOp, StateClass, StateType, StoreError, StoredSessionRecord,
        MAX_SESSION_TTL,
    };
    use opc_types::{NetworkFunctionKind, SpiffeId, TenantId, Timestamp};
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::sync::{mpsc, watch, Semaphore};

    use crate::lifecycle::{
        ConnectionLifecycle, ConnectionLifecyclePolicy, RetirementReason,
        SessionReauthenticationControl,
    };
    use crate::protocol::MAX_NEGOTIATED_FRAME_SIZE;
    use crate::test_support::{RotatableClientMaterial, RotatableServerMaterial};

    struct RejectingTestConsumer;

    #[async_trait::async_trait]
    impl SessionQuorumConsumer for RejectingTestConsumer {
        async fn execute(
            &self,
            _identity: &SessionConsumerIdentity,
            _request: SessionConsumerRequest,
        ) -> SessionConsumerResponse {
            SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable)
        }

        async fn watch(
            &self,
            _identity: &SessionConsumerIdentity,
            _scope: SessionConsumerScope,
            _start_sequence: u64,
        ) -> Result<
            BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
            SessionConsumerRejection,
        > {
            Err(SessionConsumerRejection::Unavailable)
        }
    }

    struct CountingRejectingTestConsumer {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl SessionQuorumConsumer for CountingRejectingTestConsumer {
        async fn execute(
            &self,
            _identity: &SessionConsumerIdentity,
            _request: SessionConsumerRequest,
        ) -> SessionConsumerResponse {
            self.calls.fetch_add(1, Ordering::SeqCst);
            SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable)
        }

        async fn watch(
            &self,
            _identity: &SessionConsumerIdentity,
            _scope: SessionConsumerScope,
            _start_sequence: u64,
        ) -> Result<
            BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
            SessionConsumerRejection,
        > {
            Err(SessionConsumerRejection::Unavailable)
        }
    }

    struct AuthorityRejectingTestConsumer {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl SessionQuorumConsumer for AuthorityRejectingTestConsumer {
        async fn execute(
            &self,
            _identity: &SessionConsumerIdentity,
            _request: SessionConsumerRequest,
        ) -> SessionConsumerResponse {
            self.calls.fetch_add(1, Ordering::SeqCst);
            SessionConsumerResponse::Rejected(SessionConsumerRejection::Unauthorized)
        }

        async fn watch(
            &self,
            _identity: &SessionConsumerIdentity,
            _scope: SessionConsumerScope,
            _start_sequence: u64,
        ) -> Result<
            BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
            SessionConsumerRejection,
        > {
            Err(SessionConsumerRejection::Unauthorized)
        }
    }

    fn scope() -> SessionConsumerScope {
        SessionConsumerScope::new(SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([1; 32]),
            SessionConsensusConfigurationId::from_bytes([2; 32]),
            SessionConsensusConfigurationEpoch::new(1).expect("non-zero configuration epoch"),
        ))
    }

    #[tokio::test]
    async fn watch_terminal_is_ordered_after_saturated_item_and_byte_capacity() {
        let (sender, receiver) = mpsc::channel::<QueuedConsumerWatchItem>(1);
        let byte_budget = Arc::new(Semaphore::new(1));
        let queued_permit = Arc::clone(&byte_budget)
            .try_acquire_owned()
            .expect("saturate the complete byte budget");
        sender
            .try_send(QueuedConsumerWatchItem {
                item: Some(Err(StoreError::BackendUnavailable(
                    "consumer watch queued item".into(),
                ))),
                _byte_permit: queued_permit,
                watch_pool: None,
            })
            .expect("saturate the one-item queue");
        let terminal = Arc::new(ConsumerWatchTerminalSlot::new(None));
        terminal.store(ConsumerWatchTerminal::PayloadTooLarge { actual: 2, max: 1 });
        drop(sender);

        let mut stream = queued_consumer_watch_stream(receiver, terminal);
        assert!(matches!(
            stream.next().await,
            Some(Err(StoreError::BackendUnavailable(_)))
        ));
        assert!(matches!(
            stream.next().await,
            Some(Err(StoreError::PayloadTooLarge { actual: 2, max: 1 }))
        ));
        assert!(stream.next().await.is_none());
        assert_eq!(byte_budget.available_permits(), 1);

        let (_sender, receiver) = mpsc::channel::<QueuedConsumerWatchItem>(1);
        let terminal = Arc::new(ConsumerWatchTerminalSlot::new(None));
        terminal.store(ConsumerWatchTerminal::Unavailable);
        drop(_sender);
        let mut stream = queued_consumer_watch_stream(receiver, terminal);
        assert!(matches!(
            stream.next().await,
            Some(Err(StoreError::BackendUnavailable(_)))
        ));
        assert!(stream.next().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn watch_recovery_scheduler_enforces_each_attempt_floor_and_absolute_window() {
        let mut recovery = PersistentWatchRecovery::default();
        let started = tokio::time::Instant::now();
        let (first_attempt, deadline) = recovery
            .next_attempt_at(Duration::from_millis(150), 2, Duration::from_millis(50))
            .expect("first bounded recovery attempt");
        assert_eq!(first_attempt, started + Duration::from_millis(50));
        assert_eq!(deadline, started + Duration::from_millis(150));
        let first_wait = tokio::time::sleep_until(first_attempt);
        tokio::pin!(first_wait);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(first_wait.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_millis(49)).await;
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(first_wait.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_millis(1)).await;
        first_wait.await;
        recovery.attempts += 1;

        let (second_attempt, same_deadline) = recovery
            .next_attempt_at(Duration::from_millis(150), 2, Duration::from_millis(50))
            .expect("second bounded recovery attempt");
        assert_eq!(second_attempt, started + Duration::from_millis(100));
        assert_eq!(same_deadline, deadline);
        tokio::time::advance(Duration::from_millis(50)).await;
        recovery.attempts += 1;
        assert_eq!(
            recovery.next_attempt_at(Duration::from_millis(150), 2, Duration::from_millis(50),),
            Err(SessionConsumerClientError::Unavailable),
        );
        recovery.reset();
        assert_eq!(recovery.attempts, 0);
        assert!(recovery.deadline.is_none());
    }

    fn spiffe(suffix: &str) -> SpiffeId {
        SpiffeId::new(format!(
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/{suffix}"
        ))
        .expect("test SPIFFE ID")
    }

    fn material_spiffe(suffix: &str) -> SpiffeId {
        SpiffeId::new(format!(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/consumer/instance/{suffix}"
        ))
        .expect("test material SPIFFE ID")
    }

    fn mutation_request(request_id: SessionConsumerRequestId) -> SessionConsumerRequest {
        SessionConsumerRequest::new(
            scope(),
            request_id,
            SessionConsumerOperation::AcquireLease {
                key: SessionKey {
                    tenant: TenantId::new("wire-test").expect("test tenant"),
                    nf_kind: NetworkFunctionKind::smf(),
                    key_type: SessionKeyType::PduSession,
                    stable_id: Bytes::from_static(b"opaque-session")
                        .try_into()
                        .expect("bounded stable ID"),
                },
                owner: OwnerId::new("wire-owner").expect("test owner"),
                ttl: Duration::from_secs(30),
            },
        )
    }

    struct PhaseFailWriter {
        accepted: usize,
        fail_after: Option<usize>,
        fail_flush: bool,
    }

    impl AsyncWrite for PhaseFailWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if let Some(fail_after) = self.fail_after {
                if self.accepted >= fail_after {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "controlled write failure",
                    )));
                }
                let accepted = bytes.len().min(fail_after - self.accepted);
                self.accepted += accepted;
                return Poll::Ready(Ok(accepted));
            }
            self.accepted += bytes.len();
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.fail_flush {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "controlled flush failure",
                )))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct PendingWriter;

    impl AsyncWrite for PendingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct SharedCountingWriter {
        accepted: Arc<AtomicUsize>,
    }

    impl AsyncWrite for SharedCountingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.accepted.fetch_add(bytes.len(), Ordering::SeqCst);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct PartialPendingWriter {
        accepted: Arc<AtomicUsize>,
        started: Arc<tokio::sync::Notify>,
        wrote_prefix: bool,
    }

    impl AsyncWrite for PartialPendingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.wrote_prefix {
                return Poll::Pending;
            }
            let accepted = bytes.len().min(2);
            self.accepted.fetch_add(accepted, Ordering::SeqCst);
            self.wrote_prefix = true;
            self.started.notify_waiters();
            Poll::Ready(Ok(accepted))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct GatedCountingReader {
        encoded: Vec<u8>,
        offset: usize,
        ready: Arc<AtomicBool>,
        accepted: Arc<AtomicUsize>,
    }

    impl AsyncRead for GatedCountingReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if !self.ready.load(Ordering::Acquire) {
                return Poll::Pending;
            }
            let remaining = &self.encoded[self.offset..];
            if remaining.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let amount = remaining.len().min(buffer.remaining());
            buffer.put_slice(&remaining[..amount]);
            self.offset = self.offset.saturating_add(amount);
            self.accepted.fetch_add(amount, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }

    fn install_shutdown_barrier(
        connection: &mut ConsumerConnection,
    ) -> Arc<PersistentConsumerIoBarrier> {
        let barrier = Arc::new(PersistentConsumerIoBarrier::new());
        let reader = std::mem::replace(&mut connection.reader, Box::new(tokio::io::empty()));
        connection.reader = Box::new(PersistentConsumerShutdownReader {
            inner: reader,
            barrier: Arc::clone(&barrier),
        });
        let writer = std::mem::replace(&mut connection.writer, Box::new(tokio::io::sink()));
        connection.writer = Box::new(PersistentConsumerShutdownWriter {
            inner: writer,
            barrier: Arc::clone(&barrier),
        });
        connection.shutdown_io = Some(Arc::clone(&barrier));
        barrier
    }

    fn stateless_test_client(
        control: SessionReauthenticationControl,
    ) -> (StatelessSessionConsumerClient, RotatableClientMaterial) {
        let material = RotatableClientMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/consumer/instance/client",
        );
        let client = StatelessSessionConsumerClient::new(
            "127.0.0.1:9".parse().expect("test socket address"),
            rustls_pki_types::ServerName::try_from("consumer.test").expect("test TLS server name"),
            spiffe("server"),
            scope(),
            material.config(),
        )
        .with_reauthentication_control(control);
        (client, material)
    }

    fn synthetic_consumer_connection(
        client: &StatelessSessionConsumerClient,
        idle_deadline: tokio::time::Instant,
        writer: Box<dyn AsyncWrite + Unpin + Send>,
    ) -> (ConsumerConnection, ConnectionLifecycle) {
        let established_at = tokio::time::Instant::now();
        let generation = client.reauthentication.generation();
        let material_epoch = client.tls_config.material_status().epoch();
        let lifecycle = ConnectionLifecycle::new(
            client.lifecycle_policy,
            established_at,
            None,
            None,
            generation,
            Some(material_epoch),
        )
        .expect("test lifecycle");
        let observed_lifecycle = lifecycle.clone();
        (
            ConsumerConnection {
                reader: Box::new(tokio::io::empty()),
                writer,
                lifecycle,
                rotation_edge_key: client
                    .tls_config
                    .begin_handshake()
                    .expect("test client handshake snapshot")
                    .directed_lifecycle_edge_key(b"consumer", &client.expected_server_identity),
                next_correlation: NonZeroU32::MIN,
                calls: 0,
                idle_deadline,
                request_frame_size: super::MAX_NEGOTIATED_FRAME_SIZE,
                shutdown_io: None,
                pool_connection: None,
                _physical_admission: None,
            },
            observed_lifecycle,
        )
    }

    async fn wait_for_raw_idle_count(client: &PersistentSessionConsumerClient, expected: usize) {
        for _ in 0..32 {
            let actual = client
                .pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len();
            if actual == expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        let actual = client
            .pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        assert_eq!(actual, expected, "raw idle storage did not converge");
    }

    async fn wait_for_idle_reaper_armed_deadline(
        client: &PersistentSessionConsumerClient,
        expected: tokio::time::Instant,
        label: &str,
    ) {
        for _ in 0..32 {
            let actual = *client
                .pool
                .test_hooks
                .idle_reaper_armed_deadline
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if actual == Some(expected) {
                return;
            }
            tokio::task::yield_now().await;
        }
        let actual = *client
            .pool
            .test_hooks
            .idle_reaper_armed_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(
            actual,
            Some(expected),
            "idle reaper did not arm the exact shortened lifecycle deadline ({label})"
        );
    }

    #[tokio::test]
    async fn mutation_write_phases_preserve_the_exact_effect_boundary() {
        let request_id = SessionConsumerRequestId::new();
        let request = mutation_request(request_id);
        let outbound = BorrowedConsumerWireRequest::Call(BorrowedConsumerCall {
            correlation: NonZeroU32::MIN,
            request: &request,
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);

        let mut before_write = PhaseFailWriter {
            accepted: 0,
            fail_after: None,
            fail_flush: false,
        };
        let error = crate::protocol::write_frame_bounded_until_classified(
            &mut before_write,
            &outbound,
            1,
            deadline,
        )
        .await
        .expect_err("oversize mutation must fail before the prefix");
        assert_eq!(before_write.accepted, 0);
        let classified = classify_call_write_error(error, false);
        let not_transmitted: Result<(), SessionConsumerLeaseMutationError> =
            lease_response(request_id, Err(classified), |_| None);
        assert!(matches!(
            not_transmitted,
            Err(SessionConsumerLeaseMutationError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol
            })
        ));

        for (phase, fail_after, fail_flush) in [
            ("partial_prefix", Some(2), false),
            ("partial_payload", Some(12), false),
            ("flush", None, true),
        ] {
            let mut writer = PhaseFailWriter {
                accepted: 0,
                fail_after,
                fail_flush,
            };
            let error = crate::protocol::write_frame_bounded_until_classified(
                &mut writer,
                &outbound,
                MAX_NEGOTIATED_FRAME_SIZE,
                deadline,
            )
            .await
            .expect_err("controlled phase must fail");
            let classified = classify_call_write_error(error, false);
            let outcome: Result<(), SessionConsumerLeaseMutationError> =
                lease_response(request_id, Err(classified), |_| None);
            assert!(matches!(
                outcome,
                Err(SessionConsumerLeaseMutationError::OutcomeUnknown { request_id: retry_id })
                    if retry_id == request_id
            ));
            assert!(writer.accepted > 0, "{phase} crossed the write boundary");
        }
    }

    #[test]
    fn persistent_effectful_helper_matrix_preserves_before_write_and_unknown_ids() {
        let before =
            SessionConsumerCallError::BeforeCallWrite(SessionConsumerClientError::Protocol);
        let may_have_sent =
            SessionConsumerCallError::MayHaveSent(SessionConsumerClientError::Deadline);
        for family in ["cas", "delete", "refresh", "mutating_batch"] {
            let request_id = SessionConsumerRequestId::new();
            assert!(
                matches!(
                    persistent_execute_error(request_id, before),
                    PersistentSessionConsumerExecuteError::NotTransmitted {
                        cause: SessionConsumerClientError::Protocol
                    }
                ),
                "{family} raw persistent execute remains safely retryable before write"
            );
            assert!(
                matches!(
                    mutation_response::<()>(request_id, Err(before), |_| None),
                    Err(SessionConsumerMutationError::NotTransmitted {
                        cause: SessionConsumerClientError::Protocol
                    })
                ),
                "{family} helper remains safely retryable before write"
            );
            assert!(matches!(
                persistent_execute_error(request_id, may_have_sent),
                PersistentSessionConsumerExecuteError::OutcomeUnknown { request_id: retry_id }
                    if retry_id == request_id
            ));
            assert!(
                matches!(
                    mutation_response::<()>(request_id, Err(may_have_sent), |_| None),
                    Err(SessionConsumerMutationError::OutcomeUnknown { request_id: retry_id })
                        if retry_id == request_id
                ),
                "{family} has no automatic replay after a possible write"
            );
        }
        for family in ["acquire", "renew", "release"] {
            let request_id = SessionConsumerRequestId::new();
            assert!(
                matches!(
                    lease_response::<()>(request_id, Err(before), |_| None),
                    Err(SessionConsumerLeaseMutationError::NotTransmitted {
                        cause: SessionConsumerClientError::Protocol
                    })
                ),
                "{family} helper remains safely retryable before write"
            );
            assert!(
                matches!(
                    lease_response::<()>(request_id, Err(may_have_sent), |_| None),
                    Err(SessionConsumerLeaseMutationError::OutcomeUnknown { request_id: retry_id })
                        if retry_id == request_id
                ),
                "{family} has no automatic replay after a possible write"
            );
        }
    }

    #[test]
    fn authority_and_malformed_rejections_have_explicit_lane_retirement_semantics() {
        for rejection in [
            SessionConsumerRejection::ScopeMismatch,
            SessionConsumerRejection::Unauthorized,
            SessionConsumerRejection::MalformedRequest,
        ] {
            assert!(response_retires_connection_authority(
                &SessionConsumerResponse::Rejected(rejection)
            ));
        }
        assert!(
            !response_retires_connection_authority(&SessionConsumerResponse::Rejected(
                SessionConsumerRejection::Unavailable,
            )),
            "pre-dispatch unavailability leaves the authenticated lane reusable"
        );
    }

    #[test]
    fn complete_lease_rejections_are_known_safe_not_outcome_unknown() {
        let request_id = SessionConsumerRequestId::new();
        for rejection in [
            SessionConsumerRejection::ScopeMismatch,
            SessionConsumerRejection::Unauthorized,
            SessionConsumerRejection::MalformedRequest,
            SessionConsumerRejection::Unavailable,
        ] {
            let outcome = lease_response::<()>(
                request_id,
                Ok(SessionConsumerResponse::Rejected(rejection)),
                |_| None,
            );
            assert!(
                matches!(outcome, Err(SessionConsumerLeaseMutationError::Lease(_))),
                "a complete {rejection:?} rejection proves the lease mutation was not dispatched"
            );
        }
    }

    #[tokio::test]
    async fn payload_fragment_preflight_is_an_exact_safe_lower_bound() {
        let key = SessionKey {
            tenant: TenantId::new("consumer-payload-preflight").expect("test tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"consumer-payload-preflight")
                .try_into()
                .expect("bounded stable ID"),
        };
        let owner = OwnerId::new("consumer-payload-owner").expect("test owner");
        let lease = FakeSessionBackend::new()
            .acquire(&key, owner.clone(), Duration::from_secs(30))
            .await
            .expect("test lease");
        let payload = [0, 9, 10, 99, 100, 255];
        let op = CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: None,
            new_record: StoredSessionRecord {
                key,
                generation: Generation::new(1),
                owner,
                fence: FenceToken::new(1),
                state_class: StateClass::AuthoritativeSession,
                state_type: StateType::from_static("consumer-payload-preflight"),
                expires_at: None,
                payload: EncryptedSessionPayload::new(payload),
            },
        };
        let single = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::CompareAndSet {
                op: Box::new(op.clone()),
            },
        );

        // `[0,9,10,99,100,255]` is exactly 19 bytes. Equality is retained for
        // the exact frame encoder; one byte below is provably impossible.
        assert!(!consumer_payload_fragments_exceed_frame(&single, 19));
        assert!(consumer_payload_fragments_exceed_frame(&single, 18));

        let batch = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::Batch {
                ops: vec![
                    SessionOp::CompareAndSet(op.clone()),
                    SessionOp::CompareAndSet(op),
                ],
            },
        );
        assert!(!consumer_payload_fragments_exceed_frame(&batch, 38));
        assert!(consumer_payload_fragments_exceed_frame(&batch, 37));
    }

    #[tokio::test]
    async fn official_consumer_error_families_remain_legal_and_cross_family_errors_do_not() {
        let key = SessionKey {
            tenant: TenantId::new("consumer-error-family").expect("test tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"consumer-error-family")
                .try_into()
                .expect("bounded stable ID"),
        };
        let owner = OwnerId::new("consumer-error-owner").expect("test owner");
        let backend = FakeSessionBackend::new();
        let lease = backend
            .acquire(&key, owner.clone(), Duration::from_secs(30))
            .await
            .expect("test lease");
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner,
            fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("consumer-error-family"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"opaque-test-payload"),
        };
        let cas = CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record,
        };

        for operation in [
            SessionConsumerOperation::Get { key: key.clone() },
            SessionConsumerOperation::PreflightRecordExpiry {
                preflights: Vec::new(),
            },
            SessionConsumerOperation::ScanRestoreRecords {
                request: RestoreScanRequest::all(1),
            },
        ] {
            assert!(
                store_error_matches_operation(&operation, SessionConsumerStoreError::StaleFence),
                "a mid-operation topology authority revocation is an official typed response"
            );
        }
        for operation in [
            SessionConsumerOperation::CompareAndSet {
                op: Box::new(cas.clone()),
            },
            SessionConsumerOperation::DeleteFenced {
                lease: lease.clone(),
            },
            SessionConsumerOperation::RefreshTtl {
                lease: lease.clone(),
                ttl: Duration::from_secs(30),
            },
        ] {
            assert!(
                store_error_matches_operation(
                    &operation,
                    SessionConsumerStoreError::LeaseUnavailable,
                ),
                "an expired presented guard is an official typed fenced-mutation response"
            );
        }
        for operation in [
            SessionConsumerOperation::CompareAndSet { op: Box::new(cas) },
            SessionConsumerOperation::DeleteFenced {
                lease: lease.clone(),
            },
        ] {
            assert!(store_error_matches_operation(
                &operation,
                SessionConsumerStoreError::NotFound,
            ));
        }
        assert!(super::batch_slot_error_matches_operation(
            &SessionOp::Get { key: key.clone() },
            SessionConsumerStoreError::StaleFence,
        ));
        assert!(store_error_matches_operation(
            &SessionConsumerOperation::Batch {
                ops: vec![SessionOp::Get { key: key.clone() }],
            },
            SessionConsumerStoreError::StaleFence,
        ));
        assert!(lease_error_matches_operation(
            &SessionConsumerOperation::RenewLease {
                lease: lease.clone(),
                ttl: Duration::from_secs(30),
            },
            SessionConsumerLeaseError::AlreadyHeld,
        ));
        assert!(lease_error_matches_operation(
            &SessionConsumerOperation::AcquireLease {
                key: key.clone(),
                owner: OwnerId::new("consumer-error-owner").expect("test owner"),
                ttl: Duration::from_secs(30),
            },
            SessionConsumerLeaseError::StaleFence,
        ));

        assert!(!store_error_matches_operation(
            &SessionConsumerOperation::Get { key: key.clone() },
            SessionConsumerStoreError::InvalidTtl,
        ));
        assert!(!lease_error_matches_operation(
            &SessionConsumerOperation::AcquireLease {
                key,
                owner: OwnerId::new("consumer-error-owner").expect("test owner"),
                ttl: Duration::from_secs(30),
            },
            SessionConsumerLeaseError::Expired,
        ));
    }

    #[test]
    fn revision_two_semantics_bind_ttl_records_batches_watches_and_future_operations() {
        fn lease_guard(
            key: SessionKey,
            owner: OwnerId,
            fence: FenceToken,
            acquired_at: Timestamp,
            expires_at: Timestamp,
            credential_id: u64,
        ) -> LeaseGuard {
            serde_json::from_value(serde_json::json!({
                "key": key,
                "owner": owner,
                "fence": fence,
                "acquired_at": acquired_at,
                "expires_at": expires_at,
                "credential_id": credential_id,
            }))
            .expect("public lease wire shape")
        }

        let key = SessionKey {
            tenant: TenantId::new("semantic-profile").expect("test tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"opaque-semantic-profile")
                .try_into()
                .expect("bounded stable ID"),
        };
        let owner = OwnerId::new("semantic-profile-owner").expect("test owner");
        let authority_time = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let ttl = Duration::from_secs(30);
        let exact_expiry = checked_session_deadline(authority_time, ttl).expect("exact expiry");
        let lease = lease_guard(
            key.clone(),
            owner.clone(),
            FenceToken::new(7),
            authority_time,
            exact_expiry,
            9,
        );
        let acquire = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::AcquireLease {
                key: key.clone(),
                owner: owner.clone(),
                ttl,
            },
        );
        assert!(response_matches_request(
            &acquire,
            &SessionConsumerResponse::AcquireLease(Ok(SessionConsumerLeaseGrant::new(
                lease.clone(),
                authority_time,
            ))),
        ));
        for wrong_ttl in [Duration::from_secs(29), Duration::from_secs(31)] {
            let wrong = lease_guard(
                key.clone(),
                owner.clone(),
                lease.fence(),
                authority_time,
                checked_session_deadline(authority_time, wrong_ttl).expect("wrong expiry"),
                lease.credential_id(),
            );
            assert!(!response_matches_request(
                &acquire,
                &SessionConsumerResponse::AcquireLease(Ok(SessionConsumerLeaseGrant::new(
                    wrong,
                    authority_time,
                ))),
            ));
        }

        let maximum_expiry =
            checked_session_deadline(authority_time, MAX_SESSION_TTL).expect("maximum expiry");
        let maximum = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::AcquireLease {
                key: key.clone(),
                owner: owner.clone(),
                ttl: MAX_SESSION_TTL,
            },
        );
        assert!(response_matches_request(
            &maximum,
            &SessionConsumerResponse::AcquireLease(Ok(SessionConsumerLeaseGrant::new(
                lease_guard(
                    key.clone(),
                    owner.clone(),
                    FenceToken::new(8),
                    authority_time,
                    maximum_expiry,
                    10,
                ),
                authority_time,
            ))),
        ));

        let zero = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::AcquireLease {
                key: key.clone(),
                owner: owner.clone(),
                ttl: Duration::ZERO,
            },
        );
        assert!(response_matches_request(
            &zero,
            &SessionConsumerResponse::AcquireLease(Ok(SessionConsumerLeaseGrant::new(
                lease_guard(
                    key.clone(),
                    owner.clone(),
                    FenceToken::new(9),
                    authority_time,
                    authority_time,
                    11,
                ),
                authority_time,
            ))),
        ));

        let renewal_authority = authority_time.add_seconds(10).expect("renewal authority");
        let renewed_expiry =
            checked_session_deadline(renewal_authority, ttl).expect("renewed expiry");
        let renewed = lease_guard(
            key.clone(),
            owner.clone(),
            lease.fence(),
            lease.acquired_at(),
            renewed_expiry,
            lease.credential_id(),
        );
        let renew = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::RenewLease {
                lease: lease.clone(),
                ttl,
            },
        );
        assert!(response_matches_request(
            &renew,
            &SessionConsumerResponse::RenewLease(Ok(SessionConsumerLeaseGrant::new(
                renewed.clone(),
                renewal_authority,
            ))),
        ));
        assert!(!response_matches_request(
            &renew,
            &SessionConsumerResponse::RenewLease(Ok(SessionConsumerLeaseGrant::new(
                lease.clone(),
                authority_time,
            ))),
        ));
        assert!(!response_matches_request(
            &renew,
            &SessionConsumerResponse::RenewLease(Ok(SessionConsumerLeaseGrant::new(
                renewed,
                authority_time,
            ))),
        ));

        let invalid_record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner: owner.clone(),
            fence: lease.fence(),
            state_class: StateClass::EphemeralProcedure,
            state_type: StateType::from_static("invalid-immortal-ephemeral"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"opaque"),
        };
        let get = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::Get { key: key.clone() },
        );
        assert!(!response_matches_request(
            &get,
            &SessionConsumerResponse::Get(Ok(Some(invalid_record.clone()))),
        ));
        let cas = CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: StoredSessionRecord {
                state_class: StateClass::AuthoritativeSession,
                ..invalid_record.clone()
            },
        };
        let cas_request = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::CompareAndSet {
                op: Box::new(cas.clone()),
            },
        );
        assert!(!response_matches_request(
            &cas_request,
            &SessionConsumerResponse::CompareAndSet(Ok(CompareAndSetResult::Conflict {
                current: Some(invalid_record.clone()),
            })),
        ));
        let batch_get = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::Batch {
                ops: vec![SessionOp::Get { key: key.clone() }],
            },
        );
        assert!(!response_matches_request(
            &batch_get,
            &SessionConsumerResponse::Batch(Ok(vec![SessionConsumerBatchResult::Get(Ok(Some(
                invalid_record.clone(),
            )))])),
        ));
        let mut restore_page = RestoreScanPage::new(vec![invalid_record], 0, None);
        restore_page.cursor_profile = RestoreScanCursorProfile::DurableOpaqueV1;
        let restore = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::ScanRestoreRecords {
                request: RestoreScanRequest::all(1),
            },
        );
        assert!(!response_matches_request(
            &restore,
            &SessionConsumerResponse::ScanRestoreRecords(Ok(restore_page)),
        ));

        let mutating_batch = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::Batch {
                ops: vec![SessionOp::CompareAndSet(cas)],
            },
        );
        let nested_unknown =
            SessionConsumerResponse::Batch(Ok(vec![SessionConsumerBatchResult::CompareAndSet(
                Err(SessionConsumerStoreError::OutcomeUnavailable),
            )]));
        assert!(response_matches_request(&mutating_batch, &nested_unknown));
        assert!(response_is_outcome_unknown(
            mutating_batch.operation(),
            &nested_unknown,
        ));
        let read_unavailable =
            SessionConsumerResponse::Batch(Err(SessionConsumerStoreError::Unavailable));
        assert!(response_matches_request(&batch_get, &read_unavailable));
        assert!(!response_is_outcome_unknown(
            batch_get.operation(),
            &read_unavailable,
        ));

        for legal in [
            SessionConsumerStoreError::StaleFence,
            SessionConsumerStoreError::Unavailable,
            SessionConsumerStoreError::InvalidInput,
            SessionConsumerStoreError::WatchCatchUpRequired,
            SessionConsumerStoreError::ProtectedDataRejected,
        ] {
            assert!(consumer_watch_error_is_legal(legal));
        }
        for illegal in [
            SessionConsumerStoreError::CasConflict,
            SessionConsumerStoreError::RequestConflict,
            SessionConsumerStoreError::OutcomeUnavailable,
            SessionConsumerStoreError::InvalidTtl,
            SessionConsumerStoreError::RestoreRejected,
        ] {
            assert!(!consumer_watch_error_is_legal(illegal));
        }

        assert!(!response_matches_operation(
            ConsumerOperationKind::UnknownEffectful,
            &SessionConsumerResponse::CompareAndSet(Ok(CompareAndSetResult::Success)),
        ));
        assert!(response_matches_operation(
            ConsumerOperationKind::UnknownEffectful,
            &SessionConsumerResponse::OutcomeUnknown(SessionConsumerOutcomeUnknown::Mutation),
        ));
        assert!(response_matches_operation(
            ConsumerOperationKind::UnknownEffectful,
            &SessionConsumerResponse::Rejected(SessionConsumerRejection::MalformedRequest),
        ));
    }

    #[test]
    fn consumer_capabilities_use_the_fixed_width_checked_wire_dto() {
        let mut capabilities = BackendCapabilities::all_enabled();
        capabilities.max_value_bytes = usize::MAX;
        let response = ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation: NonZeroU32::MIN,
            response: Box::new(SessionConsumerResponse::Capabilities(capabilities)),
        });
        let encoded = serde_json::to_value(&response).expect("consumer capabilities encode");
        assert_eq!(
            encoded["body"]["response"]["body"]["max_value_bytes"],
            u64::try_from(usize::MAX).expect("supported pointer width"),
        );
        let encoded = serde_json::to_vec(&response).expect("consumer capabilities encode");
        let decoded = decode_consumer_frame_payload::<ConsumerWireResponse>(&encoded)
            .expect("consumer capabilities decode");
        assert!(matches!(
            decoded,
            ConsumerWireResponse::Response(ConsumerCallResponse {
                response,
                ..
            }) if matches!(*response, SessionConsumerResponse::Capabilities(BackendCapabilities {
                max_value_bytes: usize::MAX,
                ..
            }))
        ));
    }

    #[test]
    fn borrowed_revision_two_envelopes_are_wire_identical() {
        let request = mutation_request(SessionConsumerRequestId::new());
        let owned_request = ConsumerWireRequest::Call(ConsumerCall {
            correlation: NonZeroU32::MIN,
            request: Box::new(request.clone()),
        });
        let borrowed_request = BorrowedConsumerWireRequest::Call(BorrowedConsumerCall {
            correlation: NonZeroU32::MIN,
            request: &request,
        });
        assert_eq!(
            serde_json::to_vec(&owned_request).expect("owned request encodes"),
            serde_json::to_vec(&borrowed_request).expect("borrowed request encodes")
        );

        let response = SessionConsumerResponse::Capabilities(BackendCapabilities::all_enabled());
        let owned_response = ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation: NonZeroU32::MIN,
            response: Box::new(response.clone()),
        });
        let borrowed_response =
            BorrowedConsumerWireResponse::Response(BorrowedConsumerCallResponse {
                correlation: NonZeroU32::MIN,
                response: SerializableConsumerResponse(&response),
            });
        assert_eq!(
            serde_json::to_vec(&owned_response).expect("owned response encodes"),
            serde_json::to_vec(&borrowed_response).expect("borrowed response encodes")
        );
    }

    #[test]
    fn consumer_and_member_roles_are_structurally_disjoint() {
        let shared = spiffe("shared");
        assert!(matches!(
            SessionConsumerAuthorizer::from_authoritative_members(
                scope(),
                [shared.clone()],
                [shared.as_str().to_owned()],
            ),
            Err(SessionConsumerAuthorizationError::MemberRoleConflict)
        ));

        let consumer = spiffe("application");
        let member = spiffe("member");
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [consumer.clone()],
            [member.as_str().to_owned()],
        )
        .expect("disjoint roles are valid");
        assert_eq!(
            authorizer
                .authorize(&consumer)
                .expect("consumer is authorized")
                .as_str(),
            consumer.as_str()
        );
        assert!(authorizer.authorize(&member).is_err());
        assert!(authorizer.authorize(&spiffe("untrusted")).is_err());

        let debug = format!("{authorizer:?}");
        assert!(!debug.contains(consumer.as_str()));
        assert!(!debug.contains(member.as_str()));
    }

    #[test]
    fn consumer_decoder_rejects_unknown_shared_dto_fields() {
        let response = ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation: NonZeroU32::MIN,
            response: Box::new(SessionConsumerResponse::Capabilities(
                BackendCapabilities::all_enabled(),
            )),
        });
        let mut encoded = serde_json::to_value(response).expect("consumer response encodes");
        encoded["body"]["Capabilities"]["unexpected"] = serde_json::Value::Bool(true);
        let payload = serde_json::to_vec(&encoded).expect("JSON payload");
        assert!(decode_consumer_frame_payload::<ConsumerWireResponse>(&payload).is_err());
    }

    #[test]
    fn consumer_decoder_accepts_only_the_canonical_private_encoding() {
        let response = ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation: NonZeroU32::MIN,
            response: Box::new(SessionConsumerResponse::Capabilities(
                BackendCapabilities::all_enabled(),
            )),
        });
        let canonical = serde_json::to_vec(&response).expect("consumer response encodes");
        assert!(decode_consumer_frame_payload::<ConsumerWireResponse>(&canonical).is_ok());

        let mut noncanonical = Vec::with_capacity(canonical.len().saturating_add(1));
        noncanonical.push(b' ');
        noncanonical.extend_from_slice(&canonical);
        assert!(decode_consumer_frame_payload::<ConsumerWireResponse>(&noncanonical).is_err());
    }

    #[test]
    fn consumer_decoder_rejects_trailing_json_values() {
        let response = ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation: NonZeroU32::MIN,
            response: Box::new(SessionConsumerResponse::Capabilities(
                BackendCapabilities::all_enabled(),
            )),
        });
        let mut payload = serde_json::to_vec(&response).expect("consumer response encodes");
        payload.extend_from_slice(br#"{}"#);
        assert!(decode_consumer_frame_payload::<ConsumerWireResponse>(&payload).is_err());
    }

    #[test]
    fn correlation_sequence_and_response_kind_fail_closed() {
        let one = NonZeroU32::MIN;
        let two = NonZeroU32::new(2).expect("nonzero correlation");
        assert!(exact_correlation(one, one).is_ok());
        assert!(exact_correlation(one, two).is_err(), "future correlation");
        assert!(
            exact_correlation(two, one).is_err(),
            "duplicate or late correlation"
        );

        let response = ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation: one,
            response: Box::new(SessionConsumerResponse::Capabilities(
                BackendCapabilities::all_enabled(),
            )),
        });
        let mut zero = serde_json::to_value(response).expect("consumer response encodes");
        zero["body"]["correlation"] = serde_json::Value::from(0);
        let zero = serde_json::to_vec(&zero).expect("zero-correlation payload encodes");
        assert!(
            decode_consumer_frame_payload::<ConsumerWireResponse>(&zero).is_err(),
            "zero is not a representable wire correlation"
        );
        assert!(!response_matches_operation(
            ConsumerOperationKind::Capabilities,
            &SessionConsumerResponse::Get(Ok(None)),
        ));
    }

    #[test]
    fn persistent_config_rejects_every_unbounded_dimension() {
        let config = |request_connections,
                      pending_calls,
                      pool_wait_timeout,
                      watch_connections,
                      setup_timeout,
                      connect_attempts,
                      reconnect_jitter,
                      shutdown_drain| {
            PersistentSessionConsumerConfig::try_new(
                request_connections,
                pending_calls,
                pool_wait_timeout,
                watch_connections,
                setup_timeout,
                connect_attempts,
                reconnect_jitter,
                shutdown_drain,
            )
        };
        let (requests, pending, wait, watches, setup, attempts, jitter, drain) = (
            DEFAULT_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_PENDING_CALLS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_RECONNECT_JITTER,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        );
        assert!(config(requests, pending, wait, watches, setup, attempts, jitter, drain).is_ok());
        for (invalid_requests, invalid_pending, invalid_watches) in [
            (0, pending, watches),
            (
                MAX_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS + 1,
                pending,
                watches,
            ),
            (
                requests,
                MAX_PERSISTENT_SESSION_CONSUMER_PENDING_CALLS + 1,
                watches,
            ),
            (
                requests,
                pending,
                MAX_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS + 1,
            ),
            (requests, pending, 0),
        ] {
            assert_eq!(
                config(
                    invalid_requests,
                    invalid_pending,
                    wait,
                    invalid_watches,
                    setup,
                    attempts,
                    jitter,
                    drain,
                ),
                Err(PersistentSessionConsumerConfigError::Capacity)
            );
        }
        for (invalid_wait, invalid_setup, invalid_attempts, invalid_jitter, invalid_drain) in [
            (Duration::ZERO, setup, attempts, jitter, drain),
            (
                wait + Duration::from_millis(1),
                setup,
                attempts,
                jitter,
                drain,
            ),
            (wait, Duration::ZERO, attempts, jitter, drain),
            (
                wait,
                setup + Duration::from_millis(1),
                attempts,
                jitter,
                drain,
            ),
            (wait, setup, 0, jitter, drain),
            (wait, setup, attempts + 1, jitter, drain),
            (
                wait,
                setup,
                attempts,
                jitter + Duration::from_millis(1),
                drain,
            ),
            (wait, setup, attempts, jitter, Duration::ZERO),
            (
                wait,
                setup,
                attempts,
                jitter,
                drain + Duration::from_millis(1),
            ),
        ] {
            assert_eq!(
                config(
                    requests,
                    pending,
                    invalid_wait,
                    watches,
                    invalid_setup,
                    invalid_attempts,
                    invalid_jitter,
                    invalid_drain,
                ),
                Err(PersistentSessionConsumerConfigError::Timing)
            );
        }
    }

    #[tokio::test]
    async fn consumer_operation_timeout_accepts_exact_limit_and_rejects_one_over() {
        assert!(valid_consumer_operation_timeout(
            DEFAULT_CONSUMER_OPERATION_TIMEOUT
        ));
        assert!(!valid_consumer_operation_timeout(
            DEFAULT_CONSUMER_OPERATION_TIMEOUT + Duration::from_nanos(1)
        ));
        assert!(!valid_consumer_operation_timeout(Duration::ZERO));

        let control = SessionReauthenticationControl::new();
        let (client, _material) = stateless_test_client(control);
        assert!(PersistentSessionConsumerClient::try_from_stateless(
            client
                .clone()
                .with_operation_timeout(DEFAULT_CONSUMER_OPERATION_TIMEOUT),
            PersistentSessionConsumerConfig::default(),
        )
        .is_ok());
        assert!(matches!(
            PersistentSessionConsumerClient::try_from_stateless(
                client.with_operation_timeout(
                    DEFAULT_CONSUMER_OPERATION_TIMEOUT + Duration::from_nanos(1),
                ),
                PersistentSessionConsumerConfig::default(),
            ),
            Err(PersistentSessionConsumerConfigError::Timing)
        ));

        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let resolving = Arc::clone(&resolver_calls);
        let control = SessionReauthenticationControl::new();
        let (_base, material) = stateless_test_client(control);
        let client = StatelessSessionConsumerClient::new_with_resolver(
            Arc::new(move || {
                resolving.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok("127.0.0.1:9".parse().expect("test address")) })
            }),
            rustls_pki_types::ServerName::try_from("consumer.test").expect("test TLS server name"),
            spiffe("server"),
            scope(),
            material.config(),
        )
        .with_operation_timeout(DEFAULT_CONSUMER_OPERATION_TIMEOUT + Duration::from_nanos(1));
        assert_eq!(
            client.capabilities().await,
            Err(SessionConsumerClientError::Protocol)
        );
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);

        let server_material = RotatableServerMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/consumer/instance/server",
        );
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [spiffe("application")],
            std::iter::empty(),
        )
        .expect("test authorizer");
        assert!(SessionQuorumConsumerServer::new(
            Arc::new(RejectingTestConsumer),
            server_material.config(),
            authorizer.clone(),
        )
        .with_operation_timeout(DEFAULT_CONSUMER_OPERATION_TIMEOUT)
        .validate()
        .is_ok());
        let error = SessionQuorumConsumerServer::new(
            Arc::new(RejectingTestConsumer),
            server_material.config(),
            authorizer,
        )
        .with_operation_timeout(DEFAULT_CONSUMER_OPERATION_TIMEOUT + Duration::from_nanos(1))
        .validate()
        .expect_err("one nanosecond over the server operation cap is rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn listener_setup_uses_one_accept_to_ack_deadline_across_tls_and_hello() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("setup-client");
        let server_identity = material_spiffe("setup-server");
        let client_material = RotatableClientMaterial::new(client_identity.as_str());
        let hooks = Arc::new(ConsumerServerSetupTestHooks::new());
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity],
            std::iter::empty(),
        )
        .expect("consumer setup authorizer");
        let (server, address) = SessionQuorumConsumerServer::new(
            Arc::new(RejectingTestConsumer),
            client_material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .with_operation_timeout(Duration::from_millis(500))
        .with_setup_test_hooks(Arc::clone(&hooks))
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for setup-deadline test");

        let tcp = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect setup client");
        hooks.accepted.notified().await;
        hooks.continue_after_accept.notify_one();

        let handshake = client_material
            .config()
            .begin_handshake()
            .expect("client setup handshake snapshot");
        let connector = tokio_rustls::TlsConnector::from(super::consumer_client_tls_config(
            handshake.rustls_config(),
        ));
        let server_name = rustls_pki_types::ServerName::IpAddress(address.ip().into());
        let tls_task = tokio::spawn(async move { connector.connect(server_name, tcp).await });
        hooks.tls_complete.notified().await;
        let mut tls = tls_task
            .await
            .expect("client TLS task")
            .expect("TLS completes within the first setup phase");

        // Freeze only after the real TCP/TLS exchange has completed, then
        // consume the exact remaining absolute budget while the server is
        // paused between TLS and Hello. This avoids wall-clock sensitivity
        // while proving the next phase receives no fresh timeout.
        tokio::time::pause();
        tokio::time::advance(Duration::from_millis(500)).await;
        // At the exact absolute boundary a newly supplied complete Hello must
        // not receive an Ack. A phase-reset implementation would grant a new
        // 500 ms read/write budget and publish the lane.
        hooks.continue_after_tls.notify_one();
        let _ = super::write_frame_bounded_until(
            &mut tls,
            &ConsumerWireRequest::Hello(super::ConsumerHello {
                transport_revision: super::SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
                scope: scope(),
                response_frame_size: u32::try_from(super::MAX_NEGOTIATED_FRAME_SIZE)
                    .expect("test frame size fits u32"),
            }),
            super::MAX_NEGOTIATED_FRAME_SIZE,
            tokio::time::Instant::now() + Duration::from_millis(10),
        )
        .await;
        let response = tokio::time::timeout(
            Duration::from_millis(10),
            super::read_consumer_frame::<_, ConsumerWireResponse>(
                &mut tls,
                super::MAX_NEGOTIATED_FRAME_SIZE,
            ),
        )
        .await;
        assert!(
            !matches!(response, Ok(Ok(ConsumerWireResponse::HelloAck(_)))),
            "no complete HelloAck crosses the absolute setup boundary"
        );
        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn final_admission_samples_reject_rotated_client_and_server_handshakes() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("application-0");
        let server_identity = material_spiffe("server");

        let client_material = Arc::new(RotatableClientMaterial::new(client_identity.as_str()));
        let client_side_dispatches = Arc::new(AtomicUsize::new(0));
        let client_side_service = Arc::new(CountingRejectingTestConsumer {
            calls: Arc::clone(&client_side_dispatches),
        });
        let client_side_authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity.clone()],
            std::iter::empty(),
        )
        .expect("consumer final-admission authorizer");
        let (client_side_server, client_side_address) = SessionQuorumConsumerServer::new(
            client_side_service,
            client_material.trusted_server_config(server_identity.as_str()),
            client_side_authorizer,
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for client final-admission race");
        let client_hook_calls = Arc::new(AtomicUsize::new(0));
        let client_hook_material = Arc::clone(&client_material);
        let client_hook_count = Arc::clone(&client_hook_calls);
        let client = StatelessSessionConsumerClient::new(
            client_side_address,
            rustls_pki_types::ServerName::IpAddress(client_side_address.ip().into()),
            server_identity.clone(),
            scope(),
            client_material.config(),
        )
        .with_final_admission_test_hook(Arc::new(move || {
            client_hook_count.fetch_add(1, Ordering::SeqCst);
            client_hook_material.rotate();
        }));
        let client_result = tokio::time::timeout(Duration::from_secs(1), client.capabilities())
            .await
            .expect("client final-admission race stays bounded");
        assert_eq!(client_result, Err(SessionConsumerClientError::Deadline));
        assert_eq!(client_hook_calls.load(Ordering::SeqCst), 1);
        assert_eq!(client_side_dispatches.load(Ordering::SeqCst), 0);
        client_side_server.abort_and_wait().await;

        let server_material = Arc::new(RotatableServerMaterial::new(server_identity.as_str()));
        let server_config = server_material.config();
        let server_edge_jitter = server_config
            .begin_handshake()
            .expect("server final-admission handshake snapshot")
            .directed_lifecycle_edge_key(b"consumer", &client_identity)
            .bounded_jitter(ConnectionLifecyclePolicy::default().rotation_jitter());
        assert!(
            server_edge_jitter > Duration::from_secs(1),
            "a missing final admission check cannot retire this admitted test edge inside the observation bound"
        );
        let server_side_dispatches = Arc::new(AtomicUsize::new(0));
        let server_side_service = Arc::new(CountingRejectingTestConsumer {
            calls: Arc::clone(&server_side_dispatches),
        });
        let server_side_authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity.clone()],
            std::iter::empty(),
        )
        .expect("consumer final-admission authorizer");
        let server_hook_calls = Arc::new(AtomicUsize::new(0));
        let server_hook_material = Arc::clone(&server_material);
        let server_hook_count = Arc::clone(&server_hook_calls);
        let (server_side_server, server_side_address) = SessionQuorumConsumerServer::new(
            server_side_service,
            server_config,
            server_side_authorizer,
        )
        .with_final_admission_test_hook(Arc::new(move || {
            server_hook_count.fetch_add(1, Ordering::SeqCst);
            server_hook_material.rotate();
        }))
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for server final-admission race");
        let client = StatelessSessionConsumerClient::new(
            server_side_address,
            rustls_pki_types::ServerName::IpAddress(server_side_address.ip().into()),
            server_identity,
            scope(),
            server_material.trusted_client_config(client_identity.as_str()),
        );
        let server_result = tokio::time::timeout(Duration::from_secs(1), client.capabilities())
            .await
            .expect("server final-admission race stays bounded");
        assert_eq!(server_result, Err(SessionConsumerClientError::Unavailable));
        assert_eq!(server_hook_calls.load(Ordering::SeqCst), 1);
        assert_eq!(server_side_dispatches.load(Ordering::SeqCst), 0);
        server_side_server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn server_lifecycle_expiry_at_final_boundary_publishes_no_hello_ack() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("ack-expiry-client");
        let server_identity = material_spiffe("ack-expiry-server");
        let server_material = RotatableServerMaterial::new(server_identity.as_str());
        let dispatches = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(CountingRejectingTestConsumer {
            calls: Arc::clone(&dispatches),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity.clone()],
            std::iter::empty(),
        )
        .expect("consumer Ack-expiry authorizer");
        let (server, address) =
            SessionQuorumConsumerServer::new(service, server_material.config(), authorizer)
                .with_expiry_at_final_ack_boundary()
                .listen("127.0.0.1:0".parse().expect("loopback address"))
                .await
                .expect("listen for Ack-expiry boundary");
        let client = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            server_material.trusted_client_config(client_identity.as_str()),
        );
        let result = tokio::time::timeout(Duration::from_secs(1), client.capabilities())
            .await
            .expect("expired Ack boundary closes promptly");
        assert_eq!(result, Err(SessionConsumerClientError::Unavailable));
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);
        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn service_authority_rejection_closes_before_a_second_correlation_dispatch() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("service-rejection-client");
        let server_identity = material_spiffe("service-rejection-server");
        let client_material = RotatableClientMaterial::new(client_identity.as_str());
        let calls = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(AuthorityRejectingTestConsumer {
            calls: Arc::clone(&calls),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity.clone()],
            std::iter::empty(),
        )
        .expect("consumer authority-rejection authorizer");
        let (server, address) = SessionQuorumConsumerServer::new(
            service,
            client_material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for service authority rejection");
        let client = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            client_material.config(),
        );
        let setup_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut connection = client
            .connect(setup_deadline, false, None, false, None)
            .await
            .expect("authenticate one raw retained consumer lane");
        let first = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::from_bytes([0x31; 16]),
            SessionConsumerOperation::Capabilities,
        );
        let first_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        assert_eq!(
            client
                .execute_on_connection(
                    &mut connection,
                    &first,
                    first_deadline,
                    false,
                    first_deadline,
                    None,
                )
                .await,
            Ok(SessionConsumerResponse::Rejected(
                SessionConsumerRejection::Unauthorized
            ))
        );

        let second = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::from_bytes([0x32; 16]),
            SessionConsumerOperation::Capabilities,
        );
        let second_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        assert!(
            client
                .execute_on_connection(
                    &mut connection,
                    &second,
                    second_deadline,
                    false,
                    second_deadline,
                    None,
                )
                .await
                .is_err(),
            "the service authority rejection retires the TLS lane before correlation two"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the service is not re-entered after an authority rejection"
        );
        server.abort_and_wait().await;
    }

    #[test]
    fn stateless_clone_lineage_bounds_physical_request_and_watch_connections() {
        let control = SessionReauthenticationControl::new();
        let (client, _material) = stateless_test_client(control);
        let clone = client.clone();
        let mut requests = Vec::new();
        for _ in 0..MAX_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS {
            requests.push(
                client
                    .physical_admission
                    .try_acquire(false)
                    .expect("configured request cap admits its exact bound"),
            );
        }
        assert!(
            matches!(
                clone.physical_admission.try_acquire(false),
                Err(SessionConsumerClientError::Overloaded)
            ),
            "clones share request physical admission before resolve or write"
        );
        assert!(
            clone.physical_admission.try_acquire(true).is_ok(),
            "watch physical admission is isolated from normal request lanes"
        );
        drop(requests);
    }

    #[test]
    fn cancelled_setup_attempts_terminalize_every_fixed_phase_exactly_once() {
        for phase in [
            ConsumerSetupPhase::Resolve,
            ConsumerSetupPhase::Tcp,
            ConsumerSetupPhase::Tls,
            ConsumerSetupPhase::Hello,
        ] {
            let counters = PersistentConsumerCounters::default();
            drop(ConsumerSetupPhaseAttempt::begin(Some(&counters), phase));

            let diagnostics = [
                (
                    counters.resolve_attempts.load(Ordering::Relaxed),
                    counters.resolve_failures.load(Ordering::Relaxed),
                ),
                (
                    counters.tcp_attempts.load(Ordering::Relaxed),
                    counters.tcp_failures.load(Ordering::Relaxed),
                ),
                (
                    counters.tls_attempts.load(Ordering::Relaxed),
                    counters.tls_failures.load(Ordering::Relaxed),
                ),
                (
                    counters.hello_attempts.load(Ordering::Relaxed),
                    counters.hello_failures.load(Ordering::Relaxed),
                ),
            ];
            let expected_index = match phase {
                ConsumerSetupPhase::Resolve => 0,
                ConsumerSetupPhase::Tcp => 1,
                ConsumerSetupPhase::Tls => 2,
                ConsumerSetupPhase::Hello => 3,
            };
            for (index, (attempts, failures)) in diagnostics.into_iter().enumerate() {
                let expected = u64::from(index == expected_index);
                assert_eq!(attempts, expected, "only the selected phase starts");
                assert_eq!(failures, expected, "a dropped phase terminates once");
            }
        }

        let counters = PersistentConsumerCounters::default();
        drop(PersistentSetupAttempt::begin(&counters));
        assert_eq!(counters.setup_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(counters.setup_successes.load(Ordering::Relaxed), 0);
        assert_eq!(counters.setup_failures.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn consumer_mutation_outcome_errors_preserve_the_exact_retry_id() {
        let request_id = SessionConsumerRequestId::new();
        let mutation = mutation_response(
            request_id,
            Ok(SessionConsumerResponse::DeleteFenced(Err(
                SessionConsumerStoreError::OutcomeUnavailable,
            ))),
            |response| match response {
                SessionConsumerResponse::DeleteFenced(result) => Some(result),
                _ => None,
            },
        );
        assert!(matches!(
            mutation,
            Err(SessionConsumerMutationError::OutcomeUnknown { request_id: retry_id })
                if retry_id == request_id
        ));

        let lease = lease_response(
            request_id,
            Ok(SessionConsumerResponse::AcquireLease(Err(
                SessionConsumerLeaseError::OutcomeUnavailable,
            ))),
            |response| match response {
                SessionConsumerResponse::AcquireLease(result) => Some(result.map(|_| ())),
                _ => None,
            },
        );
        assert!(matches!(
            lease,
            Err(SessionConsumerLeaseMutationError::OutcomeUnknown { request_id: retry_id })
                if retry_id == request_id
        ));
    }

    #[test]
    fn consumer_call_effect_boundary_distinguishes_known_unsent_from_unknown() {
        let request_id = SessionConsumerRequestId::new();
        let unsent: Result<(), SessionConsumerMutationError> = mutation_response(
            request_id,
            Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Unavailable,
            )),
            |_| None,
        );
        assert!(matches!(
            unsent,
            Err(SessionConsumerMutationError::NotTransmitted {
                cause: SessionConsumerClientError::Unavailable
            })
        ));

        let uncertain: Result<(), SessionConsumerMutationError> = mutation_response(
            request_id,
            Err(SessionConsumerCallError::MayHaveSent(
                SessionConsumerClientError::Unavailable,
            )),
            |_| None,
        );
        assert!(matches!(
            uncertain,
            Err(SessionConsumerMutationError::OutcomeUnknown { request_id: retry_id })
                if retry_id == request_id
        ));

        let unsent_lease: Result<(), SessionConsumerLeaseMutationError> = lease_response(
            request_id,
            Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Deadline,
            )),
            |_| None,
        );
        assert!(matches!(
            unsent_lease,
            Err(SessionConsumerLeaseMutationError::NotTransmitted {
                cause: SessionConsumerClientError::Deadline
            })
        ));

        assert!(matches!(
            classify_call_write_error(
                crate::protocol::FrameWriteError::BeforeWrite(crate::ProtocolError::FrameTooLarge(
                    1
                ),),
                false,
            ),
            SessionConsumerCallError::BeforeCallWrite(SessionConsumerClientError::Protocol)
        ));
        assert!(matches!(
            classify_call_write_error(
                crate::protocol::FrameWriteError::MayHaveWritten(crate::ProtocolError::Io(
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "redacted test failure",),
                )),
                false,
            ),
            SessionConsumerCallError::MayHaveSent(SessionConsumerClientError::Deadline)
        ));
        assert!(matches!(
            classify_call_write_error(
                crate::protocol::FrameWriteError::BeforeWrite(crate::ProtocolError::Io(
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "redacted test failure",),
                )),
                true,
            ),
            SessionConsumerCallError::BeforeCallWrite(SessionConsumerClientError::Unavailable)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn restrictive_pre_request_budget_is_checked_at_the_call_boundary() {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        assert_eq!(ensure_pre_request_budget_remaining(deadline, true), Ok(()));

        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        assert_eq!(
            ensure_pre_request_budget_remaining(deadline, true),
            Err(SessionConsumerClientError::Unavailable)
        );
        assert_eq!(
            ensure_pre_request_budget_remaining(deadline, false),
            Ok(()),
            "the default operation deadline retains its existing write classification"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn zero_byte_watch_write_uses_the_pre_request_unavailable_classification() {
        let control = SessionReauthenticationControl::new();
        let (client, _material) = stateless_test_client(control.clone());
        let (mut connection, _) = synthetic_consumer_connection(
            &client,
            tokio::time::Instant::now() + Duration::from_secs(5),
            Box::new(PendingWriter),
        );
        let request = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::Watch { start_sequence: 0 },
        );
        let mut reauthentication_changes = control.subscribe();
        let mut material_changes = Some(client.tls_config.subscribe_material_changes());
        let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
        let write = client.write_watch_call_on_connection(
            &mut connection,
            &request,
            deadline,
            true,
            &mut reauthentication_changes,
            &mut material_changes,
        );
        tokio::pin!(write);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(write.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_millis(10)).await;
        assert_eq!(
            write.await,
            Err(SessionConsumerClientError::Unavailable),
            "a zero-byte setup-budget expiry remains proven not transmitted"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn late_setup_and_pool_permit_are_rejected_before_publication() {
        let setup_ready = std::sync::Arc::new(tokio::sync::Notify::new());
        let setup_signal = std::sync::Arc::clone(&setup_ready);
        let setup_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut setup = Box::pin(async move {
            setup_signal.notified().await;
        });
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(setup.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_secs(1)).await;
        setup_ready.notify_one();
        setup.await;
        let dispatched = std::sync::atomic::AtomicBool::new(false);
        let setup_result =
            complete_before_deadline((), setup_deadline, SessionConsumerClientError::Unavailable);
        if setup_result.is_ok() {
            dispatched.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        assert_eq!(
            setup_result,
            Err(SessionConsumerClientError::Unavailable),
            "late setup must remain NotTransmitted"
        );
        assert!(!dispatched.load(std::sync::atomic::Ordering::SeqCst));

        let lanes = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        let lane_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut acquisition = Box::pin(tokio::time::timeout_at(
            lane_deadline,
            std::sync::Arc::clone(&lanes).acquire_owned(),
        ));
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(acquisition.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_secs(1)).await;
        lanes.add_permits(1);
        let late_permit = acquisition
            .await
            .expect("locked Tokio polls the ready semaphore before the elapsed timer")
            .expect("test semaphore remains open");
        assert!(matches!(
            complete_before_deadline(
                late_permit,
                lane_deadline,
                SessionConsumerClientError::Overloaded,
            ),
            Err(SessionConsumerClientError::Overloaded)
        ));
        assert_eq!(
            lanes.available_permits(),
            1,
            "a late acquisition is dropped instead of being published"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn idle_reaper_physically_retires_without_a_pruning_api() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let control = SessionReauthenticationControl::new();
        let (stateless, material) = stateless_test_client(control.clone());
        let stateless = stateless.with_idle_timeout(Duration::from_millis(100));
        let persistent = PersistentSessionConsumerClient::from_stateless(stateless);

        let idle_deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        let (connection, idle_lifecycle) = synthetic_consumer_connection(
            &persistent.pool.client,
            idle_deadline,
            Box::new(tokio::io::sink()),
        );
        persistent.pool.return_idle(connection);
        let idle_deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        wait_for_raw_idle_count(&persistent, 1).await;
        assert!(
            persistent
                .pool
                .idle_reaper
                .task
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some(),
            "one pool-wide idle reaper is started lazily"
        );
        wait_for_idle_reaper_armed_deadline(&persistent, idle_deadline, "first idle").await;
        tokio::time::advance(Duration::from_millis(99)).await;
        tokio::task::yield_now().await;
        wait_for_raw_idle_count(&persistent, 1).await;
        tokio::time::advance(Duration::from_millis(1)).await;
        wait_for_raw_idle_count(&persistent, 0).await;
        assert_eq!(
            idle_lifecycle.recorded_retirement_reason(),
            Some(RetirementReason::IdleTimeout)
        );
        assert_eq!(idle_lifecycle.recorded_retirement_count(), 1);

        // Keep the rotation test independent from the short local-idle
        // contract above: material retirement must remain its own earliest
        // boundary, rather than being hidden by an intentionally tiny idle
        // timeout.
        let rotation_policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_secs(1),
        )
        .expect("bounded test rotation policy");
        let rotation_stateless = persistent
            .pool
            .client
            .clone()
            .with_idle_timeout(Duration::from_secs(5))
            .with_connection_lifecycle(rotation_policy);
        persistent.shutdown().await;
        let persistent = PersistentSessionConsumerClient::from_stateless(rotation_stateless);

        let (connection, material_lifecycle) = synthetic_consumer_connection(
            &persistent.pool.client,
            tokio::time::Instant::now()
                + persistent.pool.client.lifecycle_policy.rotation_jitter()
                + Duration::from_secs(1),
            Box::new(tokio::io::sink()),
        );
        let material_edge_key = connection.rotation_edge_key;
        persistent.pool.return_idle(connection);
        wait_for_raw_idle_count(&persistent, 1).await;
        let same_epoch_processed = persistent
            .pool
            .test_hooks
            .material_reaper_processed
            .notified();
        tokio::pin!(same_epoch_processed);
        material.publish_rejected_update();
        same_epoch_processed.await;
        wait_for_raw_idle_count(&persistent, 1).await;
        assert_eq!(
            material_lifecycle.recorded_retirement_count(),
            0,
            "a same-epoch rejected publication retains authenticated capacity"
        );
        let material_rotation_processed = persistent
            .pool
            .test_hooks
            .material_reaper_processed
            .notified();
        tokio::pin!(material_rotation_processed);
        let material_rotated_at = tokio::time::Instant::now();
        material.rotate();
        material_rotation_processed.await;
        let material_jitter = persistent.pool.client.lifecycle_policy.rotation_jitter();
        let material_jitter = material_edge_key.bounded_jitter(material_jitter);
        assert!(
            !material_jitter.is_zero(),
            "the fixed test identity has a nonzero cooperative rotation window"
        );
        let scheduled_retire_at = persistent
            .pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .front()
            .expect("the material-rotated lane remains cached before its deadline")
            .lifecycle
            .retire_at();
        assert_eq!(
            scheduled_retire_at,
            material_rotated_at + material_jitter,
            "the idle lane uses its stable authenticated edge jitter"
        );
        wait_for_idle_reaper_armed_deadline(&persistent, scheduled_retire_at, "material rotation")
            .await;
        wait_for_raw_idle_count(&persistent, 1).await;
        assert_eq!(material_lifecycle.recorded_retirement_count(), 0);
        tokio::time::advance(
            material_jitter
                .checked_sub(Duration::from_nanos(1))
                .expect("test jitter exceeds one nanosecond"),
        )
        .await;
        wait_for_raw_idle_count(&persistent, 1).await;
        assert_eq!(material_lifecycle.recorded_retirement_count(), 0);
        // Tokio's timer driver may schedule an arbitrary-nanosecond keyed
        // deadline on the following millisecond tick. The live-connection
        // test below seals the exact semantic boundary; this assertion seals
        // autonomous physical removal immediately after that boundary.
        tokio::time::advance(Duration::from_millis(1)).await;
        wait_for_raw_idle_count(&persistent, 0).await;
        assert_eq!(
            material_lifecycle.recorded_retirement_reason(),
            Some(RetirementReason::MaterialEpoch)
        );

        let (connection, explicit_lifecycle) = synthetic_consumer_connection(
            &persistent.pool.client,
            tokio::time::Instant::now() + Duration::from_secs(60),
            Box::new(tokio::io::sink()),
        );
        persistent.pool.return_idle(connection);
        wait_for_raw_idle_count(&persistent, 1).await;
        control
            .request_reauthentication()
            .expect("advance shared reauthentication control directly");
        wait_for_raw_idle_count(&persistent, 0).await;
        assert_eq!(
            explicit_lifecycle.recorded_retirement_reason(),
            Some(RetirementReason::Explicit)
        );
        assert_eq!(explicit_lifecycle.recorded_retirement_count(), 1);

        let report = persistent.shutdown().await;
        assert_eq!(report.forced_calls, 0);
        assert_eq!(report.forced_watches, 0);
        assert!(
            persistent
                .pool
                .idle_reaper
                .task
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_none(),
            "shutdown aborts the constant maintenance task"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn returned_idle_lifetime_starts_fresh_but_never_widens_after_a_call() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let control = SessionReauthenticationControl::new();
        let (stateless, _material) = stateless_test_client(control);
        let persistent = PersistentSessionConsumerClient::from_stateless(
            stateless.with_idle_timeout(Duration::from_millis(100)),
        );

        // This simulates a connection whose authenticated setup completed
        // after its initial active-frame deadline. The elapsed setup interval
        // is not idle time, so publication must start a full bounded lifetime.
        let (connection, lifecycle) = synthetic_consumer_connection(
            &persistent.pool.client,
            tokio::time::Instant::now() + Duration::from_millis(1),
            Box::new(tokio::io::sink()),
        );
        tokio::time::advance(Duration::from_millis(100)).await;
        let first_publication_deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        persistent.pool.return_idle(connection);
        wait_for_raw_idle_count(&persistent, 1).await;
        assert_eq!(
            persistent
                .pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .front()
                .expect("authenticated lane is published idle")
                .idle_deadline,
            first_publication_deadline,
            "idle expiry begins at authenticated idle publication"
        );

        tokio::time::advance(Duration::from_millis(99)).await;
        tokio::task::yield_now().await;
        let mut checked_out = persistent
            .pool
            .take_idle()
            .expect("the lane remains reusable before the published deadline");
        // A real call stamps this deadline immediately before its request
        // write. Its later response/return must not grant a peer more idle
        // time than the conservative boundary already in force.
        let call_idle_deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        checked_out.calls = 1;
        checked_out.idle_deadline = call_idle_deadline;
        tokio::time::advance(Duration::from_millis(20)).await;
        tokio::task::yield_now().await;
        assert_eq!(lifecycle.recorded_retirement_count(), 0);
        persistent.pool.return_idle(checked_out);
        wait_for_raw_idle_count(&persistent, 1).await;
        assert_eq!(
            persistent
                .pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .front()
                .expect("returned lane is published idle")
                .idle_deadline,
            call_idle_deadline,
            "response completion cannot widen the deadline stamped before write"
        );
        tokio::time::advance(Duration::from_millis(79)).await;
        tokio::task::yield_now().await;
        wait_for_raw_idle_count(&persistent, 1).await;
        tokio::time::advance(Duration::from_millis(1)).await;
        wait_for_raw_idle_count(&persistent, 0).await;
        assert_eq!(
            lifecycle.recorded_retirement_reason(),
            Some(RetirementReason::IdleTimeout)
        );
        assert_eq!(lifecycle.recorded_retirement_count(), 1);

        persistent.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn material_rotation_uses_stable_distinct_authenticated_edge_deadlines() {
        let client_a_id = material_spiffe("edge-client-a");
        let client_b_id = material_spiffe("edge-client-b");
        let server_id = material_spiffe("edge-server");
        let client_a_material = RotatableClientMaterial::new(client_a_id.as_str());
        let client_b_material = RotatableClientMaterial::new(client_b_id.as_str());
        let server_material = RotatableServerMaterial::new(server_id.as_str());
        let client_a_config = client_a_material.config();
        let client_b_config = client_b_material.config();
        let server_config = server_material.config();
        let client_a_key = client_a_config
            .begin_handshake()
            .expect("client A handshake snapshot")
            .directed_lifecycle_edge_key(b"consumer", &server_id);
        let stable_client_a_key = client_a_config
            .begin_handshake()
            .expect("second client A handshake snapshot")
            .directed_lifecycle_edge_key(b"consumer", &server_id);
        let client_b_key = client_b_config
            .begin_handshake()
            .expect("client B handshake snapshot")
            .directed_lifecycle_edge_key(b"consumer", &server_id);
        let server_a_key = server_config
            .begin_handshake()
            .expect("server handshake snapshot")
            .directed_lifecycle_edge_key(b"consumer", &client_a_id);
        assert_eq!(client_a_key, stable_client_a_key);
        assert_eq!(client_a_key, server_a_key);
        assert_ne!(client_a_key, client_b_key);
        assert_eq!(
            format!("{client_a_key:?}"),
            "TlsDirectedEdgeKey([redacted])"
        );

        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(2),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_secs(10),
        )
        .expect("bounded edge-jitter policy");
        let admitted_epoch = client_a_config.material_status().epoch();
        client_a_material.rotate();
        let current_epoch = client_a_config.material_status().epoch();
        assert!(!consumer_fresh_admission_is_current(
            0,
            admitted_epoch,
            0,
            current_epoch,
        ));
        let now = tokio::time::Instant::now();
        let mut edge_a = ConnectionLifecycle::new(policy, now, None, None, 0, Some(admitted_epoch))
            .expect("edge A lifecycle");
        let mut edge_b = ConnectionLifecycle::new(policy, now, None, None, 0, Some(admitted_epoch))
            .expect("edge B lifecycle");
        edge_a.observe_authenticated_rotation(now, 0, Some(current_epoch), client_a_key);
        edge_b.observe_authenticated_rotation(now, 0, Some(current_epoch), client_b_key);
        let edge_a_jitter = client_a_key.bounded_jitter(policy.rotation_jitter());
        let edge_b_jitter = client_b_key.bounded_jitter(policy.rotation_jitter());
        assert_ne!(edge_a_jitter, edge_b_jitter);
        assert_eq!(edge_a.retire_at(), now + edge_a_jitter);
        assert_eq!(edge_b.retire_at(), now + edge_b_jitter);
        assert!(edge_a.retire_at() <= now + policy.rotation_jitter());
        assert!(edge_b.retire_at() <= now + policy.rotation_jitter());
        assert_eq!(
            edge_a.hard_deadline().expect("edge A hard deadline"),
            edge_a.retire_at() + policy.rotation_drain_window()
        );
        assert_eq!(
            edge_b.hard_deadline().expect("edge B hard deadline"),
            edge_b.retire_at() + policy.rotation_drain_window()
        );

        let server_admitted_epoch = server_config.material_status().epoch();
        let server_control = SessionReauthenticationControl::new();
        let mut server_material_lifecycle = ConnectionLifecycle::new(
            policy,
            now,
            None,
            None,
            server_control.generation(),
            Some(server_admitted_epoch),
        )
        .expect("server material lifecycle");
        server_material.rotate();
        assert!(
            !edge_a_jitter.is_zero(),
            "the fixed authenticated edge exercises cooperative reuse"
        );
        assert!(server_connection_current(
            &mut server_material_lifecycle,
            &server_config,
            &server_control,
            server_a_key,
        ));
        let server_retire_at = server_material_lifecycle.retire_at();
        assert_eq!(server_retire_at, now + edge_a_jitter);
        tokio::time::advance(edge_a_jitter - Duration::from_nanos(1)).await;
        assert!(server_connection_current(
            &mut server_material_lifecycle,
            &server_config,
            &server_control,
            server_a_key,
        ));
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert!(!server_connection_current(
            &mut server_material_lifecycle,
            &server_config,
            &server_control,
            server_a_key,
        ));
        assert_eq!(
            server_material_lifecycle.recorded_retirement_reason(),
            Some(RetirementReason::MaterialEpoch)
        );

        let explicit_now = tokio::time::Instant::now();
        let mut server_explicit_lifecycle = ConnectionLifecycle::new(
            policy,
            explicit_now,
            None,
            None,
            server_control.generation(),
            Some(server_config.material_status().epoch()),
        )
        .expect("server explicit lifecycle");
        server_control
            .request_reauthentication()
            .expect("advance server explicit generation");
        assert!(!server_connection_current(
            &mut server_explicit_lifecycle,
            &server_config,
            &server_control,
            server_a_key,
        ));
        assert_eq!(
            server_explicit_lifecycle.recorded_retirement_reason(),
            Some(RetirementReason::Explicit)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn checked_out_lane_discard_is_counted_once_and_idle_return_is_not() {
        let control = SessionReauthenticationControl::new();
        let (stateless, _material) = stateless_test_client(control);
        let persistent = PersistentSessionConsumerClient::from_stateless(stateless);

        let (discarded, _) = synthetic_consumer_connection(
            &persistent.pool.client,
            tokio::time::Instant::now() + Duration::from_secs(5),
            Box::new(tokio::io::sink()),
        );
        let checkout = PersistentCheckedOutConnection::new(Arc::clone(&persistent.pool), discarded);
        drop(checkout);
        assert_eq!(
            persistent.pool.counters.reconnects.load(Ordering::Relaxed),
            1,
            "a cancelled or protocol-poisoned checked-out lane has one replacement"
        );

        let (returned, _) = synthetic_consumer_connection(
            &persistent.pool.client,
            tokio::time::Instant::now() + Duration::from_secs(5),
            Box::new(tokio::io::sink()),
        );
        PersistentCheckedOutConnection::new(Arc::clone(&persistent.pool), returned).return_idle();
        assert_eq!(
            persistent.pool.counters.reconnects.load(Ordering::Relaxed),
            1,
            "a successful idle return does not request a replacement"
        );

        persistent.shutdown().await;
        let reconnects_after_shutdown = persistent.pool.counters.reconnects.load(Ordering::Relaxed);
        let (declined_after_shutdown, _) = synthetic_consumer_connection(
            &persistent.pool.client,
            tokio::time::Instant::now() + Duration::from_secs(5),
            Box::new(tokio::io::sink()),
        );
        PersistentCheckedOutConnection::new(Arc::clone(&persistent.pool), declined_after_shutdown)
            .return_idle();
        assert_eq!(
            persistent.pool.counters.reconnects.load(Ordering::Relaxed),
            reconnects_after_shutdown + 1,
            "a lane whose idle publication is declined by shutdown is discarded exactly once"
        );
    }

    #[tokio::test]
    async fn shutdown_phase_never_regresses_after_a_cancelled_stale_publisher() {
        let state = Arc::new(AtomicU8::new(PersistentShutdownPhase::Running as u8));
        let (sender, mut receiver) = watch::channel(PersistentShutdownPhase::Running);
        let cancelled_state = Arc::clone(&state);
        let mut cancelled_receiver = sender.subscribe();
        let cancelled = tokio::spawn(async move {
            wait_for_forced_shutdown(&mut cancelled_receiver, &cancelled_state).await;
        });
        cancelled.abort();
        let _ = cancelled.await;

        assert_eq!(
            publish_monotonic_shutdown_phase(&state, &sender, PersistentShutdownPhase::Forced,),
            PersistentShutdownPhase::Forced
        );
        assert_eq!(
            publish_monotonic_shutdown_phase(&state, &sender, PersistentShutdownPhase::Draining,),
            PersistentShutdownPhase::Forced,
            "a delayed draining caller cannot overwrite forced shutdown"
        );
        // Exercise a stale watch value as well: forced waiters consult the
        // monotonic atomic source before trusting a delayed publication.
        sender.send_replace(PersistentShutdownPhase::Draining);
        wait_for_forced_shutdown(&mut receiver, &state).await;
        assert_eq!(
            PersistentShutdownPhase::load(&state),
            PersistentShutdownPhase::Forced
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_shutdown_caller_cannot_abandon_a_quiet_watch_in_draining() {
        let control = SessionReauthenticationControl::new();
        let (stateless, _material) = stateless_test_client(control);
        let client = PersistentSessionConsumerClient::from_stateless(stateless);
        let watch_permit = Arc::clone(&client.pool.watches)
            .try_acquire_owned()
            .expect("one isolated watch slot");
        let quiet_watch = client
            .pool
            .register_watch(watch_permit)
            .expect("register a quiet unpolled watch");

        let shutdown_client = client.clone();
        let caller = tokio::spawn(async move { shutdown_client.shutdown().await });
        while client.pool.phase() == PersistentShutdownPhase::Running {
            tokio::task::yield_now().await;
        }
        assert_eq!(client.pool.phase(), PersistentShutdownPhase::Draining);
        caller.abort();
        let _ = caller.await;

        tokio::time::advance(client.pool.config.shutdown_drain).await;
        let report = client.shutdown().await;
        assert_eq!(client.pool.phase(), PersistentShutdownPhase::Forced);
        assert!(client.pool.shutdown_io.is_forced());
        assert_eq!(report.forced_calls, 0);
        assert_eq!(report.forced_watches, 1);
        assert_eq!(
            *client.pool.shutdown_tx.borrow(),
            PersistentShutdownPhase::Forced,
            "the pool-owned driver completes after its caller is cancelled"
        );
        drop(quiet_watch);
        assert_eq!(
            client.pool.watches.available_permits(),
            client.pool.config.watch_connections
        );
    }

    #[tokio::test]
    async fn pool_local_shutdown_does_not_rotate_a_sibling_clone_lineage() {
        let control = SessionReauthenticationControl::new();
        let initial_generation = control.generation();
        let (stateless, _material) = stateless_test_client(control.clone());
        let first = PersistentSessionConsumerClient::from_stateless(stateless.clone());
        let sibling = PersistentSessionConsumerClient::from_stateless(stateless);
        let (mut sibling_lane, _) = synthetic_consumer_connection(
            &sibling.pool.client,
            tokio::time::Instant::now() + Duration::from_secs(5),
            Box::new(tokio::io::sink()),
        );

        first.shutdown().await;
        assert_eq!(
            control.generation(),
            initial_generation,
            "pool-local shutdown never advances clone-lineage reauthentication"
        );
        assert!(sibling_lane.current(
            &sibling.pool.client.tls_config,
            &sibling.pool.client.reauthentication,
        ));
        assert_eq!(sibling.pool.phase(), PersistentShutdownPhase::Running);
        sibling.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn watch_call_invalidates_explicit_but_drains_material_at_edge_deadline() {
        let control = SessionReauthenticationControl::new();
        let (client, material) = stateless_test_client(control.clone());
        let request = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::Watch { start_sequence: 0 },
        );

        let explicit_bytes = Arc::new(AtomicUsize::new(0));
        let (mut explicit_connection, explicit_lifecycle) = synthetic_consumer_connection(
            &client,
            tokio::time::Instant::now() + Duration::from_secs(5),
            Box::new(SharedCountingWriter {
                accepted: Arc::clone(&explicit_bytes),
            }),
        );
        control
            .request_reauthentication()
            .expect("advance before subscribing");
        let mut reauthentication_changes = control.subscribe();
        let mut material_changes = Some(client.tls_config.subscribe_material_changes());
        let result = client
            .write_watch_call_on_connection(
                &mut explicit_connection,
                &request,
                tokio::time::Instant::now() + Duration::from_secs(1),
                false,
                &mut reauthentication_changes,
                &mut material_changes,
            )
            .await;
        assert_eq!(result, Err(SessionConsumerClientError::Unavailable));
        assert_eq!(explicit_bytes.load(Ordering::SeqCst), 0);
        assert_eq!(explicit_connection.calls, 0);
        assert_eq!(
            explicit_lifecycle.recorded_retirement_reason(),
            Some(RetirementReason::Explicit)
        );

        let material_bytes = Arc::new(AtomicUsize::new(0));
        let (mut material_connection, material_lifecycle) = synthetic_consumer_connection(
            &client,
            tokio::time::Instant::now() + Duration::from_secs(5),
            Box::new(SharedCountingWriter {
                accepted: Arc::clone(&material_bytes),
            }),
        );
        material.rotate();
        let mut reauthentication_changes = control.subscribe();
        let mut material_changes = Some(client.tls_config.subscribe_material_changes());
        let result = client
            .write_watch_call_on_connection(
                &mut material_connection,
                &request,
                tokio::time::Instant::now() + Duration::from_secs(1),
                false,
                &mut reauthentication_changes,
                &mut material_changes,
            )
            .await;
        assert_eq!(result, Ok(NonZeroU32::MIN));
        assert!(material_bytes.load(Ordering::SeqCst) > 0);
        assert_eq!(material_connection.calls, 1);
        assert_eq!(material_lifecycle.recorded_retirement_count(), 0);
        let material_retire_at = material_connection.lifecycle.retire_at();
        let now = tokio::time::Instant::now();
        assert!(material_retire_at > now);
        tokio::time::advance(material_retire_at.duration_since(now) - Duration::from_nanos(1))
            .await;
        assert!(material_connection.current(&client.tls_config, &client.reauthentication));
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert!(!material_connection.current(&client.tls_config, &client.reauthentication));
        assert_eq!(
            material_lifecycle.recorded_retirement_reason(),
            Some(RetirementReason::MaterialEpoch)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn partial_watch_write_stops_at_rotation_hard_deadline() {
        let control = SessionReauthenticationControl::new();
        let (client, _material) = stateless_test_client(control.clone());
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(10),
            Duration::from_millis(100),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::ZERO,
        )
        .expect("bounded zero-jitter test lifecycle");
        let client = client.with_connection_lifecycle(policy);
        let accepted = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());
        let (mut connection, observed_lifecycle) = synthetic_consumer_connection(
            &client,
            tokio::time::Instant::now() + Duration::from_secs(5),
            Box::new(PartialPendingWriter {
                accepted: Arc::clone(&accepted),
                started: Arc::clone(&started),
                wrote_prefix: false,
            }),
        );
        let request = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::Watch { start_sequence: 0 },
        );
        let mut reauthentication_changes = control.subscribe();
        let mut material_changes = Some(client.tls_config.subscribe_material_changes());
        {
            let write_started = started.notified();
            tokio::pin!(write_started);
            let write = client.write_watch_call_on_connection(
                &mut connection,
                &request,
                tokio::time::Instant::now() + Duration::from_secs(1),
                false,
                &mut reauthentication_changes,
                &mut material_changes,
            );
            tokio::pin!(write);
            tokio::select! {
                biased;
                _ = &mut write_started => {}
                result = &mut write => panic!("write completed before controlled rotation: {result:?}"),
            }
            assert_eq!(accepted.load(Ordering::SeqCst), 2);

            control
                .request_reauthentication()
                .expect("rotate during a partial prefix write");
            std::future::poll_fn(|context| {
                assert!(std::future::Future::poll(write.as_mut(), context).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(
                observed_lifecycle.recorded_retirement_reason(),
                Some(RetirementReason::Explicit)
            );
            tokio::time::advance(Duration::from_millis(99)).await;
            std::future::poll_fn(|context| {
                assert!(std::future::Future::poll(write.as_mut(), context).is_pending());
                Poll::Ready(())
            })
            .await;
            tokio::time::advance(Duration::from_millis(1)).await;
            assert_eq!(write.await, Err(SessionConsumerClientError::Deadline));
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
        assert_eq!(connection.calls, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn unary_rotation_interrupt_preserves_the_positive_byte_boundary() {
        for partial in [false, true] {
            let control = SessionReauthenticationControl::new();
            let (client, _material) = stateless_test_client(control.clone());
            let policy = ConnectionLifecyclePolicy::try_new(
                Duration::from_secs(10),
                Duration::from_millis(100),
                Duration::from_millis(1),
                Duration::from_millis(1),
                Duration::ZERO,
            )
            .expect("bounded zero-jitter test lifecycle");
            let persistent = PersistentSessionConsumerClient::from_stateless(
                client.with_connection_lifecycle(policy),
            );
            let accepted = Arc::new(AtomicUsize::new(0));
            let started = Arc::new(tokio::sync::Notify::new());
            let writer: Box<dyn AsyncWrite + Unpin + Send> = if partial {
                Box::new(PartialPendingWriter {
                    accepted: Arc::clone(&accepted),
                    started: Arc::clone(&started),
                    wrote_prefix: false,
                })
            } else {
                Box::new(PendingWriter)
            };
            let (mut connection, observed_lifecycle) = synthetic_consumer_connection(
                &persistent.pool.client,
                tokio::time::Instant::now() + Duration::from_secs(5),
                writer,
            );
            let request_id = SessionConsumerRequestId::new();
            let request = mutation_request(request_id);
            let write_started = started.notified();
            tokio::pin!(write_started);
            let call = persistent.pool.client.execute_on_connection(
                &mut connection,
                &request,
                tokio::time::Instant::now() + Duration::from_secs(1),
                false,
                tokio::time::Instant::now() + Duration::from_secs(1),
                None,
            );
            tokio::pin!(call);
            if partial {
                tokio::select! {
                    biased;
                    _ = &mut write_started => {}
                    result = &mut call => {
                        panic!("write completed before controlled rotation: {result:?}")
                    }
                }
                assert_eq!(accepted.load(Ordering::SeqCst), 2);
            } else {
                std::future::poll_fn(|context| {
                    assert!(std::future::Future::poll(call.as_mut(), context).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert_eq!(accepted.load(Ordering::SeqCst), 0);
            }

            control
                .request_reauthentication()
                .expect("rotate during the controlled request write");
            std::future::poll_fn(|context| {
                assert!(std::future::Future::poll(call.as_mut(), context).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(
                observed_lifecycle.recorded_retirement_reason(),
                Some(RetirementReason::Explicit)
            );
            tokio::time::advance(Duration::from_millis(100)).await;
            let result = call
                .await
                .expect_err("rotation hard deadline interrupts the request write");
            let may_have_sent = matches!(result, SessionConsumerCallError::MayHaveSent(_));
            persistent
                .pool
                .record_error(result.into_client_error(), may_have_sent);
            let public = persistent_execute_error(request_id, result);
            if partial {
                assert!(matches!(
                    public,
                    PersistentSessionConsumerExecuteError::OutcomeUnknown {
                        request_id: retained
                    } if retained == request_id
                ));
            } else {
                assert_eq!(
                    public,
                    PersistentSessionConsumerExecuteError::NotTransmitted {
                        cause: SessionConsumerClientError::Deadline,
                    }
                );
            }
            let diagnostics = persistent.diagnostics().await;
            assert_eq!(diagnostics.not_transmitted, u64::from(!partial));
            assert_eq!(diagnostics.outcome_unknown, u64::from(partial));
            assert_eq!(diagnostics.deadline, 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn unary_forced_shutdown_interrupt_preserves_the_positive_byte_boundary() {
        for partial in [false, true] {
            let control = SessionReauthenticationControl::new();
            let (client, _material) = stateless_test_client(control);
            let persistent = PersistentSessionConsumerClient::from_stateless(client);
            let accepted = Arc::new(AtomicUsize::new(0));
            let started = Arc::new(tokio::sync::Notify::new());
            let writer: Box<dyn AsyncWrite + Unpin + Send> = if partial {
                Box::new(PartialPendingWriter {
                    accepted: Arc::clone(&accepted),
                    started: Arc::clone(&started),
                    wrote_prefix: false,
                })
            } else {
                Box::new(PendingWriter)
            };
            let (mut connection, _) = synthetic_consumer_connection(
                &persistent.pool.client,
                tokio::time::Instant::now() + Duration::from_secs(5),
                writer,
            );
            let io_barrier = install_shutdown_barrier(&mut connection);
            let request_id = SessionConsumerRequestId::new();
            let request = mutation_request(request_id);
            let (shutdown_tx, shutdown_rx) = watch::channel(PersistentShutdownPhase::Running);
            let shutdown_state = AtomicU8::new(PersistentShutdownPhase::Running as u8);
            let write_started = started.notified();
            tokio::pin!(write_started);
            let call = persistent.pool.client.execute_on_connection(
                &mut connection,
                &request,
                tokio::time::Instant::now() + Duration::from_secs(1),
                false,
                tokio::time::Instant::now() + Duration::from_secs(1),
                Some((shutdown_rx, &shutdown_state)),
            );
            tokio::pin!(call);
            if partial {
                tokio::select! {
                    biased;
                    _ = &mut write_started => {}
                    result = &mut call => {
                        panic!("write completed before controlled shutdown: {result:?}")
                    }
                }
                assert_eq!(accepted.load(Ordering::SeqCst), 2);
            } else {
                std::future::poll_fn(|context| {
                    assert!(std::future::Future::poll(call.as_mut(), context).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert_eq!(accepted.load(Ordering::SeqCst), 0);
            }

            // Production shutdown closes transport polling first, then
            // publishes Forced. No later ready writer can cross that barrier.
            io_barrier.force();
            io_barrier.wait_quiescent().await;
            publish_monotonic_shutdown_phase(
                &shutdown_state,
                &shutdown_tx,
                PersistentShutdownPhase::Forced,
            );
            let result = call
                .await
                .expect_err("forced shutdown interrupts the request write");
            let may_have_sent = matches!(result, SessionConsumerCallError::MayHaveSent(_));
            persistent
                .pool
                .record_error(result.into_client_error(), may_have_sent);
            let public = persistent_execute_error(request_id, result);
            if partial {
                assert!(matches!(
                    public,
                    PersistentSessionConsumerExecuteError::OutcomeUnknown {
                        request_id: retained
                    } if retained == request_id
                ));
            } else {
                assert_eq!(
                    public,
                    PersistentSessionConsumerExecuteError::NotTransmitted {
                        cause: SessionConsumerClientError::ShuttingDown,
                    }
                );
            }
            let diagnostics = persistent.diagnostics().await;
            assert_eq!(diagnostics.not_transmitted, u64::from(!partial));
            assert_eq!(diagnostics.outcome_unknown, u64::from(partial));
            assert_eq!(diagnostics.shutdown, 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn forced_shutdown_precedes_ready_request_and_response_io() {
        let control = SessionReauthenticationControl::new();
        let (client, _material) = stateless_test_client(control);
        let persistent = PersistentSessionConsumerClient::from_stateless(client);

        let request_bytes = Arc::new(AtomicUsize::new(0));
        let (mut ready_write, _) = synthetic_consumer_connection(
            &persistent.pool.client,
            tokio::time::Instant::now() + Duration::from_secs(5),
            Box::new(SharedCountingWriter {
                accepted: Arc::clone(&request_bytes),
            }),
        );
        let ready_barrier = install_shutdown_barrier(&mut ready_write);
        let (ready_tx, ready_rx) = watch::channel(PersistentShutdownPhase::Running);
        let ready_state = AtomicU8::new(PersistentShutdownPhase::Running as u8);
        ready_barrier.force();
        publish_monotonic_shutdown_phase(&ready_state, &ready_tx, PersistentShutdownPhase::Forced);
        let request = mutation_request(SessionConsumerRequestId::new());
        assert_eq!(
            persistent
                .pool
                .client
                .execute_on_connection(
                    &mut ready_write,
                    &request,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                    false,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                    Some((ready_rx, &ready_state)),
                )
                .await,
            Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::ShuttingDown
            ))
        );
        assert_eq!(request_bytes.load(Ordering::SeqCst), 0);

        let response = ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation: NonZeroU32::MIN,
            response: Box::new(SessionConsumerResponse::AcquireLease(Err(
                SessionConsumerLeaseError::Unavailable,
            ))),
        });
        let payload = serde_json::to_vec(&response).expect("encode controlled response");
        let mut framed = Vec::with_capacity(payload.len() + 4);
        framed.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("test response length")
                .to_be_bytes(),
        );
        framed.extend_from_slice(&payload);
        let response_ready = Arc::new(AtomicBool::new(false));
        let response_bytes = Arc::new(AtomicUsize::new(0));
        let written = Arc::new(AtomicUsize::new(0));
        let (mut ready_response, _) = synthetic_consumer_connection(
            &persistent.pool.client,
            tokio::time::Instant::now() + Duration::from_secs(5),
            Box::new(SharedCountingWriter {
                accepted: Arc::clone(&written),
            }),
        );
        ready_response.reader = Box::new(GatedCountingReader {
            encoded: framed,
            offset: 0,
            ready: Arc::clone(&response_ready),
            accepted: Arc::clone(&response_bytes),
        });
        let response_barrier = install_shutdown_barrier(&mut ready_response);
        let (response_tx, response_rx) = watch::channel(PersistentShutdownPhase::Running);
        let response_state = AtomicU8::new(PersistentShutdownPhase::Running as u8);
        let call = persistent.pool.client.execute_on_connection(
            &mut ready_response,
            &request,
            tokio::time::Instant::now() + Duration::from_secs(1),
            false,
            tokio::time::Instant::now() + Duration::from_secs(1),
            Some((response_rx, &response_state)),
        );
        tokio::pin!(call);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(call.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(written.load(Ordering::SeqCst) > 0);
        assert_eq!(response_bytes.load(Ordering::SeqCst), 0);
        response_ready.store(true, Ordering::Release);
        response_barrier.force();
        publish_monotonic_shutdown_phase(
            &response_state,
            &response_tx,
            PersistentShutdownPhase::Forced,
        );
        assert_eq!(
            call.await,
            Err(SessionConsumerCallError::MayHaveSent(
                SessionConsumerClientError::ShuttingDown
            ))
        );
        assert_eq!(
            response_bytes.load(Ordering::SeqCst),
            0,
            "a ready authenticated response cannot be consumed after Forced"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn unary_idle_deadline_does_not_record_a_later_lifecycle_overrun() {
        let control = SessionReauthenticationControl::new();
        let (client, _material) = stateless_test_client(control);
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_millis(6),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::ZERO,
        )
        .expect("bounded test lifecycle");
        let client = client
            .with_connection_lifecycle(policy)
            .with_idle_timeout(Duration::from_millis(5))
            .with_operation_timeout(Duration::from_millis(10));
        let (mut connection, observed_lifecycle) = synthetic_consumer_connection(
            &client,
            tokio::time::Instant::now() + Duration::from_millis(5),
            Box::new(tokio::io::sink()),
        );
        let (pending_peer, pending_reader) = tokio::io::duplex(64);
        connection.reader = Box::new(pending_reader);
        let request = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::Capabilities,
        );
        let now = tokio::time::Instant::now();
        let execute = client.execute_on_connection(
            &mut connection,
            &request,
            now + Duration::from_millis(10),
            false,
            now + Duration::from_millis(10),
            None,
        );
        tokio::pin!(execute);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(execute.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_millis(5)).await;
        assert!(matches!(
            execute.await,
            Err(SessionConsumerCallError::MayHaveSent(
                SessionConsumerClientError::Deadline
            ))
        ));
        assert!(
            !observed_lifecycle.hard_overrun_recorded(),
            "an earlier active-frame idle deadline must not start lifecycle draining"
        );
        drop(pending_peer);
    }

    #[tokio::test(start_paused = true)]
    async fn authenticated_consumer_idle_and_partial_frame_are_distinct() {
        let (idle_peer, mut idle_reader) = tokio::io::duplex(64);
        let idle = read_authenticated_consumer_frame_within::<_, ConsumerWireRequest>(
            &mut idle_reader,
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_millis(100),
        );
        tokio::pin!(idle);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(idle.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(matches!(idle.await, Ok(None)));
        drop(idle_peer);

        let (mut partial_peer, mut partial_reader) = tokio::io::duplex(64);
        partial_peer
            .write_all(&[0])
            .await
            .expect("write one prefix byte");
        let partial = read_authenticated_consumer_frame_within::<_, ConsumerWireRequest>(
            &mut partial_reader,
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_millis(100),
        );
        tokio::pin!(partial);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(partial.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(matches!(
            partial.await,
            Err(crate::ProtocolError::Io(error))
                if error.kind() == io::ErrorKind::TimedOut
        ));

        let request = ConsumerWireRequest::Call(ConsumerCall {
            correlation: NonZeroU32::MIN,
            request: Box::new(mutation_request(SessionConsumerRequestId::new())),
        });
        let mut request = serde_json::to_value(request).expect("consumer call encodes");
        request["body"]["request"]["operation"]["key"]["unexpected"] =
            serde_json::Value::Bool(true);
        assert_eq!(
            request
                .pointer("/body/request/operation/key/unexpected")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        let (mut unknown_peer, mut unknown_reader) = tokio::io::duplex(64 * 1024);
        crate::protocol::write_frame(&mut unknown_peer, &request)
            .await
            .expect("write unknown nested request field");
        match read_authenticated_consumer_frame_within::<_, ConsumerWireRequest>(
            &mut unknown_reader,
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_millis(100),
        )
        .await
        {
            Err(crate::ProtocolError::InvalidWireValue)
            | Err(crate::ProtocolError::Serialization(_)) => {}
            Ok(Some(_)) => panic!("authenticated decoder accepted an unknown nested field"),
            Ok(None) => panic!("authenticated decoder mislabeled a complete frame as idle"),
            Err(_) => panic!("authenticated decoder returned a non-decoding error"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pooled_retirement_records_the_earliest_elapsed_deadline() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let control = SessionReauthenticationControl::new();
        let (client, _material) = stateless_test_client(control);
        let lifecycle_first = ConnectionLifecyclePolicy::try_new(
            Duration::from_millis(200),
            Duration::from_millis(100),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::ZERO,
        )
        .expect("short lifecycle policy");
        let lifecycle_client = client.clone().with_connection_lifecycle(lifecycle_first);
        let (mut connection, observed) = synthetic_consumer_connection(
            &lifecycle_client,
            tokio::time::Instant::now() + Duration::from_millis(200),
            Box::new(tokio::io::sink()),
        );
        tokio::time::advance(Duration::from_millis(200)).await;
        assert!(!connection.reusable());
        assert_eq!(
            observed.recorded_retirement_reason(),
            Some(RetirementReason::MaximumAge)
        );

        let idle_first = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(10),
            Duration::from_millis(100),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::ZERO,
        )
        .expect("long lifecycle policy");
        let idle_client = client.with_connection_lifecycle(idle_first);
        let (mut connection, observed) = synthetic_consumer_connection(
            &idle_client,
            tokio::time::Instant::now() + Duration::from_millis(100),
            Box::new(tokio::io::sink()),
        );
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(!connection.reusable());
        assert_eq!(
            observed.recorded_retirement_reason(),
            Some(RetirementReason::IdleTimeout)
        );
    }

    #[test]
    fn scan_response_that_would_overflow_the_frame_is_not_admitted() {
        let record = StoredSessionRecord {
            key: SessionKey {
                tenant: TenantId::new("consumer-frame-test").expect("valid tenant"),
                nf_kind: NetworkFunctionKind::smf(),
                key_type: SessionKeyType::PduSession,
                stable_id: Bytes::from_static(b"consumer-frame-test")
                    .try_into()
                    .expect("valid stable ID"),
            },
            generation: Generation::new(1),
            owner: OwnerId::new("consumer-frame-owner").expect("valid owner"),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("consumer-frame-test"),
            expires_at: None,
            // JSON represents every 0xff byte with three digits. A valid
            // 4-MiB restore page therefore exceeds the 16-MiB frame once its
            // transport envelope is included.
            payload: EncryptedSessionPayload::new(vec![u8::MAX; 4 * 1024 * 1024]),
        };
        let response = SessionConsumerResponse::ScanRestoreRecords(Ok(RestoreScanPage::new(
            vec![record],
            0,
            None,
        )));
        assert!(!consumer_response_fits(
            &response,
            MAX_NEGOTIATED_FRAME_SIZE
        ));
    }
}
