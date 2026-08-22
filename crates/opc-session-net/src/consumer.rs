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
use std::num::{NonZeroU32, NonZeroUsize};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::stream::{self, BoxStream, StreamExt};
use futures_util::FutureExt;
use opc_session_store::{
    checked_session_deadline, session_consumer_batch_result_into_store,
    validate_stored_record_expiry_profile, AtomicFencedTransitionCapability, BackendCapabilities,
    CompareAndSet, CompareAndSetResult, FencedTransitionExecuteError, FencedTransitionObservation,
    FencedTransitionOutcome, FencedTransitionRequest, FencedTransitionRequestId,
    FencedTransitionStatus, FencedTransitionV2RequestId, LeaseError, LeaseGuard, OwnerId,
    PreparedFencedTransition, RecordExpiryPreflight, RestoreScanPage, RestoreScanRequest,
    SessionBackend, SessionConsumerAuthorizationManifest, SessionConsumerBatchResult,
    SessionConsumerChange, SessionConsumerFencedTransitionError,
    SessionConsumerFencedTransitionStatus, SessionConsumerIdentity, SessionConsumerLeaseError,
    SessionConsumerOperation, SessionConsumerOutcomeUnknown, SessionConsumerRejection,
    SessionConsumerRequest, SessionConsumerRequestId, SessionConsumerResponse,
    SessionConsumerScope, SessionConsumerStoreError, SessionConsumerV2Operation,
    SessionConsumerV2Request, SessionConsumerV2Response, SessionOp, SessionOpResult,
    SessionPayloadEncoding, SessionQuorumConsumer, StatelessSessionConsumer, StoreError,
    MAX_SESSION_CONSUMER_BATCH_RESPONSE_BYTES,
};
use opc_types::SpiffeId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use crate::consensus::RemoteAddrResolver;
use crate::error::{classify_tls_io_error, ProtocolError};
use crate::lifecycle::{
    CertificateExpiryEvidence, ConnectionLifecycle, ConnectionLifecyclePolicy, RetirementReason,
    SessionReauthenticationControl,
};
#[cfg(test)]
use crate::protocol::read_frame_payload;
use crate::protocol::{
    bounded_session_op_expectations, compare_and_set_result_matches_key,
    conservative_payload_budget, get_result_matches_key, read_authenticated_frame_payload_until,
    read_authenticated_frame_payload_with_active_timeout_until,
    validate_restore_scan_wire_payload_bytes, write_frame_bounded_until,
    write_frame_bounded_until_classified_with_progress, FrameWriteError, FrameWriteProgress,
    WireBackendCapabilities, MAX_NEGOTIATED_FRAME_SIZE,
};

/// Dedicated ALPN for authenticated session-quorum consumers.
pub const SESSION_QUORUM_CONSUMER_ALPN: &[u8] = b"opc-session-consumer/1";

/// Dedicated ALPN for the explicit V2 fenced-transition consumer lane.
///
/// It is intentionally distinguishable from revision 3 at TLS negotiation;
/// a V1-only peer therefore cannot mistake a V2 operation for a new V1
/// operation even before the authenticated revision handshake is checked.
pub const SESSION_QUORUM_CONSUMER_V2_ALPN: &[u8] = b"opc-session-consumer/2";

/// Fixed wire revision for [`SESSION_QUORUM_CONSUMER_ALPN`].
pub const SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION: u16 = 3;

/// Fixed wire revision for [`SESSION_QUORUM_CONSUMER_V2_ALPN`].
///
/// The V2 server rejects every other Hello revision before dispatch.
pub const SESSION_QUORUM_CONSUMER_V2_TRANSPORT_REVISION: u16 = 5;

/// Maximum sequential application requests processed on one consumer
/// connection. Every request has an exact nonzero connection-local
/// correlation and only one can be in flight.
pub const MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION: usize = 4096;
/// Fixed logical width of the nonzero connection-local correlation value.
pub const SESSION_QUORUM_CONSUMER_CORRELATION_ID_BYTES: usize = std::mem::size_of::<u32>();
/// Revision 3 deliberately admits one in-flight request per physical lane.
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
/// Hard request-connection admission shared by one stateless clone lineage.
pub const MAX_STATELESS_SESSION_CONSUMER_REQUEST_CONNECTIONS: usize = 16;
/// Hard watch-connection admission shared by one stateless clone lineage.
pub const MAX_STATELESS_SESSION_CONSUMER_WATCH_CONNECTIONS: usize = 16;
/// One pool-wide maintenance task owns idle retirement and replenishment.
pub const PERSISTENT_SESSION_CONSUMER_MAINTENANCE_TASKS_PER_POOL: usize = 1;
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
        SessionConsumerOperation::FencedTransition { request }
        | SessionConsumerOperation::FencedTransitionStatus { request } => request
            .mutation()
            .record()
            .is_some_and(|record| debit_payload(&mut remaining, record.payload.as_bytes())),
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

fn effective_consumer_idle_timeout(timeout: Duration) -> Duration {
    timeout.min(DEFAULT_CONSUMER_IDLE_TIMEOUT)
}

fn effective_consumer_operation_timeout(timeout: Duration) -> Duration {
    timeout.min(DEFAULT_CONSUMER_OPERATION_TIMEOUT)
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
struct ConsumerFrameReadProgress<'a> {
    started: AtomicBool,
    poison_authority: Option<&'a PersistentV2LaneLifetime>,
    poison_armed: AtomicBool,
}

impl<'a> ConsumerFrameReadProgress<'a> {
    fn unarmed() -> Self {
        Self {
            started: AtomicBool::new(false),
            poison_authority: None,
            poison_armed: AtomicBool::new(false),
        }
    }

    fn read_ahead(poison_authority: &'a PersistentV2LaneLifetime) -> Self {
        Self {
            started: AtomicBool::new(false),
            poison_authority: Some(poison_authority),
            poison_armed: AtomicBool::new(true),
        }
    }

    fn started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }

    fn disarm_poison(&self) {
        self.poison_armed.store(false, Ordering::Release);
    }

    fn observe_positive_byte(&self) {
        if self.started() {
            return;
        }
        // A read-ahead byte becomes pool-wide debt before this decoder makes
        // its local positive-byte state visible.  The authority reservation
        // holds the same short queue lock that a checkout uses to consume
        // front poison, so another lane cannot be selected in between.
        if self.poison_armed.swap(false, Ordering::AcqRel) {
            if let Some(authority) = self.poison_authority {
                authority.install_poison_ticket();
            }
        }
        self.started.store(true, Ordering::Release);
    }

    fn observe_positive_byte_with_queue_lock(
        &self,
        pool: &PersistentSessionConsumerV2Pool,
        idle: &mut VecDeque<PersistentV2PoolEntry>,
    ) {
        if self.started() {
            return;
        }
        if self.poison_armed.swap(false, Ordering::AcqRel) {
            if let Some(authority) = self.poison_authority {
                authority.install_poison_ticket_locked(pool, idle);
            }
        }
        self.started.store(true, Ordering::Release);
    }
}

struct ConsumerProgressReader<'a, R> {
    inner: &'a mut R,
    progress: &'a ConsumerFrameReadProgress<'a>,
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
        // For an armed read-ahead decoder, serialize the nonblocking TLS poll
        // with queue checkout. The guard never crosses Pending or an await,
        // but it closes the otherwise observable plaintext-before-poison gap.
        if self.progress.poison_armed.load(Ordering::Acquire) {
            if let Some(pool) = self
                .progress
                .poison_authority
                .and_then(|authority| authority.pool_connection.upgrade())
            {
                let mut idle = pool
                    .idle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let result = Pin::new(&mut *self.inner).poll_read(context, buffer);
                if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
                    self.progress
                        .observe_positive_byte_with_queue_lock(&pool, &mut idle);
                }
                return result;
            }
        }
        let result = Pin::new(&mut *self.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            self.progress.observe_positive_byte();
        }
        result
    }
}

enum PersistentV2ReadAheadEvent {
    Frame,
    PositiveByte,
}

async fn persistent_v2_read_ahead_event<F>(
    mut read: Pin<&mut F>,
    progress: &ConsumerFrameReadProgress<'_>,
) -> PersistentV2ReadAheadEvent
where
    F: std::future::Future,
{
    std::future::poll_fn(|context| match read.as_mut().poll(context) {
        Poll::Ready(_) => Poll::Ready(PersistentV2ReadAheadEvent::Frame),
        Poll::Pending if progress.started() => {
            Poll::Ready(PersistentV2ReadAheadEvent::PositiveByte)
        }
        Poll::Pending => Poll::Pending,
    })
    .await
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
        | SessionConsumerOperation::Watch { .. }
        | SessionConsumerOperation::FencedTransitionCapability
        | SessionConsumerOperation::ObserveFencedTransition { .. }
        | SessionConsumerOperation::FencedTransitionStatus { .. } => false,
        SessionConsumerOperation::Batch { ops } => ops
            .iter()
            .any(|operation| !matches!(operation, SessionOp::Get { .. })),
        SessionConsumerOperation::CompareAndSet { .. }
        | SessionConsumerOperation::DeleteFenced { .. }
        | SessionConsumerOperation::RefreshTtl { .. }
        | SessionConsumerOperation::AcquireLease { .. }
        | SessionConsumerOperation::RenewLease { .. }
        | SessionConsumerOperation::ReleaseLease { .. }
        | SessionConsumerOperation::FencedTransition { .. } => true,
        _ => true,
    }
}

/// Revision 3 deliberately binds the outer consumer id to the complete
/// fenced-transition body's stable id byte-for-byte.  Keep this check at both
/// client and listener boundaries so a hand-built generic request cannot
/// submit one durable body under a second public identity.
fn consumer_request_has_exact_fenced_transition_id(request: &SessionConsumerRequest) -> bool {
    match request.operation() {
        SessionConsumerOperation::FencedTransition {
            request: transition,
        }
        | SessionConsumerOperation::FencedTransitionStatus {
            request: transition,
        } => request.request_id().as_bytes() == transition.request_id().as_bytes(),
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
/// selects fail-fast admission. Revision 3 and revision 5 each receive this
/// fixed request width (at most 16) and their own bounded pending queue; their
/// sockets and physical admission ceilings remain ALPN-isolated.
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

/// Result failure for an atomic fenced transition submitted through the
/// consumer port.
///
/// The stable transition identity is deliberately distinct from the generic
/// consumer request identity.  The consumer envelope is constructed from the
/// exact same sixteen bytes, but callers recover an ambiguous transition only
/// with the complete retained transition body and its own request ID.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionConsumerFencedTransitionMutationError {
    /// No application-call byte was written, so the transition did not reach
    /// the quorum and may be submitted on another admitted endpoint.
    #[error("consumer fenced transition was not transmitted: {cause}")]
    NotTransmitted {
        /// Redaction-safe pre-write transport classification.
        cause: SessionConsumerClientError,
    },
    /// The transition may have reached the quorum.  Do not automatically
    /// replay it; use only the retained identical request body and ID.
    #[error(
        "consumer fenced transition outcome is unconfirmed; recover only the retained request"
    )]
    OutcomeUnknown {
        /// Exact caller-retained transition identity.
        request_id: FencedTransitionRequestId,
    },
    /// A confirmed typed store or rejection failure.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl fmt::Debug for SessionConsumerFencedTransitionMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::NotTransmitted { .. } => "not_transmitted",
            Self::OutcomeUnknown { .. } => "outcome_unknown",
            Self::Store(_) => "store",
        };
        formatter
            .debug_struct("SessionConsumerFencedTransitionMutationError")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

impl SessionConsumerFencedTransitionMutationError {
    /// Return the only identity permitted for exact status/recovery.
    pub const fn exact_retry_id(&self) -> Option<FencedTransitionRequestId> {
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
/// pre-write reconnect attempt while retaining the exact revision-3 encoding.
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
    response: Box<ConsumerSessionResponseWire>,
}

struct BorrowedConsumerCallResponse<'a> {
    correlation: NonZeroU32,
    response: &'a ConsumerSessionResponseWire,
}

impl Serialize for BorrowedConsumerCallResponse<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("BorrowedConsumerCallResponse", 2)?;
        state.serialize_field("correlation", &self.correlation)?;
        state.serialize_field("response", self.response)?;
        state.end()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "response",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ConsumerSessionResponseWire {
    Capabilities(WireBackendCapabilities),
    FencedTransitionCapability(Result<AtomicFencedTransitionCapability, SessionConsumerStoreError>),
    ObserveFencedTransition(Result<FencedTransitionObservation, SessionConsumerStoreError>),
    FencedTransition(Result<FencedTransitionOutcome, SessionConsumerFencedTransitionError>),
    FencedTransitionStatus(
        Result<SessionConsumerFencedTransitionStatus, SessionConsumerStoreError>,
    ),
    Get(Result<Option<opc_session_store::StoredSessionRecord>, SessionConsumerStoreError>),
    PreflightRecordExpiry(Result<(), SessionConsumerStoreError>),
    CompareAndSet(Result<CompareAndSetResult, SessionConsumerStoreError>),
    DeleteFenced(Result<(), SessionConsumerStoreError>),
    RefreshTtl(Result<(), SessionConsumerStoreError>),
    Batch(Result<Vec<SessionConsumerBatchResult>, SessionConsumerStoreError>),
    ScanRestoreRecords(Result<RestoreScanPage, SessionConsumerStoreError>),
    WatchOpened,
    AcquireLease(Result<ConsumerSessionLeaseGrantWire, SessionConsumerLeaseError>),
    RenewLease(Result<ConsumerSessionLeaseGrantWire, SessionConsumerLeaseError>),
    ReleaseLease(Result<(), SessionConsumerLeaseError>),
    OutcomeUnknown(SessionConsumerOutcomeUnknown),
    Rejected(SessionConsumerRejection),
}

/// Private revision-3 lease authority envelope. The public store response
/// remains the source-compatible `LeaseGuard`; only this transport validates
/// the committed authority time before removing the envelope.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerSessionLeaseGrantWire {
    guard: LeaseGuard,
    authority_time: opc_types::Timestamp,
}

impl ConsumerSessionLeaseGrantWire {
    fn new(guard: LeaseGuard, authority_time: opc_types::Timestamp) -> Self {
        Self {
            guard,
            authority_time,
        }
    }

    fn guard(&self) -> &LeaseGuard {
        &self.guard
    }

    const fn authority_time(&self) -> opc_types::Timestamp {
        self.authority_time
    }

    fn into_guard(self) -> LeaseGuard {
        self.guard
    }
}

impl fmt::Debug for ConsumerSessionLeaseGrantWire {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsumerSessionLeaseGrantWire(<redacted>)")
    }
}

impl TryFrom<ConsumerSessionResponseWire> for SessionConsumerResponse {
    type Error = crate::protocol::WireConversionError;

    fn try_from(response: ConsumerSessionResponseWire) -> Result<Self, Self::Error> {
        Ok(match response {
            ConsumerSessionResponseWire::Capabilities(capabilities) => {
                Self::Capabilities(BackendCapabilities::try_from(capabilities)?)
            }
            ConsumerSessionResponseWire::FencedTransitionCapability(value) => {
                Self::FencedTransitionCapability(value)
            }
            ConsumerSessionResponseWire::ObserveFencedTransition(value) => {
                Self::ObserveFencedTransition(value)
            }
            ConsumerSessionResponseWire::FencedTransition(value) => Self::FencedTransition(value),
            ConsumerSessionResponseWire::FencedTransitionStatus(value) => {
                Self::FencedTransitionStatus(value)
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
            ConsumerSessionResponseWire::AcquireLease(value) => {
                Self::AcquireLease(value.map(ConsumerSessionLeaseGrantWire::into_guard))
            }
            ConsumerSessionResponseWire::RenewLease(value) => {
                Self::RenewLease(value.map(ConsumerSessionLeaseGrantWire::into_guard))
            }
            ConsumerSessionResponseWire::ReleaseLease(value) => Self::ReleaseLease(value),
            ConsumerSessionResponseWire::OutcomeUnknown(value) => Self::OutcomeUnknown(value),
            ConsumerSessionResponseWire::Rejected(value) => Self::Rejected(value),
        })
    }
}

fn consumer_authority_time_from_expiry(
    expires_at: opc_types::Timestamp,
    ttl: Duration,
) -> Option<opc_types::Timestamp> {
    let seconds = i64::try_from(ttl.as_secs()).ok()?;
    let delta = time::Duration::seconds(seconds)
        .checked_add(time::Duration::nanoseconds(i64::from(ttl.subsec_nanos())))?;
    expires_at
        .as_offset_datetime()
        .checked_sub(delta)
        .map(opc_types::Timestamp::from_offset_datetime)
}

fn consumer_wire_response_from_public(
    lease_context: ConsumerLeaseWireContext,
    response: SessionConsumerResponse,
) -> Result<ConsumerSessionResponseWire, ProtocolError> {
    Ok(match response {
        SessionConsumerResponse::Capabilities(value) => ConsumerSessionResponseWire::Capabilities(
            WireBackendCapabilities::try_from(&value)
                .map_err(|_| ProtocolError::InvalidWireValue)?,
        ),
        SessionConsumerResponse::FencedTransitionCapability(value) => {
            ConsumerSessionResponseWire::FencedTransitionCapability(value)
        }
        SessionConsumerResponse::ObserveFencedTransition(value) => {
            ConsumerSessionResponseWire::ObserveFencedTransition(value)
        }
        SessionConsumerResponse::FencedTransition(value) => {
            ConsumerSessionResponseWire::FencedTransition(value)
        }
        SessionConsumerResponse::FencedTransitionStatus(value) => {
            ConsumerSessionResponseWire::FencedTransitionStatus(value)
        }
        SessionConsumerResponse::Get(value) => ConsumerSessionResponseWire::Get(value),
        SessionConsumerResponse::PreflightRecordExpiry(value) => {
            ConsumerSessionResponseWire::PreflightRecordExpiry(value)
        }
        SessionConsumerResponse::CompareAndSet(value) => {
            ConsumerSessionResponseWire::CompareAndSet(value)
        }
        SessionConsumerResponse::DeleteFenced(value) => {
            ConsumerSessionResponseWire::DeleteFenced(value)
        }
        SessionConsumerResponse::RefreshTtl(value) => {
            ConsumerSessionResponseWire::RefreshTtl(value)
        }
        SessionConsumerResponse::Batch(value) => ConsumerSessionResponseWire::Batch(value),
        SessionConsumerResponse::ScanRestoreRecords(value) => {
            ConsumerSessionResponseWire::ScanRestoreRecords(value)
        }
        SessionConsumerResponse::WatchOpened => ConsumerSessionResponseWire::WatchOpened,
        SessionConsumerResponse::AcquireLease(value) => {
            let value = value.map(|guard| {
                let authority_time = guard.acquired_at();
                ConsumerSessionLeaseGrantWire::new(guard, authority_time)
            });
            ConsumerSessionResponseWire::AcquireLease(value)
        }
        SessionConsumerResponse::RenewLease(value) => {
            let ConsumerLeaseWireContext::Renew(ttl) = lease_context else {
                return Err(ProtocolError::UnexpectedResponse);
            };
            let value = match value {
                Ok(guard) => {
                    let authority_time =
                        consumer_authority_time_from_expiry(guard.expires_at(), ttl)
                            .ok_or(ProtocolError::InvalidWireValue)?;
                    Ok(ConsumerSessionLeaseGrantWire::new(guard, authority_time))
                }
                Err(error) => Err(error),
            };
            ConsumerSessionResponseWire::RenewLease(value)
        }
        SessionConsumerResponse::ReleaseLease(value) => {
            ConsumerSessionResponseWire::ReleaseLease(value)
        }
        SessionConsumerResponse::OutcomeUnknown(value) => {
            ConsumerSessionResponseWire::OutcomeUnknown(value)
        }
        SessionConsumerResponse::Rejected(value) => ConsumerSessionResponseWire::Rejected(value),
        _ => return Err(ProtocolError::UnexpectedResponse),
    })
}

#[derive(Clone, Copy)]
enum ConsumerLeaseWireContext {
    Other,
    Acquire,
    Renew(Duration),
}

impl ConsumerLeaseWireContext {
    fn from_operation(operation: &SessionConsumerOperation) -> Self {
        match operation {
            SessionConsumerOperation::AcquireLease { .. } => Self::Acquire,
            SessionConsumerOperation::RenewLease { ttl, .. } => Self::Renew(*ttl),
            _ => Self::Other,
        }
    }
}

fn consumer_public_response_from_wire(
    request: &SessionConsumerRequest,
    response: ConsumerSessionResponseWire,
) -> Result<SessionConsumerResponse, ProtocolError> {
    match (&response, request.operation()) {
        (
            ConsumerSessionResponseWire::AcquireLease(Ok(grant)),
            SessionConsumerOperation::AcquireLease { key, owner, ttl },
        ) => {
            let guard = grant.guard();
            if guard.key() != key
                || guard.owner() != owner
                || crate::protocol::validate_lease_profile(guard).is_err()
                || grant.authority_time() != guard.acquired_at()
                || !checked_session_deadline(grant.authority_time(), *ttl)
                    .is_ok_and(|deadline| deadline == guard.expires_at())
            {
                return Err(ProtocolError::UnexpectedResponse);
            }
        }
        (
            ConsumerSessionResponseWire::RenewLease(Ok(grant)),
            SessionConsumerOperation::RenewLease { lease, ttl },
        ) => {
            let renewed = grant.guard();
            if renewed.key() != lease.key()
                || renewed.owner() != lease.owner()
                || renewed.fence() != lease.fence()
                || renewed.credential_id() != lease.credential_id()
                || renewed.acquired_at() != lease.acquired_at()
                || crate::protocol::validate_lease_profile(renewed).is_err()
                || grant.authority_time() < lease.acquired_at()
                || grant.authority_time() >= lease.expires_at()
                || !checked_session_deadline(grant.authority_time(), *ttl)
                    .is_ok_and(|deadline| deadline == renewed.expires_at())
            {
                return Err(ProtocolError::UnexpectedResponse);
            }
        }
        (ConsumerSessionResponseWire::AcquireLease(Ok(_)), _)
        | (ConsumerSessionResponseWire::RenewLease(Ok(_)), _) => {
            return Err(ProtocolError::UnexpectedResponse);
        }
        _ => {}
    }
    SessionConsumerResponse::try_from(response).map_err(|_| ProtocolError::InvalidWireValue)
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

/// Revision-5-only call envelope. It intentionally has no V1 operation or
/// response member, so a V2 frame cannot be decoded as a V1 call frame.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerV2Call {
    correlation: NonZeroU32,
    attempt_nonce: [u8; 16],
    request_commitment: [u8; 32],
    request: Box<SessionConsumerV2Request>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerV2CallResponse {
    correlation: NonZeroU32,
    attempt_nonce: [u8; 16],
    request_commitment: [u8; 32],
    response: Box<SessionConsumerV2Response>,
}

fn v2_request_commitment(
    request: &SessionConsumerV2Request,
) -> Result<[u8; 32], serde_json::Error> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(request)?;
    let mut domain = Vec::with_capacity(32 + bytes.len());
    domain.extend_from_slice(b"opc-session-consumer-v2-call-phase");
    domain.extend_from_slice(&SESSION_QUORUM_CONSUMER_V2_TRANSPORT_REVISION.to_be_bytes());
    domain.extend_from_slice(&bytes);
    Ok(Sha256::digest(domain).into())
}

fn v2_attempt_nonce() -> Result<[u8; 16], rand::rngs::SysError> {
    use rand::TryRng;
    let mut nonce = [0_u8; 16];
    let mut rng = rand::rngs::SysRng;
    rng.try_fill_bytes(&mut nonce)?;
    Ok(nonce)
}

/// Private wire family admitted only after the V2 ALPN and exact revision-5
/// handshake. Keeping it as a separate enum freezes revision 3's postcard
/// and JSON discriminator ordering.
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ConsumerV2WireRequest {
    Hello(ConsumerHello),
    Call(ConsumerV2Call),
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ConsumerV2WireResponse {
    HelloAck(ConsumerHelloAck),
    HelloRejected(SessionConsumerRejection),
    Response(ConsumerV2CallResponse),
}

fn v2_response_matches_operation(
    operation: &SessionConsumerV2Operation,
    response: &SessionConsumerV2Response,
) -> bool {
    match (operation, response) {
        // A generic rejection does not carry a V2 transition identity. It is
        // safe only for the V2 read surface; an effectful Call that may have
        // reached the service must retain its exact recovery identity.
        (_, SessionConsumerV2Response::Rejected(_)) => !v2_operation_is_effectful(operation),
        (
            SessionConsumerV2Operation::FencedTransitionV2Capability,
            SessionConsumerV2Response::FencedTransitionV2Capability(_),
        )
        | (
            SessionConsumerV2Operation::FencedTransitionV2HistoryState,
            SessionConsumerV2Response::FencedTransitionV2HistoryState(_),
        )
        | (
            SessionConsumerV2Operation::FencedTransitionV2 { .. },
            SessionConsumerV2Response::FencedTransitionV2(_),
        )
        | (
            SessionConsumerV2Operation::FencedTransitionV2Batch { .. },
            SessionConsumerV2Response::FencedTransitionV2Batch(_),
        )
        | (
            SessionConsumerV2Operation::FencedTransitionV2Status { .. },
            SessionConsumerV2Response::FencedTransitionV2Status(_),
        ) => true,
        _ => false,
    }
}

/// Validate the V2 result shape after the wire discriminator has matched.
///
/// The full self-authenticating request ID remains part of the request passed
/// to this function; comparing only a nonce or an old 16-byte consumer ID
/// would allow a response from a distinct committed V2 body to be accepted.
fn v2_response_matches_request(
    request: &SessionConsumerV2Request,
    response: &SessionConsumerV2Response,
) -> bool {
    if !v2_response_matches_operation(request.operation(), response) {
        return false;
    }
    match (request.operation(), response) {
        (
            SessionConsumerV2Operation::FencedTransitionV2 { request },
            SessionConsumerV2Response::FencedTransitionV2(Ok(outcome)),
        ) => outcome.matches_v2_request(request),
        // A singleton error carries no complete V2 request identity or body
        // witness. After Call transmission it could be substituted from any
        // request, so only an exact outcome can complete this mutation.
        (
            SessionConsumerV2Operation::FencedTransitionV2 { .. },
            SessionConsumerV2Response::FencedTransitionV2(Err(error)),
        ) => error.is_pre_dispatch_deterministic(),
        (
            SessionConsumerV2Operation::FencedTransitionV2Batch { requests },
            SessionConsumerV2Response::FencedTransitionV2Batch(Ok(results)),
        ) => {
            results.len() == requests.len()
                && opc_session_store::consumer::validate_session_consumer_v2_fenced_transition_batch_results(results)
                    .is_ok()
                && requests.iter().zip(results).all(|(request, result)| {
                    // Every batch item repeats the self-authenticating V2
                    // identity. This binds an item error as well as a
                    // success to the exact ordered request body.
                    result.request_id() == request.request_id()
                        && match result.result() {
                            Ok(outcome) => outcome.matches_v2_request(request),
                            Err(error) => error.is_wire_valid(),
                        }
                })
        }
        (
            SessionConsumerV2Operation::FencedTransitionV2Batch { requests },
            SessionConsumerV2Response::FencedTransitionV2Batch(Err(error)),
        ) => {
            error.validate().is_ok()
                && match error {
                    // A batch-wide store error has no identity vector and is
                    // therefore not a definitive response after Call bytes.
                    opc_session_store::consumer::SessionConsumerV2FencedTransitionBatchError::Store(_) => false,
                    opc_session_store::consumer::SessionConsumerV2FencedTransitionBatchError::OutcomeUnknown { request_ids } => {
                        request_ids.len() == requests.len()
                            && requests
                                .iter()
                                .map(opc_session_store::FencedTransitionV2Request::request_id)
                                .eq(request_ids.iter().copied())
                    }
                    _ => false,
                }
        }
        (
            SessionConsumerV2Operation::FencedTransitionV2Status { request },
            SessionConsumerV2Response::FencedTransitionV2Status(Ok(
                opc_session_store::SessionConsumerV2FencedTransitionStatus::Recorded(result),
            )),
        ) => match result.as_ref() {
            Ok(outcome) => outcome.matches_v2_request(request),
            // A retained deterministic transition failure is already bound
            // to the complete request by the V2 receipt codec. It contains
            // no success outcome to correlate further, but it must still be
            // one of the fixed V2 receipt errors.
            Err(error) => error.is_recorded_deterministic(),
        },
        // Error and status variants are closed by their V2-specific wire
        // discriminators. The authoritative service validates the complete
        // request body before producing them; no response is a license to
        // replay an operation.
        _ => true,
    }
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
    FencedTransitionCapability,
    ObserveFencedTransition,
    FencedTransition,
    FencedTransitionStatus,
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
            SessionConsumerOperation::FencedTransitionCapability => {
                Self::FencedTransitionCapability
            }
            SessionConsumerOperation::ObserveFencedTransition { .. } => {
                Self::ObserveFencedTransition
            }
            SessionConsumerOperation::FencedTransition { .. } => Self::FencedTransition,
            SessionConsumerOperation::FencedTransitionStatus { .. } => Self::FencedTransitionStatus,
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
        ) | (
            ConsumerOperationKind::FencedTransitionCapability,
            SessionConsumerResponse::FencedTransitionCapability(_)
        ) | (
            ConsumerOperationKind::ObserveFencedTransition,
            SessionConsumerResponse::ObserveFencedTransition(_)
        ) | (
            ConsumerOperationKind::FencedTransition,
            SessionConsumerResponse::FencedTransition(_)
        ) | (
            ConsumerOperationKind::FencedTransitionStatus,
            SessionConsumerResponse::FencedTransitionStatus(_)
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
                SessionConsumerResponse::OutcomeUnknown(
                    SessionConsumerOutcomeUnknown::Mutation { .. }
                ),
            )
            | (
                ConsumerOperationKind::Batch {
                    contains_mutation: true,
                },
                SessionConsumerResponse::OutcomeUnknown(
                    SessionConsumerOutcomeUnknown::Mutation { .. }
                ),
            )
            | (
                ConsumerOperationKind::UnknownEffectful,
                SessionConsumerResponse::OutcomeUnknown(
                    SessionConsumerOutcomeUnknown::Mutation { .. }
                ),
            )
            | (
                ConsumerOperationKind::FencedTransition,
                SessionConsumerResponse::OutcomeUnknown(
                    SessionConsumerOutcomeUnknown::Mutation { .. }
                ),
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
        SessionConsumerOperation::FencedTransitionCapability => matches!(
            error,
            SessionConsumerStoreError::Unavailable
                | SessionConsumerStoreError::CapabilityNotSupported
                | SessionConsumerStoreError::ProtectedDataRejected
        ),
        SessionConsumerOperation::ObserveFencedTransition { .. } => matches!(
            error,
            SessionConsumerStoreError::Unavailable
                | SessionConsumerStoreError::InvalidInput
                | SessionConsumerStoreError::CapabilityNotSupported
                | SessionConsumerStoreError::ProtectedDataRejected
        ),
        SessionConsumerOperation::FencedTransition { .. } => {
            fenced_transition_execute_store_error_matches(error)
        }
        SessionConsumerOperation::FencedTransitionStatus { .. } => matches!(
            error,
            SessionConsumerStoreError::RequestConflict
                | SessionConsumerStoreError::Unavailable
                | SessionConsumerStoreError::InvalidInput
                | SessionConsumerStoreError::CapabilityNotSupported
                | SessionConsumerStoreError::ProtectedDataRejected
        ),
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

/// Closed revision-3 error family for an already-open watch. These are the
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
        (
            SessionConsumerOperation::FencedTransitionCapability,
            SessionConsumerResponse::FencedTransitionCapability(result),
        ) => store_result_matches_operation(request.operation(), result),
        (
            SessionConsumerOperation::ObserveFencedTransition { key },
            SessionConsumerResponse::ObserveFencedTransition(Ok(observation)),
        ) => observation.record().is_none_or(|record| {
            record.key == *key
                && record.fence <= observation.current_fence()
                && record.payload.encoding() == SessionPayloadEncoding::EnvelopeV1
                && validate_stored_record_expiry_profile(record).is_ok()
        }),
        (
            SessionConsumerOperation::ObserveFencedTransition { .. },
            SessionConsumerResponse::ObserveFencedTransition(result),
        ) => store_result_matches_operation(request.operation(), result),
        (
            SessionConsumerOperation::FencedTransition {
                request: transition,
            },
            SessionConsumerResponse::FencedTransition(Ok(outcome)),
        ) => outcome.matches_request(transition),
        (
            SessionConsumerOperation::FencedTransition { .. },
            SessionConsumerResponse::FencedTransition(Err(error)),
        ) => fenced_transition_execute_error_matches_request(error),
        (
            SessionConsumerOperation::FencedTransitionStatus {
                request: transition,
            },
            SessionConsumerResponse::FencedTransitionStatus(Ok(status)),
        ) => fenced_transition_status_matches_request(transition, status),
        (
            SessionConsumerOperation::FencedTransitionStatus { .. },
            SessionConsumerResponse::FencedTransitionStatus(result),
        ) => store_result_matches_operation(request.operation(), result),
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
            SessionConsumerResponse::AcquireLease(Ok(lease)),
        ) => {
            lease.key() == key
                && lease.owner() == owner
                && crate::protocol::validate_lease_profile(lease).is_ok()
                && checked_session_deadline(lease.acquired_at(), *ttl)
                    .is_ok_and(|deadline| deadline == lease.expires_at())
        }
        (
            SessionConsumerOperation::AcquireLease { .. },
            SessionConsumerResponse::AcquireLease(Err(error)),
        ) => lease_error_matches_operation(request.operation(), *error),
        (
            SessionConsumerOperation::RenewLease { lease, ttl },
            SessionConsumerResponse::RenewLease(Ok(renewed)),
        ) => {
            let authority_time = consumer_authority_time_from_expiry(renewed.expires_at(), *ttl);
            renewed.key() == lease.key()
                && renewed.owner() == lease.owner()
                && renewed.fence() == lease.fence()
                && renewed.credential_id() == lease.credential_id()
                && renewed.acquired_at() == lease.acquired_at()
                && crate::protocol::validate_lease_profile(renewed).is_ok()
                && authority_time.is_some_and(|authority_time| {
                    authority_time >= lease.acquired_at()
                        && authority_time < lease.expires_at()
                        && checked_session_deadline(authority_time, *ttl)
                            .is_ok_and(|deadline| deadline == renewed.expires_at())
                })
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
        | (_, SessionConsumerResponse::Rejected(_)) => true,
        (
            _,
            SessionConsumerResponse::OutcomeUnknown(SessionConsumerOutcomeUnknown::Mutation {
                request_id,
            }),
        ) => {
            consumer_operation_is_effectful(request.operation())
                && *request_id == request.request_id()
        }
        (
            SessionConsumerOperation::AcquireLease { .. }
            | SessionConsumerOperation::RenewLease { .. }
            | SessionConsumerOperation::ReleaseLease { .. },
            SessionConsumerResponse::OutcomeUnknown(SessionConsumerOutcomeUnknown::Lease),
        ) => true,
        _ => false,
    }
}

/// Validate every transition recovery form against the complete exact body
/// retained by the caller.  In particular, a status response must not turn a
/// receipt for a different key, owner, fence, or payload-bearing body into a
/// successful recovery.
fn fenced_transition_status_matches_request(
    request: &FencedTransitionRequest,
    status: &SessionConsumerFencedTransitionStatus,
) -> bool {
    match status {
        SessionConsumerFencedTransitionStatus::Recorded(result) => match result.as_ref() {
            Ok(outcome) => outcome.matches_request(request),
            Err(error) => fenced_transition_recorded_error_matches_request(error),
        },
        SessionConsumerFencedTransitionStatus::RequestConflict
        | SessionConsumerFencedTransitionStatus::Expired
        | SessionConsumerFencedTransitionStatus::HistoryFull
        | SessionConsumerFencedTransitionStatus::RetentionExhausted
        | SessionConsumerFencedTransitionStatus::NotFound => true,
        _ => false,
    }
}

/// Direct execution can report the complete safe execution-error inventory.
/// A retained receipt is deliberately stricter: it can contain only an exact
/// deterministic no-effect result, never an availability or request-binding
/// failure that could not safely have been persisted as that receipt.
fn fenced_transition_execute_error_matches_request(
    error: &SessionConsumerFencedTransitionError,
) -> bool {
    match error {
        SessionConsumerFencedTransitionError::Store(error) => {
            fenced_transition_execute_store_error_matches(*error)
        }
        SessionConsumerFencedTransitionError::RequestConflict
        | SessionConsumerFencedTransitionError::Expired
        | SessionConsumerFencedTransitionError::HistoryFull
        | SessionConsumerFencedTransitionError::RetentionExhausted
        | SessionConsumerFencedTransitionError::StorageExhausted => true,
        _ => false,
    }
}

fn fenced_transition_recorded_error_matches_request(
    error: &SessionConsumerFencedTransitionError,
) -> bool {
    match error {
        SessionConsumerFencedTransitionError::Store(error) => {
            fenced_transition_recorded_store_error_matches(*error)
        }
        SessionConsumerFencedTransitionError::StorageExhausted => true,
        _ => false,
    }
}

fn fenced_transition_execute_store_error_matches(error: SessionConsumerStoreError) -> bool {
    matches!(
        error,
        SessionConsumerStoreError::NotFound
            | SessionConsumerStoreError::StaleFence
            | SessionConsumerStoreError::CasConflict
            | SessionConsumerStoreError::RequestConflict
            | SessionConsumerStoreError::OutcomeUnavailable
            | SessionConsumerStoreError::Unavailable
            | SessionConsumerStoreError::InvalidInput
            | SessionConsumerStoreError::CapabilityNotSupported
            | SessionConsumerStoreError::InvalidTtl
            | SessionConsumerStoreError::LeaseUnavailable
            | SessionConsumerStoreError::PayloadTooLarge
            | SessionConsumerStoreError::ProtectedDataRejected
    )
}

fn fenced_transition_recorded_store_error_matches(error: SessionConsumerStoreError) -> bool {
    matches!(
        error,
        SessionConsumerStoreError::NotFound
            | SessionConsumerStoreError::StaleFence
            | SessionConsumerStoreError::CasConflict
            | SessionConsumerStoreError::InvalidInput
            | SessionConsumerStoreError::InvalidTtl
            | SessionConsumerStoreError::LeaseUnavailable
            | SessionConsumerStoreError::PayloadTooLarge
    )
}

fn consumer_capability_payload_budget(
    request_frame_size: usize,
    response_frame_size: usize,
) -> usize {
    conservative_payload_budget(request_frame_size)
        .min(conservative_payload_budget(response_frame_size))
}

fn response_respects_consumer_capability_budget(
    response: &SessionConsumerResponse,
    request_frame_size: usize,
    response_frame_size: usize,
) -> bool {
    match response {
        SessionConsumerResponse::Capabilities(capabilities) => {
            capabilities.max_value_bytes
                <= consumer_capability_payload_budget(request_frame_size, response_frame_size)
        }
        _ => true,
    }
}

fn clamp_consumer_capabilities(
    response: &mut SessionConsumerResponse,
    request_frame_size: usize,
    response_frame_size: usize,
) {
    if let SessionConsumerResponse::Capabilities(capabilities) = response {
        capabilities.max_value_bytes =
            capabilities
                .max_value_bytes
                .min(consumer_capability_payload_budget(
                    request_frame_size,
                    response_frame_size,
                ));
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
        SessionConsumerResponse::FencedTransition(Err(
            SessionConsumerFencedTransitionError::Store(
                SessionConsumerStoreError::OutcomeUnavailable,
            ),
        )) => true,
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
        SessionConsumerResponse::FencedTransition(Err(_))
        | SessionConsumerResponse::Get(Err(_))
        | SessionConsumerResponse::ObserveFencedTransition(Err(_))
        | SessionConsumerResponse::FencedTransitionStatus(Err(_))
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
        SessionConsumerResponse::FencedTransitionStatus(Ok(
            SessionConsumerFencedTransitionStatus::Recorded(result),
        )) => result.is_err(),
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
/// adapter, so the decoded revision-3 type is serialized through a streaming
/// byte comparator against the bounded received payload. This rejects aliases,
/// omissions, noncanonical encodings, and unknown nested fields without a
/// second buffer, a generic JSON tree, or surfacing their content.
#[cfg(test)]
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
    let progress = ConsumerFrameReadProgress::unarmed();
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

async fn read_authenticated_consumer_bootstrap_frame_until<R, T>(
    reader: &mut R,
    max_frame_size: usize,
    setup_deadline: tokio::time::Instant,
    active_timeout: Duration,
) -> Result<Option<T>, ProtocolError>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de> + Serialize,
{
    let progress = ConsumerFrameReadProgress::unarmed();
    let mut reader = ConsumerProgressReader {
        inner: reader,
        progress: &progress,
    };
    let payload = read_authenticated_frame_payload_with_active_timeout_until(
        &mut reader,
        max_frame_size,
        setup_deadline,
        active_timeout,
    )
    .await
    .map_err(|error| {
        if progress.started() && consumer_watch_transport_lost(&error) {
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
/// buffer or materializing generic value trees. Revision 3 is emitted only by
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
    consumer_client_tls_config_for_alpn(config, SESSION_QUORUM_CONSUMER_ALPN)
}

fn consumer_client_tls_config_v2(config: Arc<opc_tls::ClientConfig>) -> Arc<opc_tls::ClientConfig> {
    consumer_client_tls_config_for_alpn(config, SESSION_QUORUM_CONSUMER_V2_ALPN)
}

fn consumer_client_tls_config_for_alpn(
    config: Arc<opc_tls::ClientConfig>,
    alpn: &[u8],
) -> Arc<opc_tls::ClientConfig> {
    let mut config = config.as_ref().clone();
    config.alpn_protocols = vec![alpn.to_vec()];
    config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Arc::new(config)
}

fn consumer_server_tls_config(config: Arc<opc_tls::ServerConfig>) -> Arc<opc_tls::ServerConfig> {
    let mut config = config.as_ref().clone();
    // The client's one-element ALPN offer selects exactly one lane. Keeping
    // both names here lets one listener serve V1/revision 3 and V2/revision 5
    // without falling back across their semantic boundary.
    config.alpn_protocols = vec![
        SESSION_QUORUM_CONSUMER_V2_ALPN.to_vec(),
        SESSION_QUORUM_CONSUMER_ALPN.to_vec(),
    ];
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
    /// High bit is the irreversible forced state; remaining bits are the
    /// number of synchronous transport polls that linearized before it.
    state: AtomicUsize,
    quiescent: Notify,
    #[cfg(test)]
    enter_hook: StdMutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl PersistentConsumerIoBarrier {
    const FORCED: usize = 1_usize << (usize::BITS - 1);
    const ACTIVE_MASK: usize = Self::FORCED - 1;

    fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
            quiescent: Notify::new(),
            #[cfg(test)]
            enter_hook: StdMutex::new(None),
        }
    }

    fn is_forced(&self) -> bool {
        self.state.load(Ordering::Acquire) & Self::FORCED != 0
    }

    fn enter(&self) -> Option<PersistentConsumerIoPoll<'_>> {
        let mut observed = self.state.load(Ordering::Acquire);
        #[cfg(test)]
        if let Some(hook) = self
            .enter_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            hook();
        }
        loop {
            if observed & Self::FORCED != 0 || observed & Self::ACTIVE_MASK == Self::ACTIVE_MASK {
                return None;
            }
            match self.state.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(PersistentConsumerIoPoll { barrier: self }),
                Err(current) => observed = current,
            }
        }
    }

    fn leave(&self) {
        let previous = self.state.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous & Self::ACTIVE_MASK != 0);
        if previous & Self::ACTIVE_MASK == 1 {
            // Retain a permit if the shutdown driver has not registered its
            // waiter yet; there is only one pool-owned quiescence waiter.
            self.quiescent.notify_one();
        }
    }

    fn force(&self) {
        self.state.fetch_or(Self::FORCED, Ordering::AcqRel);
    }

    async fn wait_quiescent(&self) {
        loop {
            let quiescent = self.quiescent.notified();
            tokio::pin!(quiescent);
            quiescent.as_mut().enable();
            if self.state.load(Ordering::Acquire) & Self::ACTIVE_MASK == 0 {
                return;
            }
            quiescent.await;
        }
    }

    #[cfg(test)]
    fn set_enter_hook(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self
            .enter_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
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

async fn poll_persistent_consumer_setup_io<F, T>(
    future: F,
    barrier: Option<&Arc<PersistentConsumerIoBarrier>>,
) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    tokio::pin!(future);
    std::future::poll_fn(|context| {
        let poll = match barrier {
            Some(barrier) => Some(barrier.enter().ok_or_else(forced_consumer_io_error)?),
            None => None,
        };
        let result = std::future::Future::poll(future.as_mut(), context);
        drop(poll);
        result
    })
    .await
}

#[cfg(test)]
struct PersistentConsumerShutdownReader<R> {
    inner: R,
    barrier: Arc<PersistentConsumerIoBarrier>,
}

#[cfg(test)]
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

#[cfg(test)]
struct PersistentConsumerShutdownWriter<W> {
    inner: W,
    barrier: Arc<PersistentConsumerIoBarrier>,
}

/// Transport wrapper installed both below TLS and around the completed TLS
/// stream so forced shutdown supervises TCP plus buffered TLS/Hello/frame
/// polls through one linearizable barrier.
struct PersistentConsumerShutdownIo<T> {
    inner: T,
    barrier: Option<Arc<PersistentConsumerIoBarrier>>,
}

impl<T> AsyncRead for PersistentConsumerShutdownIo<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = match this.barrier.as_ref() {
            Some(barrier) => Some(barrier.enter().ok_or_else(forced_consumer_io_error)?),
            None => None,
        };
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        drop(poll);
        result
    }
}

impl<T> AsyncWrite for PersistentConsumerShutdownIo<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = match this.barrier.as_ref() {
            Some(barrier) => Some(barrier.enter().ok_or_else(forced_consumer_io_error)?),
            None => None,
        };
        let result = Pin::new(&mut this.inner).poll_write(context, bytes);
        drop(poll);
        result
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = match this.barrier.as_ref() {
            Some(barrier) => Some(barrier.enter().ok_or_else(forced_consumer_io_error)?),
            None => None,
        };
        let result = Pin::new(&mut this.inner).poll_flush(context);
        drop(poll);
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = match this.barrier.as_ref() {
            Some(barrier) => Some(barrier.enter().ok_or_else(forced_consumer_io_error)?),
            None => None,
        };
        let result = Pin::new(&mut this.inner).poll_shutdown(context);
        drop(poll);
        result
    }
}

#[cfg(test)]
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
    rotation_jitter: Duration,
    next_correlation: NonZeroU32,
    calls: usize,
    idle_deadline: tokio::time::Instant,
    /// Exact server-advertised request-frame ceiling for this revision-3 lane.
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
    v1_requests: Arc<Semaphore>,
    v2_requests: Arc<Semaphore>,
    watches: Arc<Semaphore>,
}

impl StatelessConsumerPhysicalAdmission {
    fn new() -> Self {
        Self {
            // Request revisions are physically and cryptographically
            // separated by ALPN. Keep their fixed admissions separate too:
            // legal V1 and V2 pools can coexist, while stateless clones can
            // never consume more than the published V1 bound.
            v1_requests: Arc::new(Semaphore::new(
                MAX_STATELESS_SESSION_CONSUMER_REQUEST_CONNECTIONS,
            )),
            v2_requests: Arc::new(Semaphore::new(
                MAX_STATELESS_SESSION_CONSUMER_REQUEST_CONNECTIONS,
            )),
            watches: Arc::new(Semaphore::new(
                MAX_STATELESS_SESSION_CONSUMER_WATCH_CONNECTIONS,
            )),
        }
    }

    fn try_acquire_v1(&self) -> Result<OwnedSemaphorePermit, SessionConsumerClientError> {
        Arc::clone(&self.v1_requests)
            .try_acquire_owned()
            .map_err(|_| SessionConsumerClientError::Overloaded)
    }

    fn try_acquire_v2(&self) -> Result<OwnedSemaphorePermit, SessionConsumerClientError> {
        Arc::clone(&self.v2_requests)
            .try_acquire_owned()
            .map_err(|_| SessionConsumerClientError::Overloaded)
    }

    fn try_acquire_watch(&self) -> Result<OwnedSemaphorePermit, SessionConsumerClientError> {
        Arc::clone(&self.watches)
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
            self.rotation_jitter,
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
    material_status: opc_tls::TlsMaterialStatus,
    rotation_jitter: Duration,
) {
    lifecycle.observe_authenticated_rotation(now, generation, material_status, rotation_jitter);
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
    rotation_jitter: Duration,
) -> bool {
    let now = tokio::time::Instant::now();
    let current_generation = reauthentication.generation();
    let current_material_status = config.material_status();
    observe_consumer_rotation(
        lifecycle,
        now,
        current_generation,
        current_material_status,
        rotation_jitter,
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
    rotation_jitter: Duration,
) -> bool {
    let now = tokio::time::Instant::now();
    let current_generation = reauthentication.generation();
    let current_material_status = config.material_status();
    observe_consumer_rotation(
        lifecycle,
        now,
        current_generation,
        current_material_status,
        rotation_jitter,
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

const AUTHENTICATED_CONSUMER_FENCED_TRANSITION_ONLY_CAPABILITY: &str =
    "authenticated_consumer_fenced_transition_only";

fn authenticated_consumer_fenced_transition_only() -> StoreError {
    StoreError::CapabilityNotSupported(
        AUTHENTICATED_CONSUMER_FENCED_TRANSITION_ONLY_CAPABILITY.into(),
    )
}

fn invalid_authenticated_consumer_fenced_transition() -> StoreError {
    StoreError::Serialization("prepared_fenced_transition_invalid".into())
}

/// Redaction-safe construction failure for
/// [`SessionConsumerFencedTransitionBackend`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("authenticated consumer identity is unavailable")]
pub struct SessionConsumerFencedTransitionBackendError;

#[derive(Clone)]
enum SessionConsumerFencedTransitionClient {
    Stateless(Box<StatelessSessionConsumerClient>),
    Persistent(PersistentSessionConsumerClient),
}

impl SessionConsumerFencedTransitionClient {
    async fn preflight_record_expiry(
        &self,
        preflights: Vec<RecordExpiryPreflight>,
    ) -> Result<(), StoreError> {
        match self {
            Self::Stateless(client) => client.preflight_record_expiry(preflights).await,
            Self::Persistent(client) => client.preflight_record_expiry(preflights).await,
        }
    }

    async fn capability(&self) -> Result<AtomicFencedTransitionCapability, StoreError> {
        match self {
            Self::Stateless(client) => client.fenced_transition_capability().await,
            Self::Persistent(client) => client.fenced_transition_capability().await,
        }
    }

    async fn observe(
        &self,
        key: opc_session_store::SessionKey,
    ) -> Result<FencedTransitionObservation, StoreError> {
        match self {
            Self::Stateless(client) => client.observe_fenced_transition(key).await,
            Self::Persistent(client) => client.observe_fenced_transition(key).await,
        }
    }

    async fn execute(
        &self,
        request: &FencedTransitionRequest,
    ) -> Result<FencedTransitionOutcome, SessionConsumerFencedTransitionMutationError> {
        match self {
            Self::Stateless(client) => client.fenced_transition(request).await,
            Self::Persistent(client) => client.fenced_transition(request).await,
        }
    }

    async fn status(
        &self,
        request: &FencedTransitionRequest,
    ) -> Result<SessionConsumerFencedTransitionStatus, StoreError> {
        match self {
            Self::Stateless(client) => client.fenced_transition_status(request).await,
            Self::Persistent(client) => client.fenced_transition_status(request).await,
        }
    }
}

/// Narrow [`SessionBackend`] adapter for the atomic fenced-transition subset
/// of an authenticated consumer client.
///
/// This intentionally does not implement `SessionLeaseManager` and every
/// unrelated backend operation rejects locally before client/transport I/O.
/// Its prepared tokens carry an opaque binding to the local authenticated
/// consumer identity and stable cluster identity; endpoint, leader, server
/// identity, and mutable configuration scope are deliberately excluded so a
/// normal authenticated failover remains usable.
#[derive(Clone)]
pub struct SessionConsumerFencedTransitionBackend {
    client: SessionConsumerFencedTransitionClient,
    binding_commitment: [u8; 32],
}

impl fmt::Debug for SessionConsumerFencedTransitionBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerFencedTransitionBackend(<redacted>)")
    }
}

impl SessionConsumerFencedTransitionBackend {
    /// Adapt a stateless authenticated consumer client to the atomic physical
    /// transition surface.
    pub fn stateless(
        client: StatelessSessionConsumerClient,
    ) -> Result<Self, SessionConsumerFencedTransitionBackendError> {
        let binding_commitment = authenticated_consumer_binding(
            client.tls_config.local_spiffe_identity_commitment(),
            client.scope(),
        )?;
        Ok(Self {
            client: SessionConsumerFencedTransitionClient::Stateless(Box::new(client)),
            binding_commitment,
        })
    }

    /// Adapt a persistent authenticated consumer client to the atomic
    /// physical transition surface.
    pub fn persistent(
        client: PersistentSessionConsumerClient,
    ) -> Result<Self, SessionConsumerFencedTransitionBackendError> {
        let binding_commitment = authenticated_consumer_binding(
            client
                .pool
                .client
                .tls_config
                .local_spiffe_identity_commitment(),
            client.scope(),
        )?;
        Ok(Self {
            client: SessionConsumerFencedTransitionClient::Persistent(client),
            binding_commitment,
        })
    }

    fn decode_prepared(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> Result<FencedTransitionRequest, StoreError> {
        let request = prepared.request_for_authenticated_consumer(self.binding_commitment)?;
        opc_session_store::validate_consensus_physical_fenced_transition_request(&request)?;
        Ok(request)
    }
}

fn authenticated_consumer_binding(
    local_identity_commitment: Option<[u8; 32]>,
    scope: SessionConsumerScope,
) -> Result<[u8; 32], SessionConsumerFencedTransitionBackendError> {
    let local_identity_commitment =
        local_identity_commitment.ok_or(SessionConsumerFencedTransitionBackendError)?;
    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consumer/fenced-transition-physical/v1\0");
    digest.update(local_identity_commitment);
    digest.update(scope.consensus_identity().cluster_id().as_bytes());
    Ok(digest.finalize().into())
}

fn consumer_status_into_fenced_transition(
    status: SessionConsumerFencedTransitionStatus,
) -> Result<FencedTransitionStatus, StoreError> {
    Ok(match status {
        SessionConsumerFencedTransitionStatus::Recorded(result) => {
            FencedTransitionStatus::Recorded(Box::new(match *result {
                Ok(outcome) => Ok(outcome),
                Err(error) => Err(consumer_fenced_transition_store_error(error)),
            }))
        }
        SessionConsumerFencedTransitionStatus::RequestConflict => {
            FencedTransitionStatus::RequestConflict
        }
        SessionConsumerFencedTransitionStatus::Expired => FencedTransitionStatus::Expired,
        SessionConsumerFencedTransitionStatus::HistoryFull => FencedTransitionStatus::HistoryFull,
        SessionConsumerFencedTransitionStatus::RetentionExhausted => {
            FencedTransitionStatus::RetentionExhausted
        }
        SessionConsumerFencedTransitionStatus::NotFound => FencedTransitionStatus::NotFound,
        _ => return Err(invalid_authenticated_consumer_fenced_transition()),
    })
}

fn consumer_execute_into_fenced_transition(
    request: &FencedTransitionRequest,
    result: Result<FencedTransitionOutcome, SessionConsumerFencedTransitionMutationError>,
) -> Result<FencedTransitionOutcome, FencedTransitionExecuteError> {
    let request_id = request.request_id();
    match result {
        Ok(outcome) if outcome.matches_request(request) => Ok(outcome),
        // Concrete clients already convert a malformed or mismatched
        // post-write response to ambiguity. Preserve that conservative effect
        // classification if another implementation reaches this boundary.
        Ok(_) => Err(FencedTransitionExecuteError::OutcomeUnknown { request_id }),
        Err(SessionConsumerFencedTransitionMutationError::NotTransmitted { .. }) => {
            Err(FencedTransitionExecuteError::NotTransmitted)
        }
        Err(SessionConsumerFencedTransitionMutationError::OutcomeUnknown { .. }) => {
            Err(FencedTransitionExecuteError::OutcomeUnknown { request_id })
        }
        Err(SessionConsumerFencedTransitionMutationError::Store(error)) => {
            Err(FencedTransitionExecuteError::Rejected(error))
        }
    }
}

#[async_trait::async_trait]
impl SessionBackend for SessionConsumerFencedTransitionBackend {
    async fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::minimal()
    }

    async fn preflight_record_expiry(
        &self,
        preflights: &[RecordExpiryPreflight],
    ) -> Result<(), StoreError> {
        self.client
            .preflight_record_expiry(preflights.to_vec())
            .await
    }

    async fn get(
        &self,
        _key: &opc_session_store::SessionKey,
    ) -> Result<Option<opc_session_store::StoredSessionRecord>, StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }

    async fn observe_fenced_transition(
        &self,
        key: &opc_session_store::SessionKey,
    ) -> Result<FencedTransitionObservation, StoreError> {
        self.client.observe(key.clone()).await
    }

    async fn fenced_transition_capability(
        &self,
    ) -> Result<Option<AtomicFencedTransitionCapability>, StoreError> {
        match self.client.capability().await? {
            AtomicFencedTransitionCapability::V1 => Ok(Some(AtomicFencedTransitionCapability::V1)),
            _ => Ok(None),
        }
    }

    fn fenced_transition_preserves_protected_payloads(&self) -> bool {
        true
    }

    fn fenced_transition_accepts_prepared_physical_token(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> bool {
        self.decode_prepared(prepared).is_ok()
    }

    async fn prepare_fenced_transition(
        &self,
        request: FencedTransitionRequest,
    ) -> Result<PreparedFencedTransition, StoreError> {
        opc_session_store::validate_consensus_physical_fenced_transition_request(&request)?;
        PreparedFencedTransition::from_unprotected_request(request)?
            .with_authenticated_consumer_binding(self.binding_commitment)
    }

    async fn fenced_transition(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> Result<FencedTransitionOutcome, FencedTransitionExecuteError> {
        let request = self
            .decode_prepared(prepared)
            .map_err(|_| FencedTransitionExecuteError::NotTransmitted)?;
        consumer_execute_into_fenced_transition(&request, self.client.execute(&request).await)
    }

    async fn fenced_transition_status(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> Result<FencedTransitionStatus, StoreError> {
        let request = self
            .decode_prepared(prepared)
            .map_err(|_| invalid_authenticated_consumer_fenced_transition())?;
        consumer_status_into_fenced_transition(self.client.status(&request).await?)
    }

    async fn compare_and_set(&self, _op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }

    async fn delete_fenced(&self, _lease: &LeaseGuard) -> Result<(), StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }

    async fn refresh_ttl(&self, _lease: &LeaseGuard, _ttl: Duration) -> Result<(), StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }

    async fn batch(&self, _ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }

    async fn scan_restore_records(
        &self,
        _request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }

    async fn get_replication_log(
        &self,
        _start: u64,
        _limit: usize,
    ) -> Result<Vec<opc_session_store::ReplicationEntry>, StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }

    async fn replicate_entry(
        &self,
        _entry: opc_session_store::ReplicationEntry,
    ) -> Result<(), StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }

    async fn rebuild_replication_state(
        &self,
        _entries: Vec<opc_session_store::ReplicationEntry>,
    ) -> Result<(), StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }

    async fn watch(
        &self,
        _start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<opc_session_store::ReplicationEntry, StoreError>>,
        StoreError,
    > {
        Err(authenticated_consumer_fenced_transition_only())
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }
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
    /// Zero remains invalid. Source-compatible stateless callers may retain a
    /// larger legacy value; revision 3 applies its five-second active-frame
    /// ceiling internally. Persistent construction rejects values outside its
    /// explicit bounded profile.
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
            || self.operation_timeout.is_zero()
            || self
                .lifecycle_policy
                .validate_at(tokio::time::Instant::now())
                .is_err()
        {
            return Err(SessionConsumerClientError::Protocol);
        }
        let physical_admission = if watch {
            self.physical_admission.try_acquire_watch()?
        } else {
            self.physical_admission.try_acquire_v1()?
        };
        let resolve_attempt =
            ConsumerSetupPhaseAttempt::begin(setup_counters, ConsumerSetupPhase::Resolve);
        let address = tokio::time::timeout_at(
            pre_request_deadline,
            poll_persistent_consumer_setup_io((self.resolve)(), shutdown_io.as_ref()),
        )
        .await
        .map_err(|_| pre_request_timeout_error(pre_request_budget_active))?
        .map_err(|_| SessionConsumerClientError::Unavailable)?;
        resolve_attempt.complete();
        let generation = self.reauthentication.generation();
        let tcp_attempt = ConsumerSetupPhaseAttempt::begin(setup_counters, ConsumerSetupPhase::Tcp);
        let tcp = tokio::time::timeout_at(
            pre_request_deadline,
            poll_persistent_consumer_setup_io(TcpStream::connect(address), shutdown_io.as_ref()),
        )
        .await
        .map_err(|_| pre_request_timeout_error(pre_request_budget_active))?
        .map_err(|_| SessionConsumerClientError::Unavailable)?;
        tcp.set_nodelay(true)
            .map_err(|_| SessionConsumerClientError::Unavailable)?;
        tcp_attempt.complete();
        let tcp = PersistentConsumerShutdownIo {
            inner: tcp,
            barrier: shutdown_io.clone(),
        };
        let tls_attempt = ConsumerSetupPhaseAttempt::begin(setup_counters, ConsumerSetupPhase::Tls);
        let handshake = self
            .tls_config
            .begin_handshake()
            .map_err(|_| SessionConsumerClientError::Authentication)?;
        let connector =
            tokio_rustls::TlsConnector::from(consumer_client_tls_config(handshake.rustls_config()));
        let tls = tokio::time::timeout_at(
            pre_request_deadline,
            poll_persistent_consumer_setup_io(
                connector.connect(self.server_name.clone(), tcp),
                shutdown_io.as_ref(),
            ),
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
        let rotation_jitter = handshake.consumer_rotation_jitter(peer.spiffe_id());
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
            Some(handshake.epoch()),
        )
        .map_err(|_| SessionConsumerClientError::Protocol)?;
        let mut reauthentication_changes = self.reauthentication.subscribe();
        let mut material_changes = Some(self.tls_config.subscribe_material_changes());
        // Guard the complete TLS/frame poll as well as the nested TCP poll.
        // rustls may satisfy a read from decrypted buffers without polling
        // TCP, so the inner wrapper alone is not a forced-shutdown barrier.
        let tls = PersistentConsumerShutdownIo {
            inner: tls,
            barrier: shutdown_io.clone(),
        };
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
        let hello_write_deadline = pre_request_deadline.min(lifecycle.retire_at()).min(
            tokio::time::Instant::now()
                .checked_add(effective_consumer_idle_timeout(self.idle_timeout))
                .ok_or(SessionConsumerClientError::Protocol)?,
        );
        {
            let hello_write = write_frame_bounded_until(
                &mut writer,
                &hello,
                MAX_NEGOTIATED_FRAME_SIZE,
                hello_write_deadline,
            );
            tokio::pin!(hello_write);
            loop {
                let setup_deadline = pre_request_deadline.min(lifecycle.retire_at());
                if tokio::time::Instant::now() >= setup_deadline {
                    return Err(pre_request_timeout_error(pre_request_budget_active));
                }
                let result = tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(setup_deadline) => {
                        return Err(pre_request_timeout_error(pre_request_budget_active));
                    }
                    _ = reauthentication_changes.changed() => {
                        if !consumer_fresh_admission_is_current(
                            generation,
                            handshake.epoch(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status().epoch(),
                        ) {
                            return Err(SessionConsumerClientError::Deadline);
                        }
                        continue;
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        if !consumer_fresh_admission_is_current(
                            generation,
                            handshake.epoch(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status().epoch(),
                        ) {
                            return Err(SessionConsumerClientError::Deadline);
                        }
                        continue;
                    }
                    result = &mut hello_write => result,
                };
                result
                    .map_err(SessionConsumerClientError::from)
                    .map_err(|error| pre_request_error(error, pre_request_budget_active))?;
                break;
            }
        }
        let ack = {
            let ack = read_authenticated_consumer_bootstrap_frame_until::<_, ConsumerWireResponse>(
                &mut reader,
                MAX_NEGOTIATED_FRAME_SIZE,
                pre_request_deadline.min(lifecycle.retire_at()),
                effective_consumer_idle_timeout(self.idle_timeout),
            );
            tokio::pin!(ack);
            loop {
                let setup_deadline = pre_request_deadline.min(lifecycle.retire_at());
                if tokio::time::Instant::now() >= setup_deadline {
                    return Err(pre_request_timeout_error(pre_request_budget_active));
                }
                let result = tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(setup_deadline) => {
                        return Err(pre_request_timeout_error(pre_request_budget_active));
                    }
                    _ = reauthentication_changes.changed() => {
                        if !consumer_fresh_admission_is_current(
                            generation,
                            handshake.epoch(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status().epoch(),
                        ) {
                            return Err(SessionConsumerClientError::Deadline);
                        }
                        continue;
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        if !consumer_fresh_admission_is_current(
                            generation,
                            handshake.epoch(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status().epoch(),
                        ) {
                            return Err(SessionConsumerClientError::Deadline);
                        }
                        continue;
                    }
                    result = &mut ack => result,
                };
                break result.map_err(SessionConsumerClientError::from)?;
            }
        };
        // Once an authenticated HelloAck frame has started, preserve its
        // active-frame timeout classification. Only a no-byte setup expiry
        // below is eligible for pre-request Unavailable mapping.
        let ack = ack.ok_or_else(|| pre_request_timeout_error(pre_request_budget_active))?;
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
        let reader: Box<dyn AsyncRead + Unpin + Send> = Box::new(reader);
        let writer: Box<dyn AsyncWrite + Unpin + Send> = Box::new(writer);
        let mut connection = ConsumerConnection {
            reader,
            writer,
            lifecycle,
            rotation_jitter,
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
        let rotation_jitter = connection.rotation_jitter;
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
            .checked_add(effective_consumer_idle_timeout(self.idle_timeout))
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
                            self.tls_config.material_status(),
                            rotation_jitter,
                        );
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        observe_consumer_rotation(
                            lifecycle,
                            tokio::time::Instant::now(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status(),
                            rotation_jitter,
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
            let initial_hard_deadline = lifecycle.hard_deadline().map_err(|_| {
                SessionConsumerCallError::MayHaveSent(SessionConsumerClientError::Protocol)
            })?;
            // Quiet server processing may use the complete operation window.
            // Only after the first response byte arrives does the independent
            // active-frame idle deadline begin.
            let read = read_authenticated_consumer_bootstrap_frame_until::<_, ConsumerWireResponse>(
                &mut connection.reader,
                MAX_NEGOTIATED_FRAME_SIZE,
                deadline.min(initial_hard_deadline),
                effective_consumer_idle_timeout(self.idle_timeout),
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
                let response_deadline = deadline.min(hard_deadline);
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
                            if hard_deadline <= deadline {
                                record_consumer_hard_overrun(lifecycle);
                            }
                            return Err(SessionConsumerCallError::MayHaveSent(
                                SessionConsumerClientError::Deadline,
                            ));
                        }
                        Some(response)
                    },
                    _ = tokio::time::sleep_until(response_deadline) => {
                        if hard_deadline <= deadline {
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
                            self.tls_config.material_status(),
                            rotation_jitter,
                        );
                        None
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        observe_consumer_rotation(
                            lifecycle,
                            tokio::time::Instant::now(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status(),
                            rotation_jitter,
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
            }) if exact_correlation(correlation, received).is_ok() => {
                let response =
                    consumer_public_response_from_wire(request, *response).map_err(|_| {
                        SessionConsumerCallError::MayHaveSent(SessionConsumerClientError::Protocol)
                    })?;
                if response_matches_request(request, &response)
                    && response_respects_consumer_capability_budget(
                        &response,
                        connection.request_frame_size,
                        MAX_NEGOTIATED_FRAME_SIZE,
                    )
                {
                    Ok(response)
                } else {
                    Err(SessionConsumerCallError::MayHaveSent(
                        SessionConsumerClientError::Protocol,
                    ))
                }
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

    /// Execute one explicit revision-5 V2 consumer request.
    ///
    /// This deliberately opens a fresh V2-ALPN connection. Persistent V1
    /// lanes are never reused, so a caller cannot accidentally send a V2
    /// envelope after completing the revision-3 handshake. A failure before
    /// proven Call-frame transmission is retryable; an effectful Call with
    /// any possibly accepted bytes retains its exact caller-owned V2 ID for
    /// authoritative recovery. This returns the same exact V2 boundary type
    /// as [`PersistentSessionConsumerClient::execute_v2`].
    pub async fn execute_v2(
        &self,
        request: SessionConsumerV2Request,
    ) -> Result<SessionConsumerV2Response, PersistentSessionConsumerV2ExecuteError> {
        if request.scope() != self.scope || request.validate().is_err() {
            return Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            });
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(effective_consumer_operation_timeout(self.operation_timeout))
            .ok_or(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Deadline,
            })?;
        // Hold the revision-specific physical permit from endpoint resolution
        // through the response. A clone therefore cannot exceed the public
        // V2 lane bound, including while its socket is in TLS or Hello.
        let _physical_admission = self
            .physical_admission
            .try_acquire_v2()
            .map_err(|cause| PersistentSessionConsumerV2ExecuteError::NotTransmitted { cause })?;
        let generation = self.reauthentication.generation();
        let address = tokio::time::timeout_at(deadline, (self.resolve)())
            .await
            .map_err(
                |_| PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                    cause: SessionConsumerClientError::Unavailable,
                },
            )?
            .map_err(
                |_| PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                    cause: SessionConsumerClientError::Unavailable,
                },
            )?;
        let stream = tokio::time::timeout_at(deadline, TcpStream::connect(address))
            .await
            .map_err(
                |_| PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                    cause: SessionConsumerClientError::Unavailable,
                },
            )?
            .map_err(
                |_| PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                    cause: SessionConsumerClientError::Unavailable,
                },
            )?;
        stream.set_nodelay(true).map_err(|_| {
            PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Unavailable,
            }
        })?;
        let handshake = self.tls_config.begin_handshake().map_err(|_| {
            PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Authentication,
            }
        })?;
        let connector = tokio_rustls::TlsConnector::from(consumer_client_tls_config_v2(
            handshake.rustls_config(),
        ));
        let tls = tokio::time::timeout_at(
            deadline,
            connector.connect(self.server_name.clone(), stream),
        )
        .await
        .map_err(
            |_| PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Unavailable,
            },
        )?
        .map_err(classify_tls_io_error)
        .map_err(SessionConsumerClientError::from)
        .map_err(|cause| PersistentSessionConsumerV2ExecuteError::NotTransmitted { cause })?;
        if tls.get_ref().1.alpn_protocol() != Some(SESSION_QUORUM_CONSUMER_V2_ALPN) {
            return Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            });
        }
        let peer =
            opc_tls::peer_tls_identity_from_client_connection(tls.get_ref().1).map_err(|_| {
                PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                    cause: SessionConsumerClientError::Authentication,
                }
            })?;
        if peer.spiffe_id() != &self.expected_server_identity {
            return Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Authentication,
            });
        }
        let established_at = tokio::time::Instant::now();
        let rotation_jitter = handshake.consumer_rotation_jitter(peer.spiffe_id());
        let mut lifecycle = ConnectionLifecycle::new(
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
            Some(handshake.epoch()),
        )
        .map_err(
            |_| PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            },
        )?;
        let mut reauthentication_changes = self.reauthentication.subscribe();
        let mut material_changes = Some(self.tls_config.subscribe_material_changes());
        let (mut reader, mut writer) = tokio::io::split(tls);
        let hello = ConsumerV2WireRequest::Hello(ConsumerHello {
            transport_revision: SESSION_QUORUM_CONSUMER_V2_TRANSPORT_REVISION,
            scope: self.scope,
            response_frame_size: consumer_wire_frame_size(MAX_NEGOTIATED_FRAME_SIZE)
                .map_err(SessionConsumerClientError::from)
                .map_err(
                    |cause| PersistentSessionConsumerV2ExecuteError::NotTransmitted { cause },
                )?,
        });
        write_frame_bounded_until(
            &mut writer,
            &hello,
            MAX_NEGOTIATED_FRAME_SIZE,
            deadline.min(lifecycle.retire_at()),
        )
        .await
        .map_err(SessionConsumerClientError::from)
        .map_err(|cause| PersistentSessionConsumerV2ExecuteError::NotTransmitted { cause })?;
        let ack = read_authenticated_consumer_bootstrap_frame_until::<_, ConsumerV2WireResponse>(
            &mut reader,
            MAX_NEGOTIATED_FRAME_SIZE,
            deadline.min(lifecycle.retire_at()),
            effective_consumer_idle_timeout(self.idle_timeout),
        )
        .await
        .map_err(SessionConsumerClientError::from)
        .map_err(|cause| PersistentSessionConsumerV2ExecuteError::NotTransmitted { cause })?
        .ok_or(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable,
        })?;
        let request_frame_size = match ack {
            ConsumerV2WireResponse::HelloAck(ack)
                if ack.transport_revision == SESSION_QUORUM_CONSUMER_V2_TRANSPORT_REVISION
                    && ack.scope == self.scope =>
            {
                checked_consumer_frame_size(ack.request_frame_size)
                    .map_err(SessionConsumerClientError::from)
                    .map_err(
                        |cause| PersistentSessionConsumerV2ExecuteError::NotTransmitted { cause },
                    )?
            }
            ConsumerV2WireResponse::HelloRejected(SessionConsumerRejection::ScopeMismatch) => {
                return Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                    cause: SessionConsumerClientError::Scope,
                });
            }
            ConsumerV2WireResponse::HelloRejected(SessionConsumerRejection::Unauthorized) => {
                return Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                    cause: SessionConsumerClientError::Authentication,
                });
            }
            _ => {
                return Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                    cause: SessionConsumerClientError::Protocol,
                });
            }
        };
        let admission = handshake.admit().map_err(|_| {
            PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Authentication,
            }
        })?;
        if !consumer_fresh_admission_is_current(
            generation,
            admission.epoch(),
            self.reauthentication.generation(),
            self.tls_config.material_status().epoch(),
        ) {
            return Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Deadline,
            });
        }
        // This is the stateless V2 final-admission boundary: after it, the
        // next wire frame is effectful. Recheck after the hook as well so a
        // reauthentication or material publication in the final gap cannot
        // authorize a Call from a stale handshake.
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
            return Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Deadline,
            });
        }
        if !consumer_connection_current(
            &mut lifecycle,
            &self.tls_config,
            &self.reauthentication,
            rotation_jitter,
        ) {
            return Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Deadline,
            });
        }
        let correlation = NonZeroU32::MIN;
        let attempt_nonce = v2_attempt_nonce().map_err(|_| {
            PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            }
        })?;
        let request_commitment = v2_request_commitment(&request).map_err(|_| {
            PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            }
        })?;
        let call = ConsumerV2WireRequest::Call(ConsumerV2Call {
            correlation,
            attempt_nonce,
            request_commitment,
            request: Box::new(request.clone()),
        });
        let write_progress = FrameWriteProgress::new();
        let write_result = {
            let initial_hard_deadline = lifecycle.hard_deadline().map_err(|_| {
                PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                    cause: SessionConsumerClientError::Protocol,
                }
            })?;
            let write_deadline = deadline.min(initial_hard_deadline);
            let write = write_frame_bounded_until_classified_with_progress(
                &mut writer,
                &call,
                request_frame_size,
                write_deadline,
                &write_progress,
            );
            tokio::pin!(write);
            loop {
                let hard_deadline = lifecycle.hard_deadline().map_err(|_| {
                    v2_persistent_error(
                        &request,
                        write_progress.accepted_any(),
                        SessionConsumerClientError::Protocol,
                    )
                })?;
                tokio::select! {
                    biased;
                    result = &mut write => {
                        if hard_deadline <= write_deadline && tokio::time::Instant::now() >= hard_deadline {
                            record_consumer_hard_overrun(&lifecycle);
                            if result.is_ok() {
                                return Err(v2_persistent_error(&request, write_progress.accepted_any(), SessionConsumerClientError::Deadline));
                            }
                        }
                        break result;
                    }
                    _ = wait_for_shortened_deadline(hard_deadline, write_deadline) => {
                        record_consumer_hard_overrun(&lifecycle);
                        return Err(v2_persistent_error(&request, write_progress.accepted_any(), SessionConsumerClientError::Deadline));
                    }
                    _ = reauthentication_changes.changed() => {
                        observe_consumer_rotation(&mut lifecycle, tokio::time::Instant::now(), self.reauthentication.generation(), self.tls_config.material_status(), rotation_jitter);
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        observe_consumer_rotation(&mut lifecycle, tokio::time::Instant::now(), self.reauthentication.generation(), self.tls_config.material_status(), rotation_jitter);
                    }
                }
            }
        };
        if let Err(error) = write_result {
            return Err(v2_persistent_error(
                &request,
                write_progress.accepted_any(),
                match error {
                    FrameWriteError::BeforeWrite(error)
                    | FrameWriteError::MayHaveWritten(error) => {
                        SessionConsumerClientError::from(error)
                    }
                },
            ));
        }
        let response = {
            let initial_hard_deadline = lifecycle.hard_deadline().map_err(|_| {
                v2_persistent_error(&request, true, SessionConsumerClientError::Protocol)
            })?;
            let read = read_authenticated_consumer_bootstrap_frame_until::<_, ConsumerV2WireResponse>(
                &mut reader,
                MAX_NEGOTIATED_FRAME_SIZE,
                deadline.min(initial_hard_deadline),
                effective_consumer_idle_timeout(self.idle_timeout),
            );
            tokio::pin!(read);
            loop {
                let hard_deadline = lifecycle.hard_deadline().map_err(|_| {
                    v2_persistent_error(&request, true, SessionConsumerClientError::Protocol)
                })?;
                let response_deadline = deadline.min(hard_deadline);
                let response = tokio::select! {
                    biased;
                    response = &mut read => {
                        if tokio::time::Instant::now() >= response_deadline {
                            if hard_deadline <= deadline { record_consumer_hard_overrun(&lifecycle); }
                            return Err(v2_persistent_error(&request, true, SessionConsumerClientError::Deadline));
                        }
                        Some(response)
                    }
                    _ = tokio::time::sleep_until(response_deadline) => {
                        if hard_deadline <= deadline { record_consumer_hard_overrun(&lifecycle); }
                        return Err(v2_persistent_error(&request, true, SessionConsumerClientError::Deadline));
                    }
                    _ = reauthentication_changes.changed() => {
                        observe_consumer_rotation(&mut lifecycle, tokio::time::Instant::now(), self.reauthentication.generation(), self.tls_config.material_status(), rotation_jitter);
                        None
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        observe_consumer_rotation(&mut lifecycle, tokio::time::Instant::now(), self.reauthentication.generation(), self.tls_config.material_status(), rotation_jitter);
                        None
                    }
                };
                if let Some(response) = response {
                    break response.map_err(SessionConsumerClientError::from).and_then(
                        |response| response.ok_or(SessionConsumerClientError::Unavailable),
                    );
                }
            }
        };
        let response = match response {
            Ok(ConsumerV2WireResponse::Response(ConsumerV2CallResponse {
                correlation: received,
                attempt_nonce: received_nonce,
                request_commitment: received_commitment,
                response,
            })) if received == correlation
                && received_nonce == attempt_nonce
                && received_commitment == request_commitment
                && v2_response_matches_request(&request, &response) =>
            {
                *response
            }
            Ok(_) => {
                return Err(v2_persistent_error(
                    &request,
                    true,
                    SessionConsumerClientError::Protocol,
                ));
            }
            Err(cause) => return Err(v2_persistent_error(&request, true, cause)),
        };
        if v2_response_is_outcome_unknown(&response) {
            return Err(v2_outcome_unknown(&request).unwrap_or(
                PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                    cause: SessionConsumerClientError::Protocol,
                },
            ));
        }
        Ok(response)
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
        if !consumer_request_has_exact_fenced_transition_id(&request) || request.validate().is_err()
        {
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Protocol,
            ));
        }
        let started_at = tokio::time::Instant::now();
        let deadline = started_at
            .checked_add(effective_consumer_operation_timeout(self.operation_timeout))
            .ok_or(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Deadline,
            ))?;
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

    /// Read the quorum's exact atomic-transition capability declaration.
    pub async fn fenced_transition_capability(
        &self,
    ) -> Result<AtomicFencedTransitionCapability, StoreError> {
        match self
            .execute(self.request(
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::FencedTransitionCapability,
            ))
            .await
        {
            Ok(SessionConsumerResponse::FencedTransitionCapability(result)) => {
                result.map_err(SessionConsumerStoreError::into_store_error)
            }
            Ok(SessionConsumerResponse::Rejected(rejection)) => {
                Err(rejection_into_store_error(rejection))
            }
            Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
                "consumer fenced-transition capability unavailable".into(),
            )),
        }
    }

    /// Read one exact key's record and durable fence floor at quorum authority.
    pub async fn observe_fenced_transition(
        &self,
        key: opc_session_store::SessionKey,
    ) -> Result<FencedTransitionObservation, StoreError> {
        match self
            .execute(self.request(
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::ObserveFencedTransition { key },
            ))
            .await
        {
            Ok(SessionConsumerResponse::ObserveFencedTransition(result)) => {
                result.map_err(SessionConsumerStoreError::into_store_error)
            }
            Ok(SessionConsumerResponse::Rejected(rejection)) => {
                Err(rejection_into_store_error(rejection))
            }
            Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
                "consumer fenced-transition observation unavailable".into(),
            )),
        }
    }

    /// Submit exactly one complete atomic transition without automatic replay.
    pub async fn fenced_transition(
        &self,
        request: &FencedTransitionRequest,
    ) -> Result<FencedTransitionOutcome, SessionConsumerFencedTransitionMutationError> {
        let outer_request_id = consumer_fenced_transition_request_id(request);
        fenced_transition_response(
            request,
            self.execute_classified(self.request(
                outer_request_id,
                SessionConsumerOperation::FencedTransition {
                    request: Box::new(request.clone()),
                },
            ))
            .await,
        )
    }

    /// Recover the typed retained status using the identical transition body.
    pub async fn fenced_transition_status(
        &self,
        request: &FencedTransitionRequest,
    ) -> Result<SessionConsumerFencedTransitionStatus, StoreError> {
        let request_id = consumer_fenced_transition_request_id(request);
        match self
            .execute(self.request(
                request_id,
                SessionConsumerOperation::FencedTransitionStatus {
                    request: Box::new(request.clone()),
                },
            ))
            .await
        {
            Ok(SessionConsumerResponse::FencedTransitionStatus(result)) => {
                result.map_err(SessionConsumerStoreError::into_store_error)
            }
            Ok(SessionConsumerResponse::Rejected(rejection)) => {
                Err(rejection_into_store_error(rejection))
            }
            Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
                "consumer fenced-transition status unavailable".into(),
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
            SessionConsumerResponse::AcquireLease(result) => Some(result),
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
            SessionConsumerResponse::RenewLease(result) => Some(result),
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
        let rotation_jitter = connection.rotation_jitter;
        let correlation = connection
            .take_correlation()
            .map_err(SessionConsumerCallError::BeforeCallWrite)?;
        connection.idle_deadline = tokio::time::Instant::now()
            .checked_add(effective_consumer_idle_timeout(self.idle_timeout))
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
                            self.tls_config.material_status(),
                            rotation_jitter,
                        );
                        None
                    }
                    _ = wait_consumer_material_change(rotation.material) => {
                        observe_consumer_rotation(
                            lifecycle,
                            tokio::time::Instant::now(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status(),
                            rotation_jitter,
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
        let deadline = started_at
            .checked_add(effective_consumer_operation_timeout(self.operation_timeout))
            .ok_or(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Protocol,
            ))?;
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
            // A quiet backend may consume the complete operation budget.
            // The active-frame bound starts only after the first response byte.
            let watch_response_deadline = deadline.min(connection.lifecycle.retire_at());
            let response_read = read_authenticated_consumer_bootstrap_frame_until::<
                _,
                ConsumerWireResponse,
            >(
                &mut connection.reader,
                MAX_NEGOTIATED_FRAME_SIZE,
                watch_response_deadline,
                effective_consumer_idle_timeout(self.idle_timeout),
            );
            tokio::pin!(response_read);
            loop {
                let now = tokio::time::Instant::now();
                if now >= watch_response_deadline
                    || !consumer_connection_current(
                        &mut connection.lifecycle,
                        &self.tls_config,
                        &self.reauthentication,
                        connection.rotation_jitter,
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
                                connection.rotation_jitter,
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
                            connection.rotation_jitter,
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
                            connection.rotation_jitter,
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
            }) if exact_correlation(correlation, received).is_ok() => {
                let request = SessionConsumerRequest::new(
                    self.scope,
                    SessionConsumerRequestId::from_bytes([0; 16]),
                    SessionConsumerOperation::Watch { start_sequence },
                );
                consumer_public_response_from_wire(&request, *response).map_err(|_| {
                    SessionConsumerCallError::MayHaveSent(SessionConsumerClientError::Protocol)
                })?
            }
            _ => {
                return Err(SessionConsumerCallError::MayHaveSent(
                    SessionConsumerClientError::Protocol,
                ));
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
        let active_frame_timeout = effective_consumer_idle_timeout(self.idle_timeout);
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
                        if tx.capacity() == 0 || byte_budget.available_permits() == 0 {
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
                // A quiet, healthy watch is normal. Its no-byte wait lasts to
                // lifecycle retirement, while the independent active-frame
                // bound begins only after the first prefix byte. Keep this
                // one read pinned across benign material notifications so a
                // partially consumed frame is never recreated.
                let response = {
                    let response_read = read_authenticated_consumer_bootstrap_frame_until::<
                        _,
                        ConsumerWireResponse,
                    >(
                        &mut connection.reader,
                        MAX_NEGOTIATED_FRAME_SIZE,
                        connection.lifecycle.retire_at(),
                        active_frame_timeout,
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
                                    connection.rotation_jitter,
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
                                    connection.rotation_jitter,
                                ) {
                                    ConsumerWatchRead::Reconnect
                                } else {
                                    continue;
                                }
                            },
                        };
                        match event {
                            ConsumerWatchRead::Frame(_) | ConsumerWatchRead::Reconnect => {
                                break event;
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
                let queued_entry = Ok(entry);
                let byte_count = match serde_json::to_vec(&queued_entry) {
                    Ok(encoded) if encoded.len() <= CONSUMER_WATCH_CHANNEL_MAX_BYTES => {
                        u32::try_from(encoded.len()).expect("watch byte cap fits u32")
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
                let permit = match Arc::clone(&byte_budget).try_acquire_many_owned(byte_count) {
                    Ok(permit) => permit,
                    Err(_) => terminate_stalled_watch!(),
                };
                if !connection.current(&tls_config, &reauthentication) {
                    reconnect_or_terminal!();
                }
                if let Some(pool) = persistent_pool.as_ref() {
                    counter_increment(&pool.counters.watch_buffered);
                }
                let queued = QueuedConsumerWatchItem {
                    item: Some(queued_entry),
                    _byte_permit: permit,
                    watch_pool: persistent_pool.clone(),
                };
                match tx.try_send(queued) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => terminate_stalled_watch!(),
                    Err(mpsc::error::TrySendError::Closed(_)) => return,
                }
                if expected_sequence == u64::MAX {
                    // The terminal sequence is valid and caller-visible, but
                    // it has no representable successor cursor. Close cleanly
                    // after queueing it exactly once; never manufacture a
                    // protocol error or reconnect from a wrapped cursor.
                    return;
                }
                // The cursor advances only after this item has crossed the
                // bounded stream queue. A loss before then replays it; a loss
                // after then resumes at the exact checked successor.
                expected_sequence = expected_sequence
                    .checked_add(1)
                    .expect("u64::MAX returns before cursor advancement");
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

/// Redaction-safe revision-5 lane counters.  They are deliberately separate
/// from the revision-3 pool: a V2 outage must not consume V1's finite queue.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct PersistentSessionConsumerV2Diagnostics {
    /// Successfully authenticated and admitted V2 lanes.
    pub setup_successes: u64,
    /// Calls served by an already authenticated V2 lane.
    pub reused: u64,
    /// V2 lanes discarded rather than returned for reuse.
    pub reconnects: u64,
    /// Open V2 physical lanes, including checked-out lanes.
    pub active: u64,
    /// Currently reusable V2 lanes held by the fixed pool.
    pub idle: u64,
}

impl fmt::Debug for PersistentSessionConsumerV2Diagnostics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentSessionConsumerV2Diagnostics")
            .field("setup_successes", &self.setup_successes)
            .field("reused", &self.reused)
            .field("reconnects", &self.reconnects)
            .field("active", &self.active)
            .field("idle", &self.idle)
            .finish()
    }
}

/// Exact V2 effect-boundary result for one stateless or persistent consumer call.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PersistentSessionConsumerV2ExecuteError {
    #[error("V2 request was not transmitted")]
    NotTransmitted { cause: SessionConsumerClientError },
    #[error("V2 read is unavailable")]
    ReadUnavailable { cause: SessionConsumerClientError },
    #[error("V2 request outcome is unknown")]
    OutcomeUnknown {
        request_id: FencedTransitionV2RequestId,
    },
    #[error("V2 batch request outcomes are unknown")]
    OutcomeUnknownBatch {
        request_ids: Vec<FencedTransitionV2RequestId>,
    },
}

impl fmt::Debug for PersistentSessionConsumerV2ExecuteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::NotTransmitted { .. } => "not_transmitted",
            Self::ReadUnavailable { .. } => "read_unavailable",
            Self::OutcomeUnknown { .. } => "outcome_unknown",
            Self::OutcomeUnknownBatch { .. } => "outcome_unknown_batch",
        };
        formatter
            .debug_struct("PersistentSessionConsumerV2ExecuteError")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

impl PersistentSessionConsumerV2ExecuteError {
    /// Return the exact caller-owned transition identity, if recovery is required.
    pub const fn exact_retry_id(&self) -> Option<FencedTransitionV2RequestId> {
        match self {
            Self::OutcomeUnknown { request_id } => Some(*request_id),
            Self::NotTransmitted { .. }
            | Self::ReadUnavailable { .. }
            | Self::OutcomeUnknownBatch { .. } => None,
        }
    }

    /// Return every caller-owned transition identity requiring recovery.
    ///
    /// Singleton requests retain [`Self::exact_retry_id`]'s existing surface;
    /// batches preserve caller order and never mint a replacement identity.
    pub fn exact_retry_ids(&self) -> Option<&[FencedTransitionV2RequestId]> {
        match self {
            Self::OutcomeUnknown { request_id } => Some(std::slice::from_ref(request_id)),
            Self::OutcomeUnknownBatch { request_ids } => Some(request_ids),
            Self::NotTransmitted { .. } | Self::ReadUnavailable { .. } => None,
        }
    }
}

struct PersistentV2Connection {
    commands: mpsc::Sender<PersistentV2LaneCall>,
    idle_deadline: tokio::time::Instant,
    retirement: watch::Sender<Option<RetirementReason>>,
    admitted_generation: u64,
    admitted_material_epoch: opc_tls::TlsMaterialEpoch,
    state: Arc<PersistentV2LaneState>,
}

struct PersistentV2LaneCall {
    request: SessionConsumerV2Request,
    attempt_nonce: [u8; 16],
    request_commitment: [u8; 32],
    deadline: tokio::time::Instant,
    completion: oneshot::Sender<Result<SessionConsumerV2Response, SessionConsumerClientError>>,
    write_progress: Arc<FrameWriteProgress>,
}

enum PersistentV2PoolEntry {
    Lane(PersistentV2Connection),
    /// A fixed-memory count of front-priority logical checkout failures.
    ///
    /// One distinct poisoned lane contributes one debt, but retaining each
    /// debt as a queue node would permit an unbounded allocation if peers
    /// repeatedly poison replacement lanes before callers check them out.
    Poison(NonZeroUsize),
}

impl PersistentV2PoolEntry {
    const fn poison() -> Self {
        Self::Poison(NonZeroUsize::MIN)
    }
}

struct PersistentV2LaneLifetime {
    pool_connection: Weak<PersistentSessionConsumerV2Pool>,
    state: Arc<PersistentV2LaneState>,
    _pool_width_admission: Option<OwnedSemaphorePermit>,
    _physical_admission: Option<OwnedSemaphorePermit>,
}

/// State which remains observable through an idle pool handle while its actor
/// is reading ahead. A positive unsolicited byte retires that exact source
/// before another checkout can select it.
struct PersistentV2LaneState {
    poisoned: AtomicBool,
    healthy: AtomicBool,
}

impl PersistentV2LaneState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            poisoned: AtomicBool::new(false),
            healthy: AtomicBool::new(false),
        })
    }
}

struct PersistentV2LaneActor {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    request_frame_size: usize,
    lifecycle: ConnectionLifecycle,
    rotation_jitter: Duration,
    client: StatelessSessionConsumerClient,
    reauthentication_changes: watch::Receiver<u64>,
    material_changes: Option<opc_tls::TlsMaterialStatusReceiver>,
    retirement: watch::Receiver<Option<RetirementReason>>,
    forced: watch::Receiver<bool>,
    shutdown_io: Arc<PersistentConsumerIoBarrier>,
    commands: mpsc::Receiver<PersistentV2LaneCall>,
    lifetime: PersistentV2LaneLifetime,
}

impl PersistentV2LaneLifetime {
    fn install_poison_ticket(&self) {
        let Some(pool) = self.pool_connection.upgrade() else {
            return;
        };
        if pool.shutdown.load(Ordering::Acquire) {
            return;
        }
        let mut idle = pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.install_poison_ticket_locked(&pool, &mut idle);
    }

    fn install_poison_ticket_locked(
        &self,
        pool: &PersistentSessionConsumerV2Pool,
        idle: &mut VecDeque<PersistentV2PoolEntry>,
    ) {
        Self::install_poison_ticket_for_state_locked(&self.state, pool, idle);
    }

    fn install_poison_ticket_for_state_locked(
        state: &PersistentV2LaneState,
        pool: &PersistentSessionConsumerV2Pool,
        idle: &mut VecDeque<PersistentV2PoolEntry>,
    ) {
        // This transition shares the checkout queue lock with the actual
        // nonblocking read poll. Thus authenticated plaintext cannot become
        // visible before both its source lane and its front-priority debt are
        // published to the pool.
        if pool.shutdown.load(Ordering::Acquire) {
            return;
        }
        let _accounting = pool
            .live_accounting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.poisoned.swap(true, Ordering::AcqRel) {
            return;
        }
        #[cfg(test)]
        let poison_accounting_hook = {
            pool.poison_accounting_hook
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        };
        #[cfg(test)]
        if let Some(hook) = poison_accounting_hook {
            hook.pause_after_poison_state();
        }
        if state.healthy.swap(false, Ordering::AcqRel) {
            pool.healthy_active.fetch_sub(1, Ordering::Release);
        }
        counter_increment(&pool.poisoned);
        let reserved = match idle.front_mut() {
            Some(PersistentV2PoolEntry::Poison(debt)) => {
                // The count is fixed-memory and preserves one logical
                // checkout failure for every newly poisoned lane. If the
                // machine-integer boundary is ever reached, the marker stays
                // permanently poisoned rather than under-reporting debt.
                if debt.get() != usize::MAX {
                    if let Some(next) = debt.checked_add(1) {
                        *debt = next;
                    }
                }
                true
            }
            Some(PersistentV2PoolEntry::Lane(_)) | None => {
                idle.push_front(PersistentV2PoolEntry::poison());
                true
            }
        };
        #[cfg(test)]
        if reserved {
            let hook = pool
                .positive_read_reservation_hook
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(hook) = hook {
                hook.pause_after_reservation();
            }
        }
        #[cfg(not(test))]
        let _ = reserved;
    }
}

impl Drop for PersistentV2LaneLifetime {
    fn drop(&mut self) {
        // Public actor completion is also the physical-capacity boundary.  A
        // waiter woken by `active == 0` must never observe either admission
        // permit still held by the actor that published that state.
        drop(self._physical_admission.take());
        drop(self._pool_width_admission.take());
        if let Some(pool) = self.pool_connection.upgrade() {
            let _accounting = pool
                .live_accounting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.state.healthy.swap(false, Ordering::AcqRel) {
                pool.healthy_active.fetch_sub(1, Ordering::Release);
            }
            if self.state.poisoned.load(Ordering::Acquire) {
                pool.poisoned.fetch_sub(1, Ordering::AcqRel);
            }
            pool.active.fetch_sub(1, Ordering::Release);
            counter_increment(&pool.reconnects);
            pool.drained_notify.notify_waiters();
        }
    }
}

struct PersistentV2ReadAheadWriter<'a> {
    inner: &'a mut Box<dyn AsyncWrite + Unpin + Send>,
    read_progress: &'a ConsumerFrameReadProgress<'a>,
    write_progress: &'a FrameWriteProgress,
}

impl AsyncWrite for PersistentV2ReadAheadWriter<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.read_progress.started() && !self.write_progress.accepted_any() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsolicited authenticated consumer frame",
            )));
        }
        Pin::new(&mut *self.inner).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.read_progress.started() && !self.write_progress.accepted_any() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsolicited authenticated consumer frame",
            )));
        }
        Pin::new(&mut *self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(context)
    }
}

fn finish_persistent_v2_lane_call(
    commands: &mut mpsc::Receiver<PersistentV2LaneCall>,
    completion: oneshot::Sender<Result<SessionConsumerV2Response, SessionConsumerClientError>>,
    result: Result<SessionConsumerV2Response, SessionConsumerClientError>,
) {
    commands.close();
    let _ = completion.send(result);
}

async fn run_persistent_v2_lane(actor: PersistentV2LaneActor) {
    let PersistentV2LaneActor {
        mut reader,
        mut writer,
        request_frame_size,
        mut lifecycle,
        rotation_jitter,
        client,
        mut reauthentication_changes,
        mut material_changes,
        mut retirement,
        mut forced,
        shutdown_io,
        mut commands,
        lifetime,
    } = actor;
    async {
        let mut pending_completion = None;
        let mut next_correlation = NonZeroU32::MIN;
        let mut calls = 0_usize;
        loop {
        // This future is created before the preceding result becomes visible
        // and remains pinned across idle command admission and the following
        // write. Thus one task continuously owns the TLS read side; there is
        // no response queue and no check-then-write gap for an unsolicited
        // future frame.
        let read_progress = ConsumerFrameReadProgress::read_ahead(&lifetime);
        let mut tracked_reader = ConsumerProgressReader {
            inner: &mut reader,
            progress: &read_progress,
        };
        let read =
            crate::protocol::read_frame_payload(&mut tracked_reader, MAX_NEGOTIATED_FRAME_SIZE);
        tokio::pin!(read);

        if let Some((completion, response, retire_after_response)) = pending_completion.take() {
            // Poll the already-owned next-frame read once before publishing
            // the previous result. A coalesced extra frame is therefore
            // consumed and retires this lane before a successor Call can
            // publish a byte, while the previous exact result remains valid.
            let publish = std::future::ready(());
            tokio::pin!(publish);
            tokio::select! {
                biased;
                event = persistent_v2_read_ahead_event(read.as_mut(), &read_progress) => {
                    let _ = event;
                    finish_persistent_v2_lane_call(
                        &mut commands,
                        completion,
                        Ok(response),
                    );
                    return;
                }
                _ = &mut publish => {
                    if read_progress.started() {
                        finish_persistent_v2_lane_call(
                            &mut commands,
                            completion,
                            Ok(response),
                        );
                        return;
                    }
                    if retire_after_response {
                        finish_persistent_v2_lane_call(
                            &mut commands,
                            completion,
                            Ok(response),
                        );
                        return;
                    }
                    if completion.send(Ok(response)).is_err() {
                        commands.close();
                        return;
                    }
                }
            }
        }

        let command = loop {
            if shutdown_io.is_forced() {
                commands.close();
                return;
            }
            let now = tokio::time::Instant::now();
            if lifecycle.retirement(now).is_some() {
                commands.close();
                return;
            }
            let retire_at = lifecycle.retire_at();
            tokio::select! {
                biased;
                event = persistent_v2_read_ahead_event(read.as_mut(), &read_progress) => {
                    let _ = event;
                    commands.close();
                    return;
                }
                _ = wait_for_v2_forced_shutdown(&mut forced) => {
                    commands.close();
                    return;
                }
                result = reauthentication_changes.changed() => {
                    if result.is_err() {
                        commands.close();
                        return;
                    }
                    observe_consumer_rotation(
                        &mut lifecycle,
                        tokio::time::Instant::now(),
                        client.reauthentication.generation(),
                        client.tls_config.material_status(),
                        rotation_jitter,
                    );
                }
                _ = wait_consumer_material_change(&mut material_changes) => {
                    observe_consumer_rotation(
                        &mut lifecycle,
                        tokio::time::Instant::now(),
                        client.reauthentication.generation(),
                        client.tls_config.material_status(),
                        rotation_jitter,
                    );
                }
                result = retirement.changed() => {
                    if result.is_err() {
                        commands.close();
                        return;
                    }
                    if let Some(reason) = *retirement.borrow_and_update() {
                        lifecycle.record_forced_retirement(reason);
                        commands.close();
                        return;
                    }
                }
                _ = tokio::time::sleep_until(retire_at) => {
                    let _ = lifecycle.retirement(tokio::time::Instant::now());
                    commands.close();
                    return;
                }
                command = commands.recv() => {
                    let Some(command) = command else {
                        return;
                    };
                    if read_progress.started() {
                        finish_persistent_v2_lane_call(
                            &mut commands,
                            command.completion,
                            Err(SessionConsumerClientError::Protocol),
                        );
                        return;
                    }
                    break command;
                }
            }
        };
        read_progress.disarm_poison();

        let PersistentV2LaneCall {
            request,
            attempt_nonce,
            request_commitment,
            deadline,
            mut completion,
            write_progress,
        } = command;
        if completion.is_closed() {
            commands.close();
            return;
        }
        if calls >= MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION {
            finish_persistent_v2_lane_call(
                &mut commands,
                completion,
                Err(SessionConsumerClientError::Unavailable),
            );
            return;
        }
        let correlation = next_correlation;
        let Some(successor) = NonZeroU32::new(correlation.get().wrapping_add(1)) else {
            finish_persistent_v2_lane_call(
                &mut commands,
                completion,
                Err(SessionConsumerClientError::Protocol),
            );
            return;
        };
        next_correlation = successor;
        calls = calls.saturating_add(1);
        let wire_call = ConsumerV2WireRequest::Call(ConsumerV2Call {
            correlation,
            attempt_nonce,
            request_commitment,
            request: Box::new(request),
        });
        let mut early_response = None;
        let initial_hard_deadline = match lifecycle.hard_deadline() {
            Ok(deadline) => deadline,
            Err(_) => {
                finish_persistent_v2_lane_call(
                    &mut commands,
                    completion,
                    Err(SessionConsumerClientError::Protocol),
                );
                return;
            }
        };
        let write_deadline = deadline.min(initial_hard_deadline);
        let mut guarded_writer = PersistentV2ReadAheadWriter {
            inner: &mut writer,
            read_progress: &read_progress,
            write_progress: &write_progress,
        };
        let write = write_frame_bounded_until_classified_with_progress(
            &mut guarded_writer,
            &wire_call,
            request_frame_size,
            write_deadline,
            &write_progress,
        );
        tokio::pin!(write);
        let write_result = loop {
            if shutdown_io.is_forced() {
                finish_persistent_v2_lane_call(
                    &mut commands,
                    completion,
                    Err(SessionConsumerClientError::ShuttingDown),
                );
                return;
            }
            let hard_deadline = match lifecycle.hard_deadline() {
                Ok(deadline) => deadline,
                Err(_) => {
                    finish_persistent_v2_lane_call(
                        &mut commands,
                        completion,
                        Err(SessionConsumerClientError::Protocol),
                    );
                    return;
                }
            };
            tokio::select! {
                biased;
                frame = &mut read, if early_response.is_none() => {
                    let frame = frame.and_then(|payload| decode_consumer_frame_payload(&payload));
                    if !write_progress.accepted_any() {
                        finish_persistent_v2_lane_call(
                            &mut commands,
                            completion,
                            Err(SessionConsumerClientError::Protocol),
                        );
                        return;
                    }
                    match frame {
                        Ok(frame) => early_response = Some(frame),
                        Err(error) => {
                            finish_persistent_v2_lane_call(
                                &mut commands,
                                completion,
                                Err(SessionConsumerClientError::from(error)),
                            );
                            return;
                        }
                    }
                }
                _ = wait_for_v2_forced_shutdown(&mut forced) => {
                    finish_persistent_v2_lane_call(
                        &mut commands,
                        completion,
                        Err(SessionConsumerClientError::ShuttingDown),
                    );
                    return;
                }
                _ = completion.closed() => {
                    commands.close();
                    return;
                }
                result = &mut write => {
                    if hard_deadline <= write_deadline
                        && tokio::time::Instant::now() >= hard_deadline
                    {
                        record_consumer_hard_overrun(&lifecycle);
                        if result.is_ok() {
                            finish_persistent_v2_lane_call(
                                &mut commands,
                                completion,
                                Err(SessionConsumerClientError::Deadline),
                            );
                            return;
                        }
                    }
                    break result;
                }
                _ = wait_for_shortened_deadline(hard_deadline, write_deadline) => {
                    record_consumer_hard_overrun(&lifecycle);
                    finish_persistent_v2_lane_call(
                        &mut commands,
                        completion,
                        Err(SessionConsumerClientError::Deadline),
                    );
                    return;
                }
                result = reauthentication_changes.changed() => {
                    if result.is_err() {
                        finish_persistent_v2_lane_call(
                            &mut commands,
                            completion,
                            Err(SessionConsumerClientError::Authentication),
                        );
                        return;
                    }
                    observe_consumer_rotation(
                        &mut lifecycle,
                        tokio::time::Instant::now(),
                        client.reauthentication.generation(),
                        client.tls_config.material_status(),
                        rotation_jitter,
                    );
                }
                _ = wait_consumer_material_change(&mut material_changes) => {
                    observe_consumer_rotation(
                        &mut lifecycle,
                        tokio::time::Instant::now(),
                        client.reauthentication.generation(),
                        client.tls_config.material_status(),
                        rotation_jitter,
                    );
                }
            }
        };
        if let Err(error) = write_result {
            let cause = match error {
                FrameWriteError::BeforeWrite(error) | FrameWriteError::MayHaveWritten(error) => {
                    SessionConsumerClientError::from(error)
                }
            };
            finish_persistent_v2_lane_call(&mut commands, completion, Err(cause));
            return;
        }

        let response = if let Some(response) = early_response {
            Ok(response)
        } else {
            loop {
                if shutdown_io.is_forced() {
                    finish_persistent_v2_lane_call(
                        &mut commands,
                        completion,
                        Err(SessionConsumerClientError::ShuttingDown),
                    );
                    return;
                }
                let hard_deadline = match lifecycle.hard_deadline() {
                    Ok(deadline) => deadline,
                    Err(_) => {
                        finish_persistent_v2_lane_call(
                            &mut commands,
                            completion,
                            Err(SessionConsumerClientError::Protocol),
                        );
                        return;
                    }
                };
                let response_deadline = deadline.min(hard_deadline);
                let response = tokio::select! {
                    biased;
                    _ = wait_for_v2_forced_shutdown(&mut forced) => {
                        finish_persistent_v2_lane_call(
                            &mut commands,
                            completion,
                            Err(SessionConsumerClientError::ShuttingDown),
                        );
                        return;
                    }
                    _ = completion.closed() => {
                        commands.close();
                        return;
                    }
                    response = &mut read => {
                        if tokio::time::Instant::now() >= response_deadline {
                            if hard_deadline <= deadline {
                                record_consumer_hard_overrun(&lifecycle);
                            }
                            finish_persistent_v2_lane_call(
                                &mut commands,
                                completion,
                                Err(SessionConsumerClientError::Deadline),
                            );
                            return;
                        }
                        Some(response)
                    }
                    _ = tokio::time::sleep_until(response_deadline) => {
                        if hard_deadline <= deadline {
                            record_consumer_hard_overrun(&lifecycle);
                        }
                        finish_persistent_v2_lane_call(
                            &mut commands,
                            completion,
                            Err(SessionConsumerClientError::Deadline),
                        );
                        return;
                    }
                    result = reauthentication_changes.changed() => {
                        if result.is_err() {
                            finish_persistent_v2_lane_call(
                                &mut commands,
                                completion,
                                Err(SessionConsumerClientError::Authentication),
                            );
                            return;
                        }
                        observe_consumer_rotation(
                            &mut lifecycle,
                            tokio::time::Instant::now(),
                            client.reauthentication.generation(),
                            client.tls_config.material_status(),
                            rotation_jitter,
                        );
                        None
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        observe_consumer_rotation(
                            &mut lifecycle,
                            tokio::time::Instant::now(),
                            client.reauthentication.generation(),
                            client.tls_config.material_status(),
                            rotation_jitter,
                        );
                        None
                    }
                };
                if let Some(response) = response {
                    break response
                        .and_then(|payload| decode_consumer_frame_payload(&payload))
                        .map_err(SessionConsumerClientError::from);
                }
            }
        };

        let expected = match &wire_call {
            ConsumerV2WireRequest::Call(expected) => expected,
            ConsumerV2WireRequest::Hello(_) => {
                finish_persistent_v2_lane_call(
                    &mut commands,
                    completion,
                    Err(SessionConsumerClientError::Protocol),
                );
                return;
            }
        };
        let response = match response {
            Ok(ConsumerV2WireResponse::Response(ConsumerV2CallResponse {
                correlation,
                attempt_nonce,
                request_commitment,
                response,
            })) if correlation == expected.correlation
                && attempt_nonce == expected.attempt_nonce
                && request_commitment == expected.request_commitment
                && v2_response_matches_request(&expected.request, &response) =>
            {
                *response
            }
            Ok(_) => {
                finish_persistent_v2_lane_call(
                    &mut commands,
                    completion,
                    Err(SessionConsumerClientError::Protocol),
                );
                return;
            }
            Err(cause) => {
                finish_persistent_v2_lane_call(&mut commands, completion, Err(cause));
                return;
            }
        };
        let retire_after_response = v2_response_retires_connection_authority(&response)
            || calls >= MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION
            || shutdown_io.is_forced()
            || lifecycle.retirement(tokio::time::Instant::now()).is_some();
        pending_completion = Some((completion, response, retire_after_response));
        }
    }
    .await;
    // The actor owns both TLS halves through its last protocol decision.  Tear
    // down those halves before releasing width/physical admission or
    // publishing `active == 0` from the lifetime guard.
    drop(reader);
    drop(writer);
    drop(lifetime);
}

struct PersistentSessionConsumerV2Pool {
    client: StatelessSessionConsumerClient,
    config: PersistentSessionConsumerConfig,
    lanes: Arc<Semaphore>,
    actor_lanes: Arc<Semaphore>,
    pending: Arc<Semaphore>,
    prewarm: Arc<Semaphore>,
    idle: StdMutex<VecDeque<PersistentV2PoolEntry>>,
    shutdown: AtomicBool,
    shutdown_forced_tx: watch::Sender<bool>,
    shutdown_io: Arc<PersistentConsumerIoBarrier>,
    shutdown_complete: AtomicBool,
    shutdown_complete_notify: Notify,
    activity: StdMutex<PersistentV2Activity>,
    drained_notify: Notify,
    idle_reaper_started: AtomicBool,
    #[cfg(test)]
    idle_reaper_armed: Notify,
    #[cfg(test)]
    idle_reaper_processed: Notify,
    #[cfg(test)]
    shutdown_activity_wait_armed: Notify,
    #[cfg(test)]
    positive_read_reservation_hook: StdMutex<Option<Arc<PersistentV2PositiveReadReservationHook>>>,
    #[cfg(test)]
    prewarm_final_publication_hook: StdMutex<Option<Arc<PersistentV2PrewarmFinalPublicationHook>>>,
    #[cfg(test)]
    poison_accounting_hook: StdMutex<Option<Arc<PersistentV2PoisonAccountingHook>>>,
    setup_successes: AtomicU64,
    reused: AtomicU64,
    reconnects: AtomicU64,
    active: AtomicU64,
    healthy_active: AtomicU64,
    poisoned: AtomicU64,
    live_accounting: StdMutex<()>,
}

struct PersistentV2Activity {
    calls: usize,
    prewarms: usize,
}

#[cfg(test)]
struct PersistentV2PositiveReadReservationHook {
    observed: Notify,
    released: StdMutex<bool>,
    release: std::sync::Condvar,
}

#[cfg(test)]
impl PersistentV2PositiveReadReservationHook {
    fn new() -> Self {
        Self {
            observed: Notify::new(),
            released: StdMutex::new(false),
            release: std::sync::Condvar::new(),
        }
    }

    fn pause_after_reservation(&self) {
        self.observed.notify_waiters();
        let mut released = self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*released {
            released = self
                .release
                .wait(released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn resume(&self) {
        *self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.release.notify_all();
    }
}

#[cfg(test)]
struct PersistentV2PrewarmFinalPublicationHook {
    observed: Notify,
    released: Semaphore,
}

#[cfg(test)]
struct PersistentV2PoisonAccountingHook {
    transition_observed: Notify,
    diagnostic_observed: Notify,
    released: StdMutex<bool>,
    release: std::sync::Condvar,
}

#[cfg(test)]
impl PersistentV2PoisonAccountingHook {
    fn new() -> Self {
        Self {
            transition_observed: Notify::new(),
            diagnostic_observed: Notify::new(),
            released: StdMutex::new(false),
            release: std::sync::Condvar::new(),
        }
    }

    fn pause_after_poison_state(&self) {
        self.transition_observed.notify_waiters();
        let mut released = self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*released {
            released = self
                .release
                .wait(released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn diagnostic_started(&self) {
        self.diagnostic_observed.notify_waiters();
    }

    fn resume(&self) {
        *self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.release.notify_all();
    }
}

#[cfg(test)]
impl PersistentV2PrewarmFinalPublicationHook {
    fn new() -> Self {
        Self {
            observed: Notify::new(),
            released: Semaphore::new(0),
        }
    }

    async fn pause_before_publication(&self) {
        self.observed.notify_waiters();
        let permit = self
            .released
            .acquire()
            .await
            .expect("test hook release semaphore remains open");
        drop(permit);
    }

    fn resume(&self) {
        self.released.add_permits(1);
    }
}

enum PersistentV2ActivityKind {
    Call,
    Prewarm,
}

struct PersistentV2ActivityLease {
    pool: Arc<PersistentSessionConsumerV2Pool>,
    kind: PersistentV2ActivityKind,
}

impl Drop for PersistentV2ActivityLease {
    fn drop(&mut self) {
        let mut activity = self
            .pool
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match self.kind {
            PersistentV2ActivityKind::Call => {
                activity.calls = activity.calls.saturating_sub(1);
            }
            PersistentV2ActivityKind::Prewarm => {
                activity.prewarms = activity.prewarms.saturating_sub(1);
            }
        }
        drop(activity);
        self.pool.drained_notify.notify_waiters();
    }
}

impl PersistentSessionConsumerV2Pool {
    fn register_activity(
        self: &Arc<Self>,
        kind: PersistentV2ActivityKind,
    ) -> Result<PersistentV2ActivityLease, SessionConsumerClientError> {
        let mut activity = self
            .activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.shutdown.load(Ordering::Acquire) {
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        match kind {
            PersistentV2ActivityKind::Call => activity.calls = activity.calls.saturating_add(1),
            PersistentV2ActivityKind::Prewarm => {
                activity.prewarms = activity.prewarms.saturating_add(1)
            }
        }
        Ok(PersistentV2ActivityLease {
            pool: Arc::clone(self),
            kind,
        })
    }

    fn setup_deadline(
        &self,
        started: tokio::time::Instant,
        operation_deadline: Option<tokio::time::Instant>,
    ) -> Result<tokio::time::Instant, SessionConsumerClientError> {
        let mut deadline = started
            .checked_add(self.config.setup_timeout)
            .ok_or(SessionConsumerClientError::Deadline)?;
        if let Some(operation_deadline) = operation_deadline {
            deadline = deadline.min(operation_deadline);
        }
        if let Some(pre_request_deadline) = self
            .client
            .pre_request_connection_timeout
            .and_then(|timeout| started.checked_add(timeout))
        {
            deadline = deadline.min(pre_request_deadline);
        }
        Ok(deadline)
    }
    fn ensure_idle_reaper(self: &Arc<Self>) {
        if self.shutdown.load(Ordering::Acquire)
            || self
                .idle_reaper_started
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let Some(pool) = weak.upgrade() else {
                return;
            };
            let mut reauthentication = pool.client.reauthentication.subscribe();
            let mut material = Some(pool.client.tls_config.subscribe_material_changes());
            drop(pool);
            loop {
                let Some(pool) = weak.upgrade() else {
                    return;
                };
                if pool.shutdown.load(Ordering::Acquire) {
                    return;
                }
                {
                    let mut idle = pool
                        .idle
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    idle.retain_mut(|entry| pool.retainable_entry(entry));
                }
                #[cfg(test)]
                pool.idle_reaper_processed.notify_waiters();
                let tick_at = tokio::time::Instant::now() + Duration::from_millis(100);
                #[cfg(test)]
                pool.idle_reaper_armed.notify_waiters();
                drop(pool);
                tokio::select! {
                    _ = tokio::time::sleep_until(tick_at) => {}
                    result = reauthentication.changed() => {
                        if result.is_err() { return; }
                    }
                    _ = wait_consumer_material_change(&mut material) => {}
                }
            }
        });
    }

    fn current(&self, connection: &mut PersistentV2Connection) -> bool {
        if self.shutdown.load(Ordering::Acquire)
            || connection.state.poisoned.load(Ordering::Acquire)
            || connection.commands.is_closed()
        {
            return false;
        }
        if connection.admitted_generation != self.client.reauthentication.generation() {
            connection
                .retirement
                .send_replace(Some(RetirementReason::Explicit));
            return false;
        }
        true
    }

    /// A just-created lane has not yet been published for reusable work. It
    /// therefore must still match the precise handshake material snapshot;
    /// published lanes instead follow their actor-owned jittered lifecycle.
    fn fresh_current(&self, connection: &mut PersistentV2Connection) -> bool {
        if !self.current(connection) {
            return false;
        }
        if connection.admitted_material_epoch != self.client.tls_config.material_status().epoch() {
            connection
                .retirement
                .send_replace(Some(RetirementReason::MaterialEpoch));
            return false;
        }
        true
    }

    fn reusable(&self, connection: &mut PersistentV2Connection) -> bool {
        if !self.current(connection) {
            return false;
        }
        let now = tokio::time::Instant::now();
        if now >= connection.idle_deadline {
            connection
                .retirement
                .send_replace(Some(RetirementReason::IdleTimeout));
            return false;
        }
        true
    }

    fn retainable_entry(&self, entry: &mut PersistentV2PoolEntry) -> bool {
        match entry {
            PersistentV2PoolEntry::Lane(connection) => self.reusable(connection),
            PersistentV2PoolEntry::Poison(_) => true,
        }
    }

    fn take_front_poison_or_idle_lane(&self) -> Result<Option<PersistentV2Connection>, ()> {
        // The exact checkout decision shares the read-ahead positive-byte
        // transition's short queue lock. It is intentionally not an execution
        // lock: admission, setup, writes, and response waits remain outside.
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(PersistentV2PoolEntry::Poison(debt)) = idle.front_mut() {
            if debt.get() == usize::MAX {
                return Err(());
            }
            if let Some(remaining) = NonZeroUsize::new(debt.get() - 1) {
                *debt = remaining;
            } else {
                idle.pop_front();
            }
            return Err(());
        }
        while let Some(entry) = idle.pop_front() {
            match entry {
                PersistentV2PoolEntry::Poison(_) => return Err(()),
                PersistentV2PoolEntry::Lane(mut connection) => {
                    if self.reusable(&mut connection) {
                        return Ok(Some(connection));
                    }
                }
            }
        }
        Ok(None)
    }

    async fn admit_call(
        self: &Arc<Self>,
        started: tokio::time::Instant,
        operation_deadline: tokio::time::Instant,
    ) -> Result<(OwnedSemaphorePermit, OwnedSemaphorePermit), SessionConsumerClientError> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(SessionConsumerClientError::ShuttingDown);
        }
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
        let lane = tokio::time::timeout_at(wait_deadline, Arc::clone(&self.lanes).acquire_owned())
            .await
            .map_err(|_| late_error)?
            .map_err(|_| SessionConsumerClientError::ShuttingDown)?;
        let lane = complete_before_deadline(lane, wait_deadline, late_error)?;
        if self.shutdown.load(Ordering::Acquire) {
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        Ok((pending, lane))
    }

    async fn connect_until(
        self: &Arc<Self>,
        deadline: tokio::time::Instant,
    ) -> Result<PersistentV2Connection, SessionConsumerClientError> {
        let mut last_error = SessionConsumerClientError::Unavailable;
        let mut retry_delay = self.client.lifecycle_policy.reconnect_backoff_min();
        let mut forced = self.shutdown_forced_tx.subscribe();
        for attempt in 0..self.config.connect_attempts {
            let connected = tokio::select! {
                biased;
                _ = wait_for_v2_forced_shutdown(&mut forced) => {
                    return Err(SessionConsumerClientError::ShuttingDown);
                }
                connected = self.connect_once(deadline) => connected,
            };
            match connected {
                Ok(connection) => return Ok(connection),
                Err(error) => last_error = error,
            }
            if attempt.saturating_add(1) >= self.config.connect_attempts
                || tokio::time::Instant::now() >= deadline
                || !matches!(
                    last_error,
                    SessionConsumerClientError::Unavailable | SessionConsumerClientError::Deadline
                )
            {
                break;
            }
            let jitter = self.reconnect_jitter(attempt as u64);
            let delay = retry_delay
                .saturating_add(jitter)
                .min(self.client.lifecycle_policy.reconnect_backoff_max());
            let wake = tokio::time::Instant::now()
                .checked_add(delay)
                .unwrap_or(deadline)
                .min(deadline);
            if wake <= tokio::time::Instant::now() {
                break;
            }
            tokio::select! {
                biased;
                _ = wait_for_v2_forced_shutdown(&mut forced) => {
                    return Err(SessionConsumerClientError::ShuttingDown);
                }
                _ = tokio::time::sleep_until(wake) => {}
            }
            retry_delay = self.client.lifecycle_policy.next_backoff(retry_delay);
        }
        Err(last_error)
    }

    fn reconnect_jitter(&self, attempt: u64) -> Duration {
        let ceiling = duration_millis(self.config.reconnect_jitter);
        if ceiling == 0 {
            return Duration::ZERO;
        }
        let mixed = attempt.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17);
        Duration::from_millis(mixed % ceiling.saturating_add(1))
    }

    async fn connect_once(
        self: &Arc<Self>,
        deadline: tokio::time::Instant,
    ) -> Result<PersistentV2Connection, SessionConsumerClientError> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        // Cancellation releases the caller's logical checkout before this
        // actor can observe its closed completion. Hold a separate pool-width
        // permit with both TLS halves so no replacement can dial or allocate
        // another frame until the old actor has fully retired.
        let pool_width_admission =
            tokio::time::timeout_at(deadline, Arc::clone(&self.actor_lanes).acquire_owned())
                .await
                .map_err(|_| SessionConsumerClientError::Unavailable)?
                .map_err(|_| SessionConsumerClientError::ShuttingDown)?;
        let physical_admission = self.client.physical_admission.try_acquire_v2()?;
        let address = tokio::time::timeout_at(
            deadline,
            poll_persistent_consumer_setup_io((self.client.resolve)(), Some(&self.shutdown_io)),
        )
        .await
        .map_err(|_| SessionConsumerClientError::Unavailable)?
        .map_err(|_| SessionConsumerClientError::Unavailable)?;
        let stream = tokio::time::timeout_at(
            deadline,
            poll_persistent_consumer_setup_io(TcpStream::connect(address), Some(&self.shutdown_io)),
        )
        .await
        .map_err(|_| SessionConsumerClientError::Unavailable)?
        .map_err(|_| SessionConsumerClientError::Unavailable)?;
        stream
            .set_nodelay(true)
            .map_err(|_| SessionConsumerClientError::Unavailable)?;
        let generation = self.client.reauthentication.generation();
        let handshake = self
            .client
            .tls_config
            .begin_handshake()
            .map_err(|_| SessionConsumerClientError::Authentication)?;
        let connector = tokio_rustls::TlsConnector::from(consumer_client_tls_config_v2(
            handshake.rustls_config(),
        ));
        let tls = tokio::time::timeout_at(
            deadline,
            poll_persistent_consumer_setup_io(
                connector.connect(
                    self.client.server_name.clone(),
                    PersistentConsumerShutdownIo {
                        inner: stream,
                        barrier: Some(Arc::clone(&self.shutdown_io)),
                    },
                ),
                Some(&self.shutdown_io),
            ),
        )
        .await
        .map_err(|_| SessionConsumerClientError::Unavailable)?
        .map_err(classify_tls_io_error)
        .map_err(SessionConsumerClientError::from)?;
        if tls.get_ref().1.alpn_protocol() != Some(SESSION_QUORUM_CONSUMER_V2_ALPN) {
            return Err(SessionConsumerClientError::Protocol);
        }
        let peer = opc_tls::peer_tls_identity_from_client_connection(tls.get_ref().1)
            .map_err(|_| SessionConsumerClientError::Authentication)?;
        if peer.spiffe_id() != &self.client.expected_server_identity {
            return Err(SessionConsumerClientError::Authentication);
        }
        let established_at = tokio::time::Instant::now();
        let rotation_jitter = handshake.consumer_rotation_jitter(peer.spiffe_id());
        let lifecycle = ConnectionLifecycle::new(
            self.client.lifecycle_policy,
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
            Some(handshake.epoch()),
        )
        .map_err(|_| SessionConsumerClientError::Protocol)?;
        let tls = PersistentConsumerShutdownIo {
            inner: tls,
            barrier: Some(Arc::clone(&self.shutdown_io)),
        };
        let (mut reader, mut writer) = tokio::io::split(tls);
        write_frame_bounded_until(
            &mut writer,
            &ConsumerV2WireRequest::Hello(ConsumerHello {
                transport_revision: SESSION_QUORUM_CONSUMER_V2_TRANSPORT_REVISION,
                scope: self.client.scope,
                response_frame_size: consumer_wire_frame_size(MAX_NEGOTIATED_FRAME_SIZE)
                    .map_err(SessionConsumerClientError::from)?,
            }),
            MAX_NEGOTIATED_FRAME_SIZE,
            deadline.min(lifecycle.retire_at()),
        )
        .await
        .map_err(SessionConsumerClientError::from)?;
        let ack = read_authenticated_consumer_bootstrap_frame_until::<_, ConsumerV2WireResponse>(
            &mut reader,
            MAX_NEGOTIATED_FRAME_SIZE,
            deadline.min(lifecycle.retire_at()),
            effective_consumer_idle_timeout(self.client.idle_timeout),
        )
        .await
        .map_err(SessionConsumerClientError::from)?
        .ok_or(SessionConsumerClientError::Unavailable)?;
        let request_frame_size = match ack {
            ConsumerV2WireResponse::HelloAck(ack)
                if ack.transport_revision == SESSION_QUORUM_CONSUMER_V2_TRANSPORT_REVISION
                    && ack.scope == self.client.scope =>
            {
                checked_consumer_frame_size(ack.request_frame_size)
                    .map_err(SessionConsumerClientError::from)?
            }
            ConsumerV2WireResponse::HelloRejected(SessionConsumerRejection::ScopeMismatch) => {
                return Err(SessionConsumerClientError::Scope);
            }
            ConsumerV2WireResponse::HelloRejected(SessionConsumerRejection::Unauthorized) => {
                return Err(SessionConsumerClientError::Authentication);
            }
            _ => return Err(SessionConsumerClientError::Protocol),
        };
        let admission = handshake
            .admit()
            .map_err(|_| SessionConsumerClientError::Authentication)?;
        if !consumer_fresh_admission_is_current(
            generation,
            admission.epoch(),
            self.client.reauthentication.generation(),
            self.client.tls_config.material_status().epoch(),
        ) || self.shutdown.load(Ordering::Acquire)
        {
            return Err(SessionConsumerClientError::Deadline);
        }
        let (commands, command_rx) = mpsc::channel(1);
        let (retirement, actor_retirement) = watch::channel(None);
        let actor_client = self.client.clone();
        let actor_reauthentication = self.client.reauthentication.subscribe();
        let actor_material = Some(self.client.tls_config.subscribe_material_changes());
        let actor_forced = self.shutdown_forced_tx.subscribe();
        let actor_shutdown_io = Arc::clone(&self.shutdown_io);
        let state = PersistentV2LaneState::new();
        {
            let _accounting = self
                .live_accounting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.healthy.store(true, Ordering::Release);
            counter_increment(&self.setup_successes);
            counter_increment(&self.active);
            counter_increment(&self.healthy_active);
        }
        let actor_lifetime = PersistentV2LaneLifetime {
            pool_connection: Arc::downgrade(self),
            state: Arc::clone(&state),
            _pool_width_admission: Some(pool_width_admission),
            _physical_admission: Some(physical_admission),
        };
        tokio::spawn(run_persistent_v2_lane(PersistentV2LaneActor {
            reader: Box::new(reader),
            writer: Box::new(writer),
            request_frame_size,
            lifecycle,
            rotation_jitter,
            client: actor_client,
            reauthentication_changes: actor_reauthentication,
            material_changes: actor_material,
            retirement: actor_retirement,
            forced: actor_forced,
            shutdown_io: actor_shutdown_io,
            commands: command_rx,
            lifetime: actor_lifetime,
        }));
        Ok(PersistentV2Connection {
            commands,
            idle_deadline: deadline,
            retirement,
            admitted_generation: generation,
            admitted_material_epoch: admission.epoch(),
            state,
        })
    }

    async fn execute(
        self: &Arc<Self>,
        request: &SessionConsumerV2Request,
    ) -> Result<SessionConsumerV2Response, PersistentSessionConsumerV2ExecuteError> {
        self.ensure_idle_reaper();
        if request.scope() != self.client.scope || request.validate().is_err() {
            return Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            });
        }
        let started = tokio::time::Instant::now();
        let deadline = started
            .checked_add(effective_consumer_operation_timeout(
                self.client.operation_timeout,
            ))
            .ok_or(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Deadline,
            })?;
        let (_pending, _lane) = self
            .admit_call(started, deadline)
            .await
            .map_err(|cause| PersistentSessionConsumerV2ExecuteError::NotTransmitted { cause })?;
        let _activity = self
            .register_activity(PersistentV2ActivityKind::Call)
            .map_err(|cause| PersistentSessionConsumerV2ExecuteError::NotTransmitted { cause })?;
        // A read-ahead actor can reserve poison while this call waits for fair
        // admission. Consume that debt or select a healthy lane in one queue
        // transition before any reconnect or call byte is possible.
        let connection = match self.take_front_poison_or_idle_lane() {
            Err(()) => {
                return Err(v2_persistent_error(
                    request,
                    false,
                    SessionConsumerClientError::Protocol,
                ));
            }
            Ok(connection) => connection,
        };
        if connection.is_some() {
            counter_increment(&self.reused);
        }
        let (mut connection, fresh) = match connection {
            Some(connection) => (connection, false),
            None => (
                self.connect_until(self.setup_deadline(started, Some(deadline)).map_err(
                    |cause| PersistentSessionConsumerV2ExecuteError::NotTransmitted { cause },
                )?)
                .await
                .map_err(|cause| {
                    PersistentSessionConsumerV2ExecuteError::NotTransmitted { cause }
                })?,
                true,
            ),
        };
        connection.idle_deadline = tokio::time::Instant::now()
            .checked_add(effective_consumer_idle_timeout(self.client.idle_timeout))
            .ok_or(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            })?;
        if !(if fresh {
            self.fresh_current(&mut connection)
        } else {
            self.current(&mut connection)
        }) {
            return Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Deadline,
            });
        }
        let attempt_nonce = v2_attempt_nonce().map_err(|_| {
            PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            }
        })?;
        let request_commitment = v2_request_commitment(request).map_err(|_| {
            PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            }
        })?;
        let (completion, completed) = oneshot::channel();
        let write_progress = Arc::new(crate::protocol::FrameWriteProgress::new());
        connection
            .commands
            .try_send(PersistentV2LaneCall {
                request: request.clone(),
                attempt_nonce,
                request_commitment,
                deadline,
                completion,
                write_progress: Arc::clone(&write_progress),
            })
            .map_err(
                |_| PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                    cause: SessionConsumerClientError::Protocol,
                },
            )?;
        let response = match completed.await {
            Ok(Ok(response)) => response,
            Ok(Err(cause)) => {
                return Err(v2_persistent_error(
                    request,
                    write_progress.accepted_any(),
                    cause,
                ));
            }
            Err(_) => {
                return Err(v2_persistent_error(
                    request,
                    write_progress.accepted_any(),
                    SessionConsumerClientError::Protocol,
                ));
            }
        };
        let service_outcome_unknown = v2_response_is_outcome_unknown(&response);
        if self.reusable(&mut connection) && !v2_response_retires_connection_authority(&response) {
            self.idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push_back(PersistentV2PoolEntry::Lane(connection));
        }
        if service_outcome_unknown {
            return Err(v2_outcome_unknown(request).unwrap_or(
                PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                    cause: SessionConsumerClientError::Protocol,
                },
            ));
        }
        Ok(response)
    }

    async fn prewarm(self: &Arc<Self>) -> Result<(), SessionConsumerClientError> {
        self.ensure_idle_reaper();
        if self.shutdown.load(Ordering::Acquire) {
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        // Prewarm owns every V2 lane while it publishes replacements, so it
        // cannot race a call or another prewarm into exceeding the fixed V2
        // width. Its admission is deliberately independent from V1.
        let _prewarm = Arc::clone(&self.prewarm)
            .try_acquire_owned()
            .map_err(|_| SessionConsumerClientError::Overloaded)?;
        let _activity = self.register_activity(PersistentV2ActivityKind::Prewarm)?;
        let lane_count = u32::try_from(self.config.request_connections)
            .map_err(|_| SessionConsumerClientError::Overloaded)?;
        let reservation_deadline = tokio::time::Instant::now()
            .checked_add(self.config.pool_wait_timeout)
            .ok_or(SessionConsumerClientError::Overloaded)?;
        let _lanes = tokio::time::timeout_at(
            reservation_deadline,
            Arc::clone(&self.lanes).acquire_many_owned(lane_count),
        )
        .await
        .map_err(|_| SessionConsumerClientError::Overloaded)?
        .map_err(|_| SessionConsumerClientError::ShuttingDown)?;
        let _pending = Arc::clone(&self.pending)
            .try_acquire_many_owned(lane_count)
            .map_err(|_| SessionConsumerClientError::Overloaded)?;
        if self.shutdown.load(Ordering::Acquire) {
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        let setup_started = tokio::time::Instant::now();
        let setup_deadline = self.setup_deadline(setup_started, None)?;
        // A lane actor owns its physical permit until both TLS halves exit.
        // After retiring stale idle handles, wait for those exact actors to
        // release before dialing replacements; a transient physical-capacity
        // failure must not turn an otherwise valid reauthentication prewarm
        // into an overload result.
        let retained_lanes = loop {
            let retained_lanes = {
                let mut idle = self
                    .idle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                idle.retain_mut(|entry| self.retainable_entry(entry));
                idle.iter()
                    .filter(|entry| matches!(entry, PersistentV2PoolEntry::Lane(_)))
                    .count()
            };
            if usize::try_from(self.active.load(Ordering::Acquire)).unwrap_or(usize::MAX)
                <= retained_lanes
            {
                break retained_lanes;
            }
            let retired = self.drained_notify.notified();
            tokio::pin!(retired);
            retired.as_mut().enable();
            if usize::try_from(self.active.load(Ordering::Acquire)).unwrap_or(usize::MAX)
                <= retained_lanes
            {
                continue;
            }
            tokio::time::timeout_at(setup_deadline, &mut retired)
                .await
                .map_err(|_| SessionConsumerClientError::Unavailable)?;
            if self.shutdown.load(Ordering::Acquire) {
                return Err(SessionConsumerClientError::ShuttingDown);
            }
        };
        // Staging is deliberately optimistic: each connection remains current
        // only until the final queue publication. Re-prune both retained and
        // staged lanes at that publication boundary and top up under this one
        // fixed setup deadline. Poison entries stay at the front, but are
        // never counted as retained/authenticated target capacity.
        let mut staged = Vec::with_capacity(
            self.config
                .request_connections
                .saturating_sub(retained_lanes),
        );
        loop {
            let healthy_lanes = {
                let mut idle = self
                    .idle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                idle.retain_mut(|entry| self.retainable_entry(entry));
                staged.retain_mut(|connection| self.fresh_current(connection));
                idle.iter()
                    .filter(|entry| matches!(entry, PersistentV2PoolEntry::Lane(_)))
                    .count()
            };
            let total_healthy = healthy_lanes.saturating_add(staged.len());
            if total_healthy > self.config.request_connections {
                return Err(SessionConsumerClientError::Unavailable);
            }
            let deficit = self
                .config
                .request_connections
                .saturating_sub(total_healthy);
            if deficit != 0 {
                let replacements = stream::iter(0..deficit)
                    .map(|_| Arc::clone(self))
                    .map(|pool| async move { pool.connect_until(setup_deadline).await })
                    .buffer_unordered(deficit)
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?;
                staged.extend(replacements);
                continue;
            }

            let publication_idle_deadline = tokio::time::Instant::now()
                .checked_add(effective_consumer_idle_timeout(self.client.idle_timeout))
                .ok_or(SessionConsumerClientError::Deadline)?;
            for connection in &mut staged {
                connection.idle_deadline = publication_idle_deadline;
            }
            #[cfg(test)]
            let final_publication_hook = {
                self.prewarm_final_publication_hook
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
            };
            #[cfg(test)]
            if let Some(hook) = final_publication_hook {
                hook.pause_before_publication().await;
            }
            let mut idle = self
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.shutdown.load(Ordering::Acquire) {
                return Err(SessionConsumerClientError::ShuttingDown);
            }
            idle.retain_mut(|entry| self.retainable_entry(entry));
            staged.retain_mut(|connection| self.fresh_current(connection));
            complete_before_deadline((), setup_deadline, SessionConsumerClientError::Deadline)?;
            let published_lanes = idle
                .iter()
                .filter(|entry| matches!(entry, PersistentV2PoolEntry::Lane(_)))
                .count();
            if published_lanes.saturating_add(staged.len()) == self.config.request_connections {
                idle.extend(staged.drain(..).map(PersistentV2PoolEntry::Lane));
                return Ok(());
            }
            // A retained or staged lane changed while the idle deadline was
            // installed. Drop the short lock and re-stage only the deficit.
        }
    }

    fn start_shutdown(self: &Arc<Self>) {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return;
        }
        self.pending.close();
        self.lanes.close();
        self.prewarm.close();
        {
            let mut idle = self
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            idle.clear();
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(self.config.shutdown_drain)
            .unwrap_or_else(tokio::time::Instant::now);
        // This pool-owned task is spawned only after admission closes. It is
        // independent from the caller awaiting public shutdown, so cancelling
        // that caller cannot extend V2 I/O beyond the fixed drain.
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let notified = pool.drained_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                #[cfg(test)]
                pool.shutdown_activity_wait_armed.notify_waiters();
                let drained = {
                    let activity = pool
                        .activity
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    activity.calls == 0 && activity.prewarms == 0
                };
                if drained || tokio::time::Instant::now() >= deadline {
                    break;
                }
                if tokio::time::timeout_at(deadline, &mut notified)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            pool.shutdown_io.force();
            pool.shutdown_forced_tx.send_replace(true);
            pool.shutdown_io.wait_quiescent().await;
            loop {
                let actor_drained = pool.drained_notify.notified();
                tokio::pin!(actor_drained);
                actor_drained.as_mut().enable();
                if pool.active.load(Ordering::Acquire) == 0 {
                    break;
                }
                actor_drained.await;
            }
            pool.shutdown_complete.store(true, Ordering::Release);
            pool.shutdown_complete_notify.notify_waiters();
        });
    }

    async fn wait_shutdown_complete(&self) {
        loop {
            let completed = self.shutdown_complete_notify.notified();
            tokio::pin!(completed);
            completed.as_mut().enable();
            if self.shutdown_complete.load(Ordering::Acquire) {
                return;
            }
            completed.await;
        }
    }

    fn diagnostics(&self) -> PersistentSessionConsumerV2Diagnostics {
        #[cfg(test)]
        if let Some(hook) = self
            .poison_accounting_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            hook.diagnostic_started();
        }
        let active = {
            let _accounting = self
                .live_accounting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.healthy_active.load(Ordering::Acquire)
        };
        PersistentSessionConsumerV2Diagnostics {
            setup_successes: self.setup_successes.load(Ordering::Relaxed),
            reused: self.reused.load(Ordering::Relaxed),
            reconnects: self.reconnects.load(Ordering::Relaxed),
            active,
            idle: self
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .filter(|entry| {
                    matches!(
                        entry,
                        PersistentV2PoolEntry::Lane(connection)
                            if !connection.state.poisoned.load(Ordering::Acquire)
                    )
                })
                .count() as u64,
        }
    }

    fn readiness(&self) -> PersistentSessionConsumerReadiness {
        let lane_count = u32::try_from(self.config.request_connections)
            .expect("validated persistent V2 request width fits u32");
        let all_lanes_idle = Arc::clone(&self.lanes)
            .try_acquire_many_owned(lane_count)
            .ok();
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        idle.retain_mut(|entry| self.retainable_entry(entry));
        let ready_lanes = idle
            .iter()
            .filter(|entry| matches!(entry, PersistentV2PoolEntry::Lane(_)))
            .count();
        let poison_debt = idle.iter().fold(0_usize, |debt, entry| match entry {
            PersistentV2PoolEntry::Poison(entry_debt) => debt.saturating_add(entry_debt.get()),
            PersistentV2PoolEntry::Lane(_) => debt,
        });
        // Poison is a front-priority logical checkout failure, never a ready
        // lane.  Keep the physical lane count visible through diagnostics,
        // but make readiness describe capacity that can accept a Call now.
        let ready_request_connections = ready_lanes.saturating_sub(poison_debt);
        PersistentSessionConsumerReadiness {
            ready: !self.shutdown.load(Ordering::Acquire)
                && all_lanes_idle.is_some()
                && poison_debt == 0
                && ready_request_connections == self.config.request_connections,
            configured_request_connections: self.config.request_connections,
            ready_request_connections,
        }
    }
}

fn v2_persistent_error(
    request: &SessionConsumerV2Request,
    wrote: bool,
    cause: SessionConsumerClientError,
) -> PersistentSessionConsumerV2ExecuteError {
    if wrote && v2_operation_is_effectful(request.operation()) {
        if let Some(error) = v2_outcome_unknown(request) {
            return error;
        }
    }
    if wrote {
        return PersistentSessionConsumerV2ExecuteError::ReadUnavailable { cause };
    }
    PersistentSessionConsumerV2ExecuteError::NotTransmitted { cause }
}

fn v2_outcome_unknown(
    request: &SessionConsumerV2Request,
) -> Option<PersistentSessionConsumerV2ExecuteError> {
    match request.operation() {
        SessionConsumerV2Operation::FencedTransitionV2 { request } => {
            Some(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown {
                request_id: request.request_id(),
            })
        }
        SessionConsumerV2Operation::FencedTransitionV2Batch { requests } => Some(
            PersistentSessionConsumerV2ExecuteError::OutcomeUnknownBatch {
                request_ids: requests
                    .iter()
                    .map(|request| request.request_id())
                    .collect(),
            },
        ),
        SessionConsumerV2Operation::FencedTransitionV2Capability
        | SessionConsumerV2Operation::FencedTransitionV2HistoryState
        | SessionConsumerV2Operation::FencedTransitionV2Status { .. } => None,
        _ => None,
    }
}

fn v2_response_is_outcome_unknown(response: &SessionConsumerV2Response) -> bool {
    matches!(
        response,
        SessionConsumerV2Response::FencedTransitionV2(Err(
            opc_session_store::SessionConsumerV2FencedTransitionError::OutcomeUnknown
        )) | SessionConsumerV2Response::FencedTransitionV2Batch(Err(
            opc_session_store::consumer::SessionConsumerV2FencedTransitionBatchError::OutcomeUnknown { .. }
        ))
    )
}

fn v2_operation_is_effectful(operation: &SessionConsumerV2Operation) -> bool {
    operation.is_effectful()
}

fn v2_response_retires_connection_authority(response: &SessionConsumerV2Response) -> bool {
    matches!(
        response,
        SessionConsumerV2Response::Rejected(
            SessionConsumerRejection::ScopeMismatch
                | SessionConsumerRejection::Unauthorized
                | SessionConsumerRejection::MalformedRequest
        )
    )
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

    fn record_error(
        &self,
        error: SessionConsumerClientError,
        may_have_sent: bool,
        effectful: bool,
    ) {
        self.record_failure(error);
        if may_have_sent && effectful {
            counter_increment(&self.counters.outcome_unknown);
        } else if !may_have_sent {
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
                .checked_add(effective_consumer_idle_timeout(self.client.idle_timeout))
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
                tokio::pin!(notified);
                notified.as_mut().enable();
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
                if tokio::time::timeout_at(deadline, &mut notified)
                    .await
                    .is_err()
                {
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
            tokio::pin!(completed);
            completed.as_mut().enable();
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
        inherited_deadline: tokio::time::Instant,
        inherited_budget_active: bool,
    ) -> Result<ConsumerConnection, SessionConsumerClientError> {
        let setup_started = tokio::time::Instant::now();
        let configured_setup_deadline = setup_started
            .checked_add(self.config.setup_timeout)
            .ok_or(SessionConsumerClientError::Deadline)?;
        let mut setup_budget_active =
            inherited_budget_active || configured_setup_deadline < inherited_deadline;
        let mut setup_deadline = configured_setup_deadline.min(inherited_deadline);
        if let Some(inherited_deadline) = self
            .client
            .pre_request_connection_timeout
            .and_then(|timeout| setup_started.checked_add(timeout))
        {
            setup_budget_active |= inherited_deadline < setup_deadline;
            setup_deadline = setup_deadline.min(inherited_deadline);
        }
        let setup_attempt = PersistentSetupAttempt::begin(&self.counters);
        let result = self
            .client
            .connect(
                setup_deadline,
                setup_budget_active,
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
                pre_request_timeout_error(setup_budget_active),
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
    v2_pool: Arc<PersistentSessionConsumerV2Pool>,
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
    pub fn from_stateless(
        client: StatelessSessionConsumerClient,
    ) -> Result<Self, PersistentSessionConsumerConfigError> {
        Self::try_from_stateless(client, PersistentSessionConsumerConfig::default())
    }

    /// Construct a bounded pool from a configured stateless client.
    pub fn try_from_stateless(
        client: StatelessSessionConsumerClient,
        config: PersistentSessionConsumerConfig,
    ) -> Result<Self, PersistentSessionConsumerConfigError> {
        config.validate()?;
        if client.idle_timeout.is_zero()
            || client.idle_timeout > DEFAULT_CONSUMER_IDLE_TIMEOUT
            || !valid_consumer_operation_timeout(client.operation_timeout)
            || client
                .lifecycle_policy
                .validate_at(tokio::time::Instant::now())
                .is_err()
        {
            return Err(PersistentSessionConsumerConfigError::Timing);
        }
        let (shutdown_tx, _) = watch::channel(PersistentShutdownPhase::Running);
        // A per-pool random starting point prevents independently constructed
        // clients from aligning their otherwise bounded reconnect sequences.
        // The seed is local-only and is never included in diagnostics.
        let (jitter_seed_high, jitter_seed_low) = uuid::Uuid::new_v4().as_u64_pair();
        let pool = Arc::new(PersistentSessionConsumerPool {
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
        });
        let (v2_shutdown_forced_tx, _) = watch::channel(false);
        let v2_pool = Arc::new(PersistentSessionConsumerV2Pool {
            client: pool.client.clone(),
            config,
            // V2 retains its own fixed logical admission budget. Its actor
            // and physical caps remain separately bounded below.
            lanes: Arc::new(Semaphore::new(config.request_connections)),
            actor_lanes: Arc::new(Semaphore::new(config.request_connections)),
            // Includes active V2 lane owners, independently of V1's queue.
            pending: Arc::new(Semaphore::new(
                config
                    .request_connections
                    .saturating_add(config.pending_calls),
            )),
            prewarm: Arc::new(Semaphore::new(1)),
            idle: StdMutex::new(VecDeque::with_capacity(config.request_connections)),
            shutdown: AtomicBool::new(false),
            shutdown_forced_tx: v2_shutdown_forced_tx,
            shutdown_io: Arc::new(PersistentConsumerIoBarrier::new()),
            shutdown_complete: AtomicBool::new(false),
            shutdown_complete_notify: Notify::new(),
            activity: StdMutex::new(PersistentV2Activity {
                calls: 0,
                prewarms: 0,
            }),
            drained_notify: Notify::new(),
            idle_reaper_started: AtomicBool::new(false),
            #[cfg(test)]
            idle_reaper_armed: Notify::new(),
            #[cfg(test)]
            idle_reaper_processed: Notify::new(),
            #[cfg(test)]
            shutdown_activity_wait_armed: Notify::new(),
            #[cfg(test)]
            positive_read_reservation_hook: StdMutex::new(None),
            #[cfg(test)]
            prewarm_final_publication_hook: StdMutex::new(None),
            #[cfg(test)]
            poison_accounting_hook: StdMutex::new(None),
            setup_successes: AtomicU64::new(0),
            reused: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            active: AtomicU64::new(0),
            healthy_active: AtomicU64::new(0),
            poisoned: AtomicU64::new(0),
            live_accounting: StdMutex::new(()),
        });
        Ok(Self { pool, v2_pool })
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
        let mut v2_idle = self
            .v2_pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        v2_idle.retain_mut(|entry| self.v2_pool.retainable_entry(entry));
        Ok(generation)
    }

    /// Establish the independent fixed revision-5 pool without dispatching a
    /// V2 operation. V1 and V2 retain separate queues and sockets while
    /// sharing the stateless client's bounded physical connection admission.
    pub async fn prewarm_v2(&self) -> Result<(), SessionConsumerClientError> {
        self.v2_pool.prewarm().await
    }

    /// Execute one revision-5 request on a dedicated bounded V2 lane.
    ///
    /// A post-write transport loss reports the complete caller-retained V2
    /// ID as `OutcomeUnknown`; callers recover through V2 status rather than
    /// minting a successor ID.
    pub async fn execute_v2(
        &self,
        request: &SessionConsumerV2Request,
    ) -> Result<SessionConsumerV2Response, PersistentSessionConsumerV2ExecuteError> {
        self.v2_pool.execute(request).await
    }

    /// Return the independent V2 fixed-pool diagnostics.
    pub fn v2_diagnostics(&self) -> PersistentSessionConsumerV2Diagnostics {
        self.v2_pool.diagnostics()
    }

    /// Return a conservative authenticated-idle-capacity snapshot for the
    /// independent revision-5 pool.
    pub async fn v2_readiness(&self) -> PersistentSessionConsumerReadiness {
        self.v2_pool.readiness()
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
            .checked_add(effective_consumer_operation_timeout(
                self.pool.client.operation_timeout,
            ))
            .ok_or(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Deadline,
            ))?;
        if request.scope() != self.pool.client.scope {
            self.pool
                .record_error(SessionConsumerClientError::Scope, false, false);
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Scope,
            ));
        }
        if matches!(request.operation(), SessionConsumerOperation::Watch { .. }) {
            self.pool
                .record_error(SessionConsumerClientError::Protocol, false, false);
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Protocol,
            ));
        }
        if !consumer_request_has_exact_fenced_transition_id(request) || request.validate().is_err()
        {
            self.pool
                .record_error(SessionConsumerClientError::Protocol, false, false);
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Protocol,
            ));
        }
        let write_progress = FrameWriteProgress::new();
        let outcome = PersistentCallOutcome::new(
            Arc::clone(&self.pool),
            &write_progress,
            consumer_operation_is_effectful(request.operation()),
        );
        let (_pending, _lane) = match self.pool.admit_call(started, deadline).await {
            Ok(admission) => admission,
            Err(error) => {
                outcome.complete();
                self.pool.record_error(error, false, false);
                return Err(SessionConsumerCallError::BeforeCallWrite(error));
            }
        };
        let _activity = match self.pool.register_call() {
            Ok(activity) => activity,
            Err(error) => {
                outcome.complete();
                self.pool.record_error(error, false, false);
                return Err(SessionConsumerCallError::BeforeCallWrite(error));
            }
        };
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
                    consumer_operation_is_effectful(request.operation()),
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

    /// Read the quorum's exact atomic-transition capability through a
    /// retained request lane.
    pub async fn fenced_transition_capability(
        &self,
    ) -> Result<AtomicFencedTransitionCapability, StoreError> {
        match self
            .execute_read(self.request(
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::FencedTransitionCapability,
            ))
            .await
        {
            Ok(SessionConsumerResponse::FencedTransitionCapability(result)) => {
                result.map_err(SessionConsumerStoreError::into_store_error)
            }
            Ok(SessionConsumerResponse::Rejected(rejection)) => {
                Err(rejection_into_store_error(rejection))
            }
            Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
                "consumer fenced-transition capability unavailable".into(),
            )),
        }
    }

    /// Read one exact key's record and durable fence floor through a retained
    /// request lane.
    pub async fn observe_fenced_transition(
        &self,
        key: opc_session_store::SessionKey,
    ) -> Result<FencedTransitionObservation, StoreError> {
        match self
            .execute_read(self.request(
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::ObserveFencedTransition { key },
            ))
            .await
        {
            Ok(SessionConsumerResponse::ObserveFencedTransition(result)) => {
                result.map_err(SessionConsumerStoreError::into_store_error)
            }
            Ok(SessionConsumerResponse::Rejected(rejection)) => {
                Err(rejection_into_store_error(rejection))
            }
            Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
                "consumer fenced-transition observation unavailable".into(),
            )),
        }
    }

    /// Submit exactly one complete atomic transition over a persistent lane.
    /// A post-write timeout or EOF retires the lane and returns the exact
    /// caller-owned transition ID as an unknown outcome.
    pub async fn fenced_transition(
        &self,
        request: &FencedTransitionRequest,
    ) -> Result<FencedTransitionOutcome, SessionConsumerFencedTransitionMutationError> {
        let outer_request_id = consumer_fenced_transition_request_id(request);
        fenced_transition_response(
            request,
            self.execute_classified(&self.request(
                outer_request_id,
                SessionConsumerOperation::FencedTransition {
                    request: Box::new(request.clone()),
                },
            ))
            .await,
        )
    }

    /// Recover one retained transition status through a persistent read lane.
    pub async fn fenced_transition_status(
        &self,
        request: &FencedTransitionRequest,
    ) -> Result<SessionConsumerFencedTransitionStatus, StoreError> {
        let request_id = consumer_fenced_transition_request_id(request);
        match self
            .execute_read(self.request(
                request_id,
                SessionConsumerOperation::FencedTransitionStatus {
                    request: Box::new(request.clone()),
                },
            ))
            .await
        {
            Ok(SessionConsumerResponse::FencedTransitionStatus(result)) => {
                result.map_err(SessionConsumerStoreError::into_store_error)
            }
            Ok(SessionConsumerResponse::Rejected(rejection)) => {
                Err(rejection_into_store_error(rejection))
            }
            Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
                "consumer fenced-transition status unavailable".into(),
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
                SessionConsumerResponse::AcquireLease(value) => Some(value),
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
                SessionConsumerResponse::RenewLease(value) => Some(value),
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
                .record_error(SessionConsumerClientError::ShuttingDown, false, false);
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        let permit = Arc::clone(&self.pool.watches)
            .try_acquire_owned()
            .map_err(|_| {
                self.pool
                    .record_error(SessionConsumerClientError::Overloaded, false, false);
                SessionConsumerClientError::Overloaded
            })?;
        let lease = self.pool.register_watch(permit).inspect_err(|&error| {
            self.pool.record_error(error, false, false);
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
                    self.pool.record_error(error, false, false);
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
                .record_error(SessionConsumerClientError::ShuttingDown, false, false);
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
                    result = self.pool.connect(
                        pre_request_deadline,
                        pre_request_budget_active,
                    ) => result,
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
                    let retry_deadline = if pre_request_budget_active {
                        pre_request_deadline
                    } else {
                        deadline
                    };
                    if tokio::time::Instant::now() >= retry_deadline {
                        return Err(SessionConsumerCallError::BeforeCallWrite(error));
                    }
                    let delay = self.pool.reconnect_delay();
                    if !delay.is_zero() {
                        tokio::select! {
                            biased;
                            _ = wait_for_forced_shutdown(&mut shutdown, &self.pool.shutdown_phase) => {
                                return Err(SessionConsumerCallError::BeforeCallWrite(
                                    SessionConsumerClientError::ShuttingDown,
                                ));
                            }
                            _ = tokio::time::sleep_until(
                                (tokio::time::Instant::now() + delay).min(retry_deadline),
                            ) => {}
                        }
                    }
                    if tokio::time::Instant::now() >= retry_deadline {
                        return Err(SessionConsumerCallError::BeforeCallWrite(error));
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
                    if !response_retires_connection_authority(&response)
                        && !response_is_outcome_unknown(request.operation(), &response)
                    {
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
                    let retry_deadline = if pre_request_budget_active {
                        pre_request_deadline
                    } else {
                        deadline
                    };
                    if tokio::time::Instant::now() >= retry_deadline {
                        return Err(SessionConsumerCallError::BeforeCallWrite(error));
                    }
                    let delay = self.pool.reconnect_delay();
                    if !delay.is_zero() {
                        tokio::select! {
                            biased;
                            _ = wait_for_forced_shutdown(&mut shutdown, &self.pool.shutdown_phase) => {
                                return Err(SessionConsumerCallError::BeforeCallWrite(
                                    SessionConsumerClientError::ShuttingDown,
                                ));
                            }
                            _ = tokio::time::sleep_until(
                                (tokio::time::Instant::now() + delay).min(retry_deadline),
                            ) => {}
                        }
                    }
                    if tokio::time::Instant::now() >= retry_deadline {
                        return Err(SessionConsumerCallError::BeforeCallWrite(error));
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
                (0..deficit).map(|_| self.pool.connect(deadline, true)),
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
        // Both ALPN-isolated pools enter their cancellation-safe shutdown
        // drivers before either drain is awaited; V2 cannot consume a second
        // drain window after V1 has already completed.
        self.v2_pool.start_shutdown();
        self.pool.start_shutdown();
        let (report, ()) = tokio::join!(
            self.pool.shutdown_report(),
            self.v2_pool.wait_shutdown_complete()
        );
        report
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

fn consumer_fenced_transition_request_id(
    request: &FencedTransitionRequest,
) -> SessionConsumerRequestId {
    SessionConsumerRequestId::from_bytes(*request.request_id().as_bytes())
}

fn consumer_fenced_transition_store_error(
    error: SessionConsumerFencedTransitionError,
) -> StoreError {
    match error {
        SessionConsumerFencedTransitionError::Store(error) => error.into_store_error(),
        SessionConsumerFencedTransitionError::RequestConflict => {
            StoreError::FencedTransitionRequestConflict
        }
        SessionConsumerFencedTransitionError::Expired => StoreError::FencedTransitionRequestExpired,
        SessionConsumerFencedTransitionError::HistoryFull => {
            StoreError::FencedTransitionHistoryFull
        }
        SessionConsumerFencedTransitionError::RetentionExhausted => {
            StoreError::FencedTransitionRetentionExhausted
        }
        SessionConsumerFencedTransitionError::StorageExhausted => {
            StoreError::FencedTransitionStorageExhausted
        }
        _ => StoreError::BackendUnavailable("consumer fenced-transition error unavailable".into()),
    }
}

fn fenced_transition_response(
    request: &FencedTransitionRequest,
    response: Result<SessionConsumerResponse, SessionConsumerCallError>,
) -> Result<FencedTransitionOutcome, SessionConsumerFencedTransitionMutationError> {
    let request_id = request.request_id();
    match response {
        Ok(SessionConsumerResponse::FencedTransition(Ok(outcome)))
            if outcome.matches_request(request) =>
        {
            Ok(outcome)
        }
        Ok(SessionConsumerResponse::FencedTransition(Err(
            SessionConsumerFencedTransitionError::Store(
                SessionConsumerStoreError::OutcomeUnavailable,
            ),
        )))
        | Err(SessionConsumerCallError::MayHaveSent(_)) => {
            Err(SessionConsumerFencedTransitionMutationError::OutcomeUnknown { request_id })
        }
        Ok(SessionConsumerResponse::OutcomeUnknown(SessionConsumerOutcomeUnknown::Mutation {
            request_id: wire_request_id,
        })) if wire_request_id == consumer_fenced_transition_request_id_from_fenced(request_id) => {
            Err(SessionConsumerFencedTransitionMutationError::OutcomeUnknown { request_id })
        }
        Err(SessionConsumerCallError::BeforeCallWrite(cause)) => {
            Err(SessionConsumerFencedTransitionMutationError::NotTransmitted { cause })
        }
        Ok(SessionConsumerResponse::Rejected(rejection)) => {
            Err(SessionConsumerFencedTransitionMutationError::Store(
                rejection_into_store_error(rejection),
            ))
        }
        Ok(SessionConsumerResponse::FencedTransition(Err(error)))
            if fenced_transition_execute_error_matches_request(&error) =>
        {
            Err(SessionConsumerFencedTransitionMutationError::Store(
                consumer_fenced_transition_store_error(error),
            ))
        }
        // A semantically checked typed call can reach this only if a newer
        // peer violates the response contract.  Its effect boundary is not
        // safely knowable, so retain the exact transition ID.
        Ok(_) => Err(SessionConsumerFencedTransitionMutationError::OutcomeUnknown { request_id }),
    }
}

fn consumer_fenced_transition_request_id_from_fenced(
    request_id: FencedTransitionRequestId,
) -> SessionConsumerRequestId {
    SessionConsumerRequestId::from_bytes(*request_id.as_bytes())
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
    /// handshakes. The stateless listener preserves the original finite
    /// `Semaphore::MAX_PERMITS` configuration domain; 256 remains the default.
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

    /// Set the active authenticated-frame idle deadline. A larger legacy
    /// stateless value remains source-compatible, while revision 3 applies its
    /// five-second active-frame ceiling internally.
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
        let cancellation = Arc::new(ConsumerServerCancellation::new());
        let permits = Arc::new(Semaphore::new(self.max_connections));
        let connection_tasks = Arc::new(tokio::sync::Mutex::new(JoinSet::new()));
        let service = self.service;
        let tls_config = self.tls_config;
        let authorizer = self.authorizer;
        let max_frame_size = self.max_frame_size;
        let idle_timeout = effective_consumer_idle_timeout(self.idle_timeout);
        let operation_timeout = effective_consumer_operation_timeout(self.operation_timeout);
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
            || self.max_connections > Semaphore::MAX_PERMITS
            || self.max_frame_size < MIN_SESSION_CONSUMER_RESPONSE_FRAME_SIZE
            || self.max_frame_size > MAX_NEGOTIATED_FRAME_SIZE
            || self.idle_timeout.is_zero()
            || self.operation_timeout.is_zero()
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
    cancellation: Arc<ConsumerServerCancellation>,
    connection_tasks: Arc<tokio::sync::Mutex<JoinSet<()>>>,
}

#[derive(Debug)]
struct ConsumerServerCancellation {
    cancelled: AtomicBool,
    notified: Notify,
}

impl ConsumerServerCancellation {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            notified: Notify::new(),
        }
    }

    fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            self.notified.notify_waiters();
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.notified.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
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
        self.cancellation.cancel();
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
async fn write_consumer_server_response_supervised<W>(
    writer: &mut W,
    response: ConsumerWireResponse,
    response_frame_size: usize,
    operation_deadline: tokio::time::Instant,
    idle_timeout: Duration,
    lifecycle: &mut ConnectionLifecycle,
    tls_config: &opc_tls::AuthenticatedServerConfig,
    reauthentication: &SessionReauthenticationControl,
    reauthentication_changes: &mut watch::Receiver<u64>,
    material_changes: &mut Option<opc_tls::TlsMaterialStatusReceiver>,
    cancellation: &ConsumerServerCancellation,
    rotation_jitter: Duration,
) -> Result<bool, ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    let initial_hard_deadline = lifecycle
        .hard_deadline()
        .map_err(|_| ProtocolError::InvalidWireValue)?;
    let active_frame_deadline = tokio::time::Instant::now()
        .checked_add(idle_timeout)
        .ok_or(ProtocolError::InvalidWireValue)?;
    let response_write_deadline = operation_deadline
        .min(initial_hard_deadline)
        .min(active_frame_deadline);
    let response_write = write_consumer_response_until(
        writer,
        response,
        response_frame_size,
        response_write_deadline,
    );
    tokio::pin!(response_write);
    loop {
        let hard_deadline = lifecycle
            .hard_deadline()
            .map_err(|_| ProtocolError::InvalidWireValue)?;
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        if hard_deadline <= response_write_deadline && tokio::time::Instant::now() >= hard_deadline
        {
            record_consumer_hard_overrun(lifecycle);
            return Ok(false);
        }
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Ok(false),
            result = &mut response_write => {
                if hard_deadline <= response_write_deadline
                    && tokio::time::Instant::now() >= hard_deadline
                {
                    record_consumer_hard_overrun(lifecycle);
                    return Ok(false);
                }
                Some(result)
            },
            _ = wait_for_shortened_deadline(hard_deadline, response_write_deadline) => {
                record_consumer_hard_overrun(lifecycle);
                return Ok(false);
            }
            _ = reauthentication_changes.changed() => {
                observe_consumer_rotation(
                    lifecycle,
                    tokio::time::Instant::now(),
                    reauthentication.generation(),
                    tls_config.material_status(),
                    rotation_jitter,
                );
                None
            }
            _ = wait_consumer_material_change(material_changes) => {
                observe_consumer_rotation(
                    lifecycle,
                    tokio::time::Instant::now(),
                    reauthentication.generation(),
                    tls_config.material_status(),
                    rotation_jitter,
                );
                None
            }
        };
        if let Some(result) = result {
            result?;
            return Ok(true);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_consumer_call_rejection_supervised<W>(
    writer: &mut W,
    correlation: NonZeroU32,
    rejection: SessionConsumerRejection,
    response_frame_size: usize,
    operation_deadline: tokio::time::Instant,
    idle_timeout: Duration,
    lifecycle: &mut ConnectionLifecycle,
    tls_config: &opc_tls::AuthenticatedServerConfig,
    reauthentication: &SessionReauthenticationControl,
    reauthentication_changes: &mut watch::Receiver<u64>,
    material_changes: &mut Option<opc_tls::TlsMaterialStatusReceiver>,
    cancellation: &ConsumerServerCancellation,
    rotation_jitter: Duration,
) -> Result<bool, ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    write_consumer_server_response_supervised(
        writer,
        ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation,
            response: Box::new(ConsumerSessionResponseWire::Rejected(rejection)),
        }),
        response_frame_size,
        operation_deadline,
        idle_timeout,
        lifecycle,
        tls_config,
        reauthentication,
        reauthentication_changes,
        material_changes,
        cancellation,
        rotation_jitter,
    )
    .await
}

/// Serve the deliberately narrow revision-5 lane after mTLS selected its
/// dedicated ALPN. No V1 DTO is decoded on this path, and a revision-5
/// decoder cannot emit V1 responses or watch frames.
struct ConsumerV2ServerConnectionContext {
    service: Arc<dyn SessionQuorumConsumer>,
    identity: SessionConsumerIdentity,
    scope: SessionConsumerScope,
    max_frame_size: usize,
    idle_timeout: Duration,
    operation_timeout: Duration,
    setup_deadline: tokio::time::Instant,
    tls_config: opc_tls::AuthenticatedServerConfig,
    handshake: opc_tls::TlsServerHandshake,
    lifecycle: ConnectionLifecycle,
    rotation_jitter: Duration,
    generation: u64,
    reauthentication: SessionReauthenticationControl,
    reauthentication_changes: watch::Receiver<u64>,
    material_changes: Option<opc_tls::TlsMaterialStatusReceiver>,
    cancellation: Arc<ConsumerServerCancellation>,
    #[cfg(test)]
    final_admission_test_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    expire_at_final_ack_boundary: bool,
}

enum ConsumerV2DispatchResult<T> {
    Completed(T),
    DeadlineClose,
}

async fn await_consumer_v2_dispatch_until<F>(
    mut execute: Pin<&mut F>,
    deadline: tokio::time::Instant,
) -> ConsumerV2DispatchResult<F::Output>
where
    F: std::future::Future,
{
    if tokio::time::Instant::now() >= deadline {
        return ConsumerV2DispatchResult::DeadlineClose;
    }
    tokio::select! {
        biased;
        response = execute.as_mut() => {
            if tokio::time::Instant::now() >= deadline {
                ConsumerV2DispatchResult::DeadlineClose
            } else {
                ConsumerV2DispatchResult::Completed(response)
            }
        }
        _ = tokio::time::sleep_until(deadline) => ConsumerV2DispatchResult::DeadlineClose,
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_consumer_v2_response_supervised<W>(
    writer: &mut W,
    response: ConsumerV2WireResponse,
    response_frame_size: usize,
    operation_deadline: tokio::time::Instant,
    idle_timeout: Duration,
    lifecycle: &mut ConnectionLifecycle,
    tls_config: &opc_tls::AuthenticatedServerConfig,
    reauthentication: &SessionReauthenticationControl,
    reauthentication_changes: &mut watch::Receiver<u64>,
    material_changes: &mut Option<opc_tls::TlsMaterialStatusReceiver>,
    cancellation: &ConsumerServerCancellation,
    rotation_jitter: Duration,
) -> Result<bool, ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    let initial_hard_deadline = lifecycle
        .hard_deadline()
        .map_err(|_| ProtocolError::InvalidWireValue)?;
    let active_frame_deadline = tokio::time::Instant::now()
        .checked_add(idle_timeout)
        .ok_or(ProtocolError::InvalidWireValue)?;
    let response_write_deadline = operation_deadline
        .min(initial_hard_deadline)
        .min(active_frame_deadline);
    let response_write = write_frame_bounded_until(
        writer,
        &response,
        response_frame_size,
        response_write_deadline,
    );
    tokio::pin!(response_write);
    loop {
        let hard_deadline = lifecycle
            .hard_deadline()
            .map_err(|_| ProtocolError::InvalidWireValue)?;
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        if hard_deadline <= response_write_deadline && tokio::time::Instant::now() >= hard_deadline
        {
            record_consumer_hard_overrun(lifecycle);
            return Ok(false);
        }
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Ok(false),
            result = &mut response_write => {
                if hard_deadline <= response_write_deadline
                    && tokio::time::Instant::now() >= hard_deadline
                {
                    record_consumer_hard_overrun(lifecycle);
                    return Ok(false);
                }
                Some(result)
            },
            _ = wait_for_shortened_deadline(hard_deadline, response_write_deadline) => {
                record_consumer_hard_overrun(lifecycle);
                return Ok(false);
            }
            _ = reauthentication_changes.changed() => {
                observe_consumer_rotation(
                    lifecycle,
                    tokio::time::Instant::now(),
                    reauthentication.generation(),
                    tls_config.material_status(),
                    rotation_jitter,
                );
                None
            }
            _ = wait_consumer_material_change(material_changes) => {
                observe_consumer_rotation(
                    lifecycle,
                    tokio::time::Instant::now(),
                    reauthentication.generation(),
                    tls_config.material_status(),
                    rotation_jitter,
                );
                None
            }
        };
        if let Some(result) = result {
            result?;
            return Ok(true);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_consumer_v2_hello_ack_supervised<W>(
    writer: &mut W,
    scope: SessionConsumerScope,
    response_frame_size: usize,
    max_frame_size: usize,
    setup_deadline: tokio::time::Instant,
    idle_timeout: Duration,
    lifecycle: &mut ConnectionLifecycle,
    tls_config: &opc_tls::AuthenticatedServerConfig,
    admitted_generation: u64,
    admitted_epoch: opc_tls::TlsMaterialEpoch,
    reauthentication: &SessionReauthenticationControl,
    reauthentication_changes: &mut watch::Receiver<u64>,
    material_changes: &mut Option<opc_tls::TlsMaterialStatusReceiver>,
    cancellation: &ConsumerServerCancellation,
) -> Result<bool, ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    let active_frame_deadline = tokio::time::Instant::now()
        .checked_add(idle_timeout)
        .ok_or(ProtocolError::InvalidWireValue)?;
    let hello_ack_response = ConsumerV2WireResponse::HelloAck(ConsumerHelloAck {
        transport_revision: SESSION_QUORUM_CONSUMER_V2_TRANSPORT_REVISION,
        scope,
        request_frame_size: consumer_wire_frame_size(max_frame_size)?,
    });
    let hello_ack = write_frame_bounded_until(
        writer,
        &hello_ack_response,
        response_frame_size,
        setup_deadline
            .min(lifecycle.retire_at())
            .min(active_frame_deadline),
    );
    tokio::pin!(hello_ack);
    loop {
        let lifecycle_deadline = lifecycle.retire_at();
        let ack_deadline = setup_deadline
            .min(lifecycle_deadline)
            .min(active_frame_deadline);
        let now = tokio::time::Instant::now();
        if cancellation.is_cancelled()
            || now >= setup_deadline
            || now >= active_frame_deadline
            || lifecycle.retirement(now).is_some()
        {
            return Err(consumer_setup_timeout(
                "consumer V2 HelloAck deadline elapsed",
            ));
        }
        let acknowledged = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Ok(false),
            _ = tokio::time::sleep_until(ack_deadline) => {
                let _ = lifecycle.retirement(tokio::time::Instant::now());
                return Err(consumer_setup_timeout("consumer V2 HelloAck deadline elapsed"));
            }
            _ = reauthentication_changes.changed() => {
                if !consumer_fresh_admission_is_current(
                    admitted_generation,
                    admitted_epoch,
                    reauthentication.generation(),
                    tls_config.material_status().epoch(),
                ) {
                    return Err(ProtocolError::Authentication);
                }
                continue;
            }
            _ = wait_consumer_material_change(material_changes) => {
                if !consumer_fresh_admission_is_current(
                    admitted_generation,
                    admitted_epoch,
                    reauthentication.generation(),
                    tls_config.material_status().epoch(),
                ) {
                    return Err(ProtocolError::Authentication);
                }
                continue;
            }
            result = &mut hello_ack => result,
        };
        acknowledged?;
        // `changed()` may have observed no update immediately before the
        // writer poll. Re-sample the exact admission evidence after a
        // completed Ack write so a material publication from that same poll
        // cannot enter the V2 call loop on a stale handshake.
        if !consumer_fresh_admission_is_current(
            admitted_generation,
            admitted_epoch,
            reauthentication.generation(),
            tls_config.material_status().epoch(),
        ) {
            return Err(ProtocolError::Authentication);
        }
        let now = tokio::time::Instant::now();
        if cancellation.is_cancelled()
            || now >= setup_deadline
            || now >= active_frame_deadline
            || lifecycle.retirement(now).is_some()
        {
            return Err(consumer_setup_timeout(
                "consumer V2 HelloAck deadline elapsed",
            ));
        }
        return Ok(true);
    }
}

async fn handle_server_connection_v2(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    context: ConsumerV2ServerConnectionContext,
) -> Result<(), ProtocolError> {
    let ConsumerV2ServerConnectionContext {
        service,
        identity,
        scope,
        max_frame_size,
        idle_timeout,
        operation_timeout,
        setup_deadline,
        tls_config,
        handshake,
        mut lifecycle,
        rotation_jitter,
        generation,
        reauthentication,
        mut reauthentication_changes,
        mut material_changes,
        cancellation,
        #[cfg(test)]
        final_admission_test_hook,
        #[cfg(test)]
        expire_at_final_ack_boundary,
    } = context;
    let (mut reader, mut writer) = tokio::io::split(tls);
    let hello = {
        let hello = read_authenticated_consumer_bootstrap_frame_until::<_, ConsumerV2WireRequest>(
            &mut reader,
            max_frame_size,
            setup_deadline.min(lifecycle.retire_at()),
            idle_timeout,
        );
        tokio::pin!(hello);
        loop {
            let deadline = setup_deadline.min(lifecycle.retire_at());
            if cancellation.is_cancelled() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = lifecycle.retirement(tokio::time::Instant::now());
                return Err(consumer_setup_timeout("consumer V2 Hello deadline elapsed"));
            }
            let result = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                _ = tokio::time::sleep_until(deadline) => {
                    let _ = lifecycle.retirement(tokio::time::Instant::now());
                    return Err(consumer_setup_timeout("consumer V2 Hello deadline elapsed"));
                }
                _ = reauthentication_changes.changed() => {
                    if !consumer_fresh_admission_is_current(
                        generation,
                        handshake.epoch(),
                        reauthentication.generation(),
                        tls_config.material_status().epoch(),
                    ) {
                        return Err(ProtocolError::Authentication);
                    }
                    continue;
                }
                _ = wait_consumer_material_change(&mut material_changes) => {
                    if !consumer_fresh_admission_is_current(
                        generation,
                        handshake.epoch(),
                        reauthentication.generation(),
                        tls_config.material_status().epoch(),
                    ) {
                        return Err(ProtocolError::Authentication);
                    }
                    continue;
                }
                result = &mut hello => result,
            };
            break result?
                .ok_or_else(|| consumer_setup_timeout("consumer V2 Hello deadline elapsed"))?;
        }
    };
    let ConsumerV2WireRequest::Hello(hello) = hello else {
        return Err(ProtocolError::UnexpectedResponse);
    };
    if hello.transport_revision != SESSION_QUORUM_CONSUMER_V2_TRANSPORT_REVISION {
        return Err(ProtocolError::UnexpectedResponse);
    }
    let response_frame_size =
        checked_consumer_frame_size(hello.response_frame_size)?.min(max_frame_size);
    if hello.scope != scope {
        let _ = write_consumer_v2_response_supervised(
            &mut writer,
            ConsumerV2WireResponse::HelloRejected(SessionConsumerRejection::ScopeMismatch),
            response_frame_size,
            setup_deadline,
            idle_timeout,
            &mut lifecycle,
            &tls_config,
            &reauthentication,
            &mut reauthentication_changes,
            &mut material_changes,
            &cancellation,
            rotation_jitter,
        )
        .await?;
        return Ok(());
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
    if !write_consumer_v2_hello_ack_supervised(
        &mut writer,
        scope,
        response_frame_size,
        max_frame_size,
        setup_deadline,
        idle_timeout,
        &mut lifecycle,
        &tls_config,
        generation,
        admission.epoch(),
        &reauthentication,
        &mut reauthentication_changes,
        &mut material_changes,
        &cancellation,
    )
    .await?
    {
        return Ok(());
    }

    let mut expected = NonZeroU32::MIN;
    for _ in 0..MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION {
        let call = {
            let idle_deadline = tokio::time::Instant::now()
                .checked_add(idle_timeout)
                .ok_or(ProtocolError::InvalidWireValue)?;
            let read_call = read_authenticated_consumer_frame_until::<_, ConsumerV2WireRequest>(
                &mut reader,
                max_frame_size,
                idle_deadline,
            );
            tokio::pin!(read_call);
            loop {
                let lifecycle_deadline = lifecycle.retire_at();
                let now = tokio::time::Instant::now();
                if cancellation.is_cancelled() {
                    return Ok(());
                }
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
                    _ = cancellation.cancelled() => return Ok(()),
                    _ = reauthentication_changes.changed() => {
                        if !server_connection_current(
                            &mut lifecycle,
                            &tls_config,
                            &reauthentication,
                            rotation_jitter,
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
                            rotation_jitter,
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
        let ConsumerV2WireRequest::Call(ConsumerV2Call {
            correlation,
            attempt_nonce,
            request_commitment,
            request,
        }) = call
        else {
            // A second Hello, or any later control frame, is never an
            // orderly close. In particular, do not let a cross-lane sender
            // turn an undecodable request into a successful no-op.
            return Err(ProtocolError::UnexpectedResponse);
        };
        exact_correlation(expected, correlation)?;
        if v2_request_commitment(&request).map_or(true, |digest| request_commitment != digest) {
            return Err(ProtocolError::UnexpectedResponse);
        }
        if !server_connection_current(
            &mut lifecycle,
            &tls_config,
            &reauthentication,
            rotation_jitter,
        ) {
            return Ok(());
        }
        let request = *request;
        let request_deadline = tokio::time::Instant::now()
            .checked_add(operation_timeout)
            .ok_or(ProtocolError::InvalidWireValue)?;
        let response = if request.scope() != scope {
            Some(SessionConsumerV2Response::Rejected(
                SessionConsumerRejection::ScopeMismatch,
            ))
        } else if request.validate().is_err() {
            Some(SessionConsumerV2Response::Rejected(
                SessionConsumerRejection::MalformedRequest,
            ))
        } else {
            let execute = service.execute_v2(&identity, request.clone());
            tokio::pin!(execute);
            loop {
                let hard_deadline = lifecycle
                    .hard_deadline()
                    .map_err(|_| ProtocolError::InvalidWireValue)?;
                let admitted_deadline = request_deadline.min(hard_deadline);
                if cancellation.is_cancelled() {
                    return Ok(());
                }
                let dispatched =
                    await_consumer_v2_dispatch_until(execute.as_mut(), admitted_deadline);
                tokio::pin!(dispatched);
                let response = tokio::select! {
                    biased;
                    response = &mut dispatched => {
                        match response {
                            ConsumerV2DispatchResult::Completed(response) => Some(response),
                            ConsumerV2DispatchResult::DeadlineClose => {
                                // `execute_v2` crossed the transport ambiguity
                                // boundary even if its future had not received
                                // a first service poll before this deadline.
                                // Closing is never a safe rejection.
                                if hard_deadline <= request_deadline {
                                    record_consumer_hard_overrun(&lifecycle);
                                }
                                return Ok(());
                            }
                        }
                    },
                    _ = cancellation.cancelled() => return Ok(()),
                    _ = reauthentication_changes.changed() => {
                        observe_consumer_rotation(
                            &mut lifecycle,
                            tokio::time::Instant::now(),
                            reauthentication.generation(),
                            tls_config.material_status(),
                            rotation_jitter,
                        );
                        None
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        observe_consumer_rotation(
                            &mut lifecycle,
                            tokio::time::Instant::now(),
                            reauthentication.generation(),
                            tls_config.material_status(),
                            rotation_jitter,
                        );
                        None
                    }
                };
                if let Some(response) = response {
                    break Some(response);
                }
            }
        };
        let Some(response) = response else {
            return Ok(());
        };
        if !v2_response_matches_request(&request, &response) {
            return Err(ProtocolError::UnexpectedResponse);
        }
        if !write_consumer_v2_response_supervised(
            &mut writer,
            ConsumerV2WireResponse::Response(ConsumerV2CallResponse {
                correlation,
                attempt_nonce,
                request_commitment,
                response: Box::new(response),
            }),
            response_frame_size,
            request_deadline,
            idle_timeout,
            &mut lifecycle,
            &tls_config,
            &reauthentication,
            &mut reauthentication_changes,
            &mut material_changes,
            &cancellation,
            rotation_jitter,
        )
        .await?
        {
            return Ok(());
        }
        expected = expected
            .get()
            .checked_add(1)
            .and_then(NonZeroU32::new)
            .ok_or(ProtocolError::InvalidWireValue)?;
    }
    Ok(())
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
    cancellation: Arc<ConsumerServerCancellation>,
    #[cfg(test)] final_admission_test_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)] setup_test_hooks: Option<Arc<ConsumerServerSetupTestHooks>>,
    #[cfg(test)] expire_at_final_ack_boundary: bool,
) -> Result<(), ProtocolError> {
    // Revision 3 reuses a socket for small request/response frames. Disable
    // Nagle on both peers so a warm exchange cannot inherit the platform's
    // delayed-ACK cadence and consume the bounded fair-pool wait budget.
    stream.set_nodelay(true).map_err(ProtocolError::Io)?;
    #[cfg(test)]
    if let Some(hooks) = &setup_test_hooks {
        hooks.accepted.notify_one();
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Ok(()),
            _ = hooks.continue_after_accept.notified() => {}
        }
    }
    let generation = reauthentication.generation();
    let handshake = tls_config
        .begin_handshake()
        .map_err(|_| ProtocolError::Authentication)?;
    let acceptor =
        tokio_rustls::TlsAcceptor::from(consumer_server_tls_config(handshake.rustls_config()));
    // TLS has the finite no-byte setup budget and is interruptible by abort.
    // The authenticated active-frame budget starts only after TLS, at the
    // first byte of Hello/HelloAck below.
    if tokio::time::Instant::now() >= setup_deadline {
        return Err(consumer_setup_timeout("consumer setup deadline elapsed"));
    }
    let tls = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Ok(()),
        result = tokio::time::timeout_at(setup_deadline, acceptor.accept(stream)) => {
            result
                .map_err(|_| consumer_setup_timeout("consumer TLS handshake timed out"))?
                .map_err(classify_tls_io_error)?
        }
    };
    if tokio::time::Instant::now() >= setup_deadline {
        return Err(consumer_setup_timeout("consumer setup deadline elapsed"));
    }
    #[cfg(test)]
    if let Some(hooks) = &setup_test_hooks {
        hooks.tls_complete.notify_one();
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Ok(()),
            _ = hooks.continue_after_tls.notified() => {}
        }
    }
    let established_at = tokio::time::Instant::now();
    let selected_alpn = tls.get_ref().1.alpn_protocol();
    if selected_alpn != Some(SESSION_QUORUM_CONSUMER_ALPN)
        && selected_alpn != Some(SESSION_QUORUM_CONSUMER_V2_ALPN)
    {
        return Err(ProtocolError::UnexpectedResponse);
    }
    let peer = opc_tls::peer_tls_identity_from_server_connection(tls.get_ref().1)
        .map_err(|_| ProtocolError::Authentication)?;
    let identity = authorizer
        .authorize(peer.spiffe_id())
        .map_err(|_| ProtocolError::Authentication)?;
    let rotation_jitter = handshake.consumer_rotation_jitter(peer.spiffe_id());
    let lifecycle = ConnectionLifecycle::new(
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
        Some(handshake.epoch()),
    )
    .map_err(|_| ProtocolError::InvalidWireValue)?;
    let reauthentication_changes = reauthentication.subscribe();
    let material_changes = Some(tls_config.subscribe_material_changes());
    if selected_alpn == Some(SESSION_QUORUM_CONSUMER_V2_ALPN) {
        return handle_server_connection_v2(
            tls,
            ConsumerV2ServerConnectionContext {
                service,
                identity,
                scope: authorizer.scope(),
                max_frame_size,
                idle_timeout,
                operation_timeout,
                setup_deadline,
                tls_config,
                handshake,
                lifecycle,
                rotation_jitter,
                generation,
                reauthentication,
                reauthentication_changes,
                material_changes,
                cancellation,
                #[cfg(test)]
                final_admission_test_hook,
                #[cfg(test)]
                expire_at_final_ack_boundary,
            },
        )
        .await;
    }
    let mut lifecycle = lifecycle;
    let mut reauthentication_changes = reauthentication_changes;
    let mut material_changes = material_changes;
    let (mut reader, mut writer) = tokio::io::split(tls);
    let hello = {
        let hello = read_authenticated_consumer_bootstrap_frame_until::<_, ConsumerWireRequest>(
            &mut reader,
            max_frame_size,
            setup_deadline.min(lifecycle.retire_at()),
            idle_timeout,
        );
        tokio::pin!(hello);
        loop {
            let deadline = setup_deadline.min(lifecycle.retire_at());
            if cancellation.is_cancelled() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = lifecycle.retirement(tokio::time::Instant::now());
                return Err(consumer_setup_timeout("consumer Hello deadline elapsed"));
            }
            let result = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                _ = tokio::time::sleep_until(deadline) => {
                    let _ = lifecycle.retirement(tokio::time::Instant::now());
                    return Err(consumer_setup_timeout("consumer Hello deadline elapsed"));
                }
                _ = reauthentication_changes.changed() => {
                    if !consumer_fresh_admission_is_current(
                        generation,
                        handshake.epoch(),
                        reauthentication.generation(),
                        tls_config.material_status().epoch(),
                    ) {
                        return Err(ProtocolError::Authentication);
                    }
                    continue;
                }
                _ = wait_consumer_material_change(&mut material_changes) => {
                    if !consumer_fresh_admission_is_current(
                        generation,
                        handshake.epoch(),
                        reauthentication.generation(),
                        tls_config.material_status().epoch(),
                    ) {
                        return Err(ProtocolError::Authentication);
                    }
                    continue;
                }
                result = &mut hello => result,
            };
            break result?
                .ok_or_else(|| consumer_setup_timeout("consumer Hello deadline elapsed"))?;
        }
    };
    let ConsumerWireRequest::Hello(hello) = hello else {
        return Err(ProtocolError::UnexpectedResponse);
    };
    if hello.transport_revision != SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION {
        return Err(ProtocolError::UnexpectedResponse);
    }
    let response_frame_size =
        checked_consumer_frame_size(hello.response_frame_size)?.min(max_frame_size);
    if hello.scope != authorizer.scope() {
        let rejection_deadline = setup_deadline.min(lifecycle.retire_at()).min(
            tokio::time::Instant::now()
                .checked_add(idle_timeout)
                .ok_or(ProtocolError::InvalidWireValue)?,
        );
        let rejection = write_consumer_response_until(
            &mut writer,
            ConsumerWireResponse::HelloRejected(SessionConsumerRejection::ScopeMismatch),
            response_frame_size,
            rejection_deadline,
        );
        tokio::pin!(rejection);
        loop {
            let deadline = rejection_deadline.min(lifecycle.retire_at());
            if cancellation.is_cancelled() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = lifecycle.retirement(tokio::time::Instant::now());
                return Err(consumer_setup_timeout(
                    "consumer Hello rejection deadline elapsed",
                ));
            }
            let completed = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                _ = tokio::time::sleep_until(deadline) => {
                    let _ = lifecycle.retirement(tokio::time::Instant::now());
                    return Err(consumer_setup_timeout(
                        "consumer Hello rejection deadline elapsed",
                    ));
                }
                _ = reauthentication_changes.changed() => {
                    if !consumer_fresh_admission_is_current(
                        generation,
                        handshake.epoch(),
                        reauthentication.generation(),
                        tls_config.material_status().epoch(),
                    ) {
                        return Err(ProtocolError::Authentication);
                    }
                    continue;
                }
                _ = wait_consumer_material_change(&mut material_changes) => {
                    if !consumer_fresh_admission_is_current(
                        generation,
                        handshake.epoch(),
                        reauthentication.generation(),
                        tls_config.material_status().epoch(),
                    ) {
                        return Err(ProtocolError::Authentication);
                    }
                    continue;
                }
                result = &mut rejection => result,
            };
            completed?;
            break;
        }
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
        let active_frame_deadline = tokio::time::Instant::now()
            .checked_add(idle_timeout)
            .ok_or(ProtocolError::InvalidWireValue)?;
        let hello_ack = write_consumer_response_until(
            &mut writer,
            ConsumerWireResponse::HelloAck(ConsumerHelloAck {
                transport_revision: SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
                scope: authorizer.scope(),
                request_frame_size: consumer_wire_frame_size(max_frame_size)?,
            }),
            response_frame_size,
            setup_deadline
                .min(lifecycle.retire_at())
                .min(active_frame_deadline),
        );
        tokio::pin!(hello_ack);
        loop {
            let lifecycle_deadline = lifecycle.retire_at();
            let ack_deadline = setup_deadline
                .min(lifecycle_deadline)
                .min(active_frame_deadline);
            let now = tokio::time::Instant::now();
            if cancellation.is_cancelled()
                || now >= setup_deadline
                || now >= active_frame_deadline
                || lifecycle.retirement(now).is_some()
            {
                return Err(consumer_setup_timeout("consumer HelloAck deadline elapsed"));
            }
            let acknowledged = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                _ = tokio::time::sleep_until(ack_deadline) => {
                    let _ = lifecycle.retirement(tokio::time::Instant::now());
                    return Err(consumer_setup_timeout("consumer HelloAck deadline elapsed"));
                }
                _ = reauthentication_changes.changed() => {
                    if !server_connection_current(
                        &mut lifecycle,
                        &tls_config,
                        &reauthentication,
                        rotation_jitter,
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
                        rotation_jitter,
                    ) {
                        return Err(ProtocolError::Authentication);
                    }
                    continue;
                }
                result = &mut hello_ack => result,
            };
            acknowledged?;
            let now = tokio::time::Instant::now();
            if cancellation.is_cancelled()
                || now >= setup_deadline
                || now >= active_frame_deadline
                || lifecycle.retirement(now).is_some()
            {
                return Err(consumer_setup_timeout("consumer HelloAck deadline elapsed"));
            }
            break;
        }
    }
    let mut expected_correlation = NonZeroU32::MIN;
    for _ in 0..MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION {
        if cancellation.is_cancelled() {
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
                if cancellation.is_cancelled() {
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
                    _ = cancellation.cancelled() => return Ok(()),
                    _ = reauthentication_changes.changed() => {
                        if !server_connection_current(
                            &mut lifecycle,
                            &tls_config,
                            &reauthentication,
                            rotation_jitter,
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
                            rotation_jitter,
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
            rotation_jitter,
        ) {
            return Ok(());
        }
        let request_deadline = tokio::time::Instant::now()
            .checked_add(operation_timeout)
            .ok_or(ProtocolError::InvalidWireValue)?;
        if request.scope() != authorizer.scope() {
            let _ = write_consumer_call_rejection_supervised(
                &mut writer,
                correlation,
                SessionConsumerRejection::ScopeMismatch,
                response_frame_size,
                request_deadline,
                idle_timeout,
                &mut lifecycle,
                &tls_config,
                &reauthentication,
                &mut reauthentication_changes,
                &mut material_changes,
                &cancellation,
                rotation_jitter,
            )
            .await?;
            return Ok(());
        }
        if !consumer_request_has_exact_fenced_transition_id(&request) {
            let _ = write_consumer_call_rejection_supervised(
                &mut writer,
                correlation,
                SessionConsumerRejection::MalformedRequest,
                response_frame_size,
                request_deadline,
                idle_timeout,
                &mut lifecycle,
                &tls_config,
                &reauthentication,
                &mut reauthentication_changes,
                &mut material_changes,
                &cancellation,
                rotation_jitter,
            )
            .await?;
            return Ok(());
        }
        if let Err(rejection) = request.validate() {
            let _ = write_consumer_call_rejection_supervised(
                &mut writer,
                correlation,
                rejection,
                response_frame_size,
                request_deadline,
                idle_timeout,
                &mut lifecycle,
                &tls_config,
                &reauthentication,
                &mut reauthentication_changes,
                &mut material_changes,
                &cancellation,
                rotation_jitter,
            )
            .await?;
            return Ok(());
        }
        let lease_wire_context = ConsumerLeaseWireContext::from_operation(request.operation());
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
        let request_id = request.request_id();
        let execute = service.execute(&identity, *request);
        tokio::pin!(execute);
        let mut response = loop {
            let hard_deadline = lifecycle
                .hard_deadline()
                .map_err(|_| ProtocolError::InvalidWireValue)?;
            let admitted_deadline = request_deadline.min(hard_deadline);
            let now = tokio::time::Instant::now();
            if cancellation.is_cancelled() {
                return Ok(());
            }
            if now >= admitted_deadline {
                if hard_deadline <= request_deadline {
                    record_consumer_hard_overrun(&lifecycle);
                    return Ok(());
                }
                break consumer_timeout_response(operation, request_id);
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
                        Some(consumer_timeout_response(operation, request_id))
                    } else {
                        Some(response)
                    }
                },
                _ = tokio::time::sleep_until(admitted_deadline) => {
                    if hard_deadline <= request_deadline {
                        record_consumer_hard_overrun(&lifecycle);
                        return Ok(());
                    }
                    Some(consumer_timeout_response(operation, request_id))
                }
                _ = cancellation.cancelled() => return Ok(()),
                _ = reauthentication_changes.changed() => {
                    observe_consumer_rotation(
                        &mut lifecycle,
                        tokio::time::Instant::now(),
                        reauthentication.generation(),
                        tls_config.material_status(),
                        rotation_jitter,
                    );
                    None
                }
                _ = wait_consumer_material_change(&mut material_changes) => {
                    observe_consumer_rotation(
                        &mut lifecycle,
                        tokio::time::Instant::now(),
                        reauthentication.generation(),
                        tls_config.material_status(),
                        rotation_jitter,
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
            tls_config.material_status(),
            rotation_jitter,
        );
        let hard_deadline = lifecycle
            .hard_deadline()
            .map_err(|_| ProtocolError::InvalidWireValue)?;
        if tokio::time::Instant::now() >= hard_deadline {
            record_consumer_hard_overrun(&lifecycle);
            return Ok(());
        }
        if cancellation.is_cancelled() {
            return Ok(());
        }
        if !response_matches_operation(operation, &response) {
            return Err(ProtocolError::UnexpectedResponse);
        }
        clamp_consumer_capabilities(&mut response, max_frame_size, response_frame_size);
        if let (Some(request), SessionConsumerResponse::ScanRestoreRecords(Ok(page))) =
            (&restore_request, &response)
        {
            // Keep #684's page validation and response-fit replacement before
            // writing a frame; revision-3 only adds the small correlation
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
                    if cancellation.is_cancelled() {
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
                        _ = cancellation.cancelled() => return Ok(()),
                        _ = reauthentication_changes.changed() => {
                            observe_consumer_rotation(
                                &mut lifecycle,
                                tokio::time::Instant::now(),
                                reauthentication.generation(),
                        tls_config.material_status(),
                        rotation_jitter,
                    );
                            None
                        }
                        _ = wait_consumer_material_change(&mut material_changes) => {
                            observe_consumer_rotation(
                                &mut lifecycle,
                                tokio::time::Instant::now(),
                                reauthentication.generation(),
                        tls_config.material_status(),
                        rotation_jitter,
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
                tls_config.material_status(),
                rotation_jitter,
            );
            let hard_deadline = lifecycle
                .hard_deadline()
                .map_err(|_| ProtocolError::InvalidWireValue)?;
            if cancellation.is_cancelled() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= hard_deadline {
                record_consumer_hard_overrun(&lifecycle);
                return Ok(());
            }
        }
        let watch_opened = matches!(response, SessionConsumerResponse::WatchOpened);
        let retire_after_response = response_retires_connection_authority(&response);
        let wire_response = consumer_wire_response_from_public(lease_wire_context, response)?;
        if !write_consumer_server_response_supervised(
            &mut writer,
            ConsumerWireResponse::Response(ConsumerCallResponse {
                correlation,
                response: Box::new(wire_response),
            }),
            response_frame_size,
            request_deadline,
            idle_timeout,
            &mut lifecycle,
            &tls_config,
            &reauthentication,
            &mut reauthentication_changes,
            &mut material_changes,
            &cancellation,
            rotation_jitter,
        )
        .await?
        {
            return Ok(());
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
            if cancellation.is_cancelled()
                || !server_connection_current(
                    &mut lifecycle,
                    &tls_config,
                    &reauthentication,
                    rotation_jitter,
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
                _ = cancellation.cancelled() => return Ok(()),
                _ = reauthentication_changes.changed() => {
                    if !server_connection_current(
                        &mut lifecycle,
                        &tls_config,
                        &reauthentication,
                            rotation_jitter,
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
                            rotation_jitter,
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
            if cancellation.is_cancelled()
                || !server_connection_current(
                    &mut lifecycle,
                    &tls_config,
                    &reauthentication,
                    rotation_jitter,
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
                if cancellation.is_cancelled()
                    || !server_connection_current(
                        &mut lifecycle,
                        &tls_config,
                        &reauthentication,
                        rotation_jitter,
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
                    _ = cancellation.cancelled() => return Ok(()),
                    _ = reader.read(&mut peer_probe) => return Ok(()),
                    _ = reauthentication_changes.changed() => {
                        observe_consumer_rotation(
                            &mut lifecycle,
                            tokio::time::Instant::now(),
                            reauthentication.generation(),
                        tls_config.material_status(),
                        rotation_jitter,
                    );
                        None
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        observe_consumer_rotation(
                            &mut lifecycle,
                            tokio::time::Instant::now(),
                            reauthentication.generation(),
                        tls_config.material_status(),
                        rotation_jitter,
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
                        rotation_jitter,
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

fn consumer_timeout_response(
    operation: ConsumerOperationKind,
    request_id: SessionConsumerRequestId,
) -> SessionConsumerResponse {
    let mutation_may_have_been_accepted = match operation {
        ConsumerOperationKind::CompareAndSet
        | ConsumerOperationKind::DeleteFenced
        | ConsumerOperationKind::RefreshTtl
        | ConsumerOperationKind::FencedTransition
        | ConsumerOperationKind::UnknownEffectful => {
            Some(SessionConsumerOutcomeUnknown::Mutation { request_id })
        }
        ConsumerOperationKind::AcquireLease
        | ConsumerOperationKind::RenewLease
        | ConsumerOperationKind::ReleaseLease => Some(SessionConsumerOutcomeUnknown::Lease),
        ConsumerOperationKind::Batch {
            contains_mutation: true,
        } => Some(SessionConsumerOutcomeUnknown::Mutation { request_id }),
        ConsumerOperationKind::Capabilities
        | ConsumerOperationKind::FencedTransitionCapability
        | ConsumerOperationKind::ObserveFencedTransition
        | ConsumerOperationKind::FencedTransitionStatus
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

    let Ok(wire_response) =
        consumer_wire_response_from_public(ConsumerLeaseWireContext::Other, response.clone())
    else {
        return false;
    };
    let mut size = BoundedResponseSize {
        encoded: 0,
        maximum: max_frame_size,
    };
    serde_json::to_writer(
        &mut size,
        &BorrowedConsumerWireResponse::Response(BorrowedConsumerCallResponse {
            correlation,
            response: &wire_response,
        }),
    )
    .is_ok()
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

async fn wait_for_v2_forced_shutdown(receiver: &mut watch::Receiver<bool>) {
    loop {
        if *receiver.borrow_and_update() {
            return;
        }
        if receiver.changed().await.is_err() {
            return;
        }
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
    use std::collections::VecDeque;
    use std::io;
    use std::num::{NonZeroU32, NonZeroUsize};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use super::{
        authenticated_consumer_binding, await_consumer_v2_dispatch_until,
        classify_call_write_error, complete_before_deadline, consumer_connection_current,
        consumer_execute_into_fenced_transition, consumer_fresh_admission_is_current,
        consumer_payload_fragments_exceed_frame, consumer_request_has_exact_fenced_transition_id,
        consumer_response_fits, consumer_watch_error_is_legal, consumer_wire_response_from_public,
        decode_consumer_frame_payload, ensure_pre_request_budget_remaining, exact_correlation,
        fenced_transition_response, lease_error_matches_operation, lease_response,
        mutation_response, persistent_execute_error, poll_persistent_consumer_setup_io,
        publish_monotonic_shutdown_phase, queued_consumer_watch_stream,
        read_authenticated_consumer_frame_until, read_authenticated_consumer_frame_within,
        response_is_outcome_unknown, response_matches_operation, response_matches_request,
        response_retires_connection_authority, run_persistent_v2_lane, server_connection_current,
        store_error_matches_operation, v2_persistent_error, valid_consumer_operation_timeout,
        wait_for_forced_shutdown, write_consumer_call_rejection_supervised, BorrowedConsumerCall,
        BorrowedConsumerCallResponse, BorrowedConsumerWireRequest, BorrowedConsumerWireResponse,
        BoxStream, ConsumerCall, ConsumerCallResponse, ConsumerConnection, ConsumerHello,
        ConsumerHelloAck, ConsumerLeaseWireContext, ConsumerOperationKind,
        ConsumerServerCancellation, ConsumerServerSetupTestHooks, ConsumerSessionResponseWire,
        ConsumerSetupPhase, ConsumerSetupPhaseAttempt, ConsumerV2Call, ConsumerV2CallResponse,
        ConsumerV2DispatchResult, ConsumerV2WireRequest, ConsumerV2WireResponse,
        ConsumerWatchTerminal, ConsumerWatchTerminalSlot, ConsumerWireRequest,
        ConsumerWireResponse, PersistentCheckedOutConnection, PersistentConsumerCounters,
        PersistentConsumerIoBarrier, PersistentConsumerShutdownReader,
        PersistentConsumerShutdownWriter, PersistentSessionConsumerClient,
        PersistentSessionConsumerConfig, PersistentSessionConsumerConfigError,
        PersistentSessionConsumerExecuteError, PersistentSessionConsumerV2ExecuteError,
        PersistentSessionConsumerV2Pool, PersistentSetupAttempt, PersistentShutdownPhase,
        PersistentV2Activity, PersistentV2ActivityKind, PersistentV2Connection,
        PersistentV2LaneActor, PersistentV2LaneCall, PersistentV2LaneLifetime,
        PersistentV2LaneState, PersistentV2PoisonAccountingHook, PersistentV2PoolEntry,
        PersistentV2PositiveReadReservationHook, PersistentV2PrewarmFinalPublicationHook,
        PersistentWatchRecovery, QueuedConsumerWatchItem, SessionConsumerAuthorizationError,
        SessionConsumerAuthorizer, SessionConsumerCallError, SessionConsumerChange,
        SessionConsumerClientError, SessionConsumerFencedTransitionBackend,
        SessionConsumerFencedTransitionMutationError, SessionConsumerIdentity,
        SessionConsumerLeaseMutationError, SessionConsumerMutationError, SessionConsumerRejection,
        SessionQuorumConsumer, SessionQuorumConsumerServer, StatelessSessionConsumerClient,
        DEFAULT_CONSUMER_IDLE_TIMEOUT, DEFAULT_CONSUMER_MAX_CONNECTIONS,
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
        MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION,
        MAX_STATELESS_SESSION_CONSUMER_REQUEST_CONNECTIONS,
        MAX_STATELESS_SESSION_CONSUMER_WATCH_CONNECTIONS,
    };
    use bytes::Bytes;
    use futures_util::StreamExt;
    use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
    use opc_session_store::{
        checked_session_deadline, BackendCapabilities, CompareAndSet, CompareAndSetResult,
        EncryptedSessionPayload, FakeSessionBackend, FenceToken, FencedTransitionExecuteError,
        FencedTransitionLease, FencedTransitionMutation, FencedTransitionObservation,
        FencedTransitionOutcome, FencedTransitionRequest, FencedTransitionRequestId,
        FencedTransitionStatus, FencedTransitionV2CallerNonce, FencedTransitionV2Capability,
        FencedTransitionV2HistoryEpoch, FencedTransitionV2RequestId, Generation, LeaseGuard,
        OwnerId, PreparedFencedTransition, RestoreScanCursorProfile, RestoreScanPage,
        RestoreScanRequest, SessionBackend, SessionConsensusClusterId,
        SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
        SessionConsensusIdentity, SessionConsumerBatchResult, SessionConsumerFencedTransitionError,
        SessionConsumerFencedTransitionStatus, SessionConsumerLeaseError, SessionConsumerOperation,
        SessionConsumerOutcomeUnknown, SessionConsumerRequest, SessionConsumerRequestId,
        SessionConsumerResponse, SessionConsumerScope, SessionConsumerStoreError,
        SessionConsumerV2FencedTransitionError, SessionConsumerV2FencedTransitionStatus,
        SessionConsumerV2Operation, SessionConsumerV2Request, SessionConsumerV2Response,
        SessionKey, SessionKeyType, SessionLeaseManager, SessionOp, StateClass, StateType,
        StoreError, StoredSessionRecord, MAX_SESSION_TTL,
    };
    use opc_types::{NetworkFunctionKind, SpiffeId, TenantId, Timestamp};
    use serde::{Deserialize, Serialize};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot, watch, Notify, Semaphore};

    use crate::consensus::RemoteAddrResolver;
    use crate::error::ProtocolError;
    use crate::lifecycle::{
        ConnectionLifecycle, ConnectionLifecyclePolicy, RetirementReason,
        SessionReauthenticationControl,
    };
    use crate::protocol::FRAME_READ_CHUNK_BYTES;
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

    struct V2CountingRejectingTestConsumer {
        v2_calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl SessionQuorumConsumer for V2CountingRejectingTestConsumer {
        async fn execute(
            &self,
            _identity: &SessionConsumerIdentity,
            _request: SessionConsumerRequest,
        ) -> SessionConsumerResponse {
            SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable)
        }

        async fn execute_v2(
            &self,
            _identity: &SessionConsumerIdentity,
            _request: SessionConsumerV2Request,
        ) -> SessionConsumerV2Response {
            self.v2_calls.fetch_add(1, Ordering::SeqCst);
            SessionConsumerV2Response::Rejected(SessionConsumerRejection::Unavailable)
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

    struct V2BlockingTestConsumer {
        entered: Arc<Notify>,
    }

    #[async_trait::async_trait]
    impl SessionQuorumConsumer for V2BlockingTestConsumer {
        async fn execute(
            &self,
            _identity: &SessionConsumerIdentity,
            _request: SessionConsumerRequest,
        ) -> SessionConsumerResponse {
            SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable)
        }

        async fn execute_v2(
            &self,
            _identity: &SessionConsumerIdentity,
            _request: SessionConsumerV2Request,
        ) -> SessionConsumerV2Response {
            self.entered.notify_one();
            std::future::pending().await
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

    struct V2EnteredRejectingTestConsumer {
        entered: Arc<Notify>,
        release: Arc<Semaphore>,
    }

    #[async_trait::async_trait]
    impl SessionQuorumConsumer for V2EnteredRejectingTestConsumer {
        async fn execute(
            &self,
            _identity: &SessionConsumerIdentity,
            _request: SessionConsumerRequest,
        ) -> SessionConsumerResponse {
            SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable)
        }

        async fn execute_v2(
            &self,
            _identity: &SessionConsumerIdentity,
            _request: SessionConsumerV2Request,
        ) -> SessionConsumerV2Response {
            self.entered.notify_one();
            let _permit = Arc::clone(&self.release)
                .acquire_owned()
                .await
                .expect("test release semaphore remains open");
            SessionConsumerV2Response::Rejected(SessionConsumerRejection::Unavailable)
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

    struct V2AdmissionBlockingTestConsumer {
        entered: Arc<AtomicUsize>,
        changed: Arc<Notify>,
        release: Arc<Semaphore>,
    }

    #[async_trait::async_trait]
    impl SessionQuorumConsumer for V2AdmissionBlockingTestConsumer {
        async fn execute(
            &self,
            _identity: &SessionConsumerIdentity,
            _request: SessionConsumerRequest,
        ) -> SessionConsumerResponse {
            SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable)
        }

        async fn execute_v2(
            &self,
            _identity: &SessionConsumerIdentity,
            _request: SessionConsumerV2Request,
        ) -> SessionConsumerV2Response {
            self.entered.fetch_add(1, Ordering::SeqCst);
            self.changed.notify_waiters();
            let _permit = Arc::clone(&self.release)
                .acquire_owned()
                .await
                .expect("test release semaphore remains open");
            SessionConsumerV2Response::Rejected(SessionConsumerRejection::Unavailable)
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

    struct V2ConflictTestConsumer {
        v2_calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl SessionQuorumConsumer for V2ConflictTestConsumer {
        async fn execute(
            &self,
            _identity: &SessionConsumerIdentity,
            _request: SessionConsumerRequest,
        ) -> SessionConsumerResponse {
            SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable)
        }

        async fn execute_v2(
            &self,
            _identity: &SessionConsumerIdentity,
            request: SessionConsumerV2Request,
        ) -> SessionConsumerV2Response {
            self.v2_calls.fetch_add(1, Ordering::SeqCst);
            match request.operation() {
                SessionConsumerV2Operation::FencedTransitionV2 { request }
                    if matches!(
                        request.validate(),
                        Err(StoreError::FencedTransitionRequestConflict)
                    ) =>
                {
                    SessionConsumerV2Response::FencedTransitionV2(Err(
                        SessionConsumerV2FencedTransitionError::RequestConflict,
                    ))
                }
                SessionConsumerV2Operation::FencedTransitionV2Status { request }
                    if matches!(
                        request.validate(),
                        Err(StoreError::FencedTransitionRequestConflict)
                    ) =>
                {
                    SessionConsumerV2Response::FencedTransitionV2Status(Ok(
                        SessionConsumerV2FencedTransitionStatus::RequestConflict,
                    ))
                }
                _ => {
                    SessionConsumerV2Response::Rejected(SessionConsumerRejection::MalformedRequest)
                }
            }
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

    fn v2_serialized_body_conflict(status: bool) -> SessionConsumerV2Request {
        let key = SessionKey {
            tenant: TenantId::new("v2-wire-body-conflict").expect("test tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"v2-wire-body-conflict")
                .try_into()
                .expect("bounded stable ID"),
        };
        let original = opc_session_store::FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(1).expect("nonzero history epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0x75; 16]),
            FencedTransitionLease::acquire(
                key,
                OwnerId::new("v2-wire-body-conflict-owner").expect("test owner"),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .expect("bounded acquire"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("original V2 transition");
        let altered = opc_session_store::FencedTransitionV2Request::new(
            original.request_id().epoch(),
            original.request_id().nonce(),
            original.lease().clone(),
            FencedTransitionMutation::delete(Generation::new(2)),
        )
        .expect("altered V2 transition");
        let operation = |request| {
            if status {
                SessionConsumerV2Operation::FencedTransitionV2Status {
                    request: Box::new(request),
                }
            } else {
                SessionConsumerV2Operation::FencedTransitionV2 {
                    request: Box::new(request),
                }
            }
        };
        let original = SessionConsumerV2Request::new(scope(), operation(original));
        let altered = SessionConsumerV2Request::new(scope(), operation(altered));
        let original_id = serde_json::to_value(original.request_id()).expect("full ID encodes");
        let mut encoded = serde_json::to_value(altered).expect("altered envelope encodes");
        let serde_json::Value::Object(fields) = &mut encoded else {
            panic!("V2 envelope is an object");
        };
        fields.insert("request_id".into(), original_id.clone());
        let body = fields
            .get_mut("operation")
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|operation| operation.get_mut("request"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("V2 body is an object");
        body.insert("request_id".into(), original_id);
        serde_json::from_value(encoded).expect("structural conflict decodes")
    }

    fn v2_effectful_request(nonce: u8) -> SessionConsumerV2Request {
        let key = SessionKey {
            tenant: TenantId::new("v2-effect-boundary").expect("test tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"v2-effect-boundary")
                .try_into()
                .expect("bounded stable ID"),
        };
        let transition = opc_session_store::FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(1).expect("nonzero history epoch"),
            FencedTransitionV2CallerNonce::from_bytes([nonce; 16]),
            FencedTransitionLease::acquire(
                key,
                OwnerId::new("v2-effect-boundary-owner").expect("test owner"),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .expect("bounded acquire"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("bounded V2 transition");
        SessionConsumerV2Request::new(
            scope(),
            SessionConsumerV2Operation::FencedTransitionV2 {
                request: Box::new(transition),
            },
        )
    }

    fn v2_effectful_batch_request(nonces: &[u8]) -> SessionConsumerV2Request {
        let requests = nonces
            .iter()
            .map(|nonce| {
                let singleton = v2_effectful_request(*nonce);
                let SessionConsumerV2Operation::FencedTransitionV2 { request } =
                    singleton.operation()
                else {
                    panic!("test singleton remains an effectful V2 transition");
                };
                (**request).clone()
            })
            .collect();
        SessionConsumerV2Request::new(
            scope(),
            SessionConsumerV2Operation::FencedTransitionV2Batch { requests },
        )
    }

    fn v2_batch_request_ids(
        request: &SessionConsumerV2Request,
    ) -> Vec<FencedTransitionV2RequestId> {
        let SessionConsumerV2Operation::FencedTransitionV2Batch { requests } = request.operation()
        else {
            panic!("test request is an effectful V2 batch");
        };
        requests
            .iter()
            .map(|request| request.request_id())
            .collect()
    }

    fn v2_batch_response_with_ids(
        request_ids: Vec<FencedTransitionV2RequestId>,
    ) -> SessionConsumerV2Response {
        SessionConsumerV2Response::FencedTransitionV2Batch(Ok(request_ids
            .into_iter()
            .map(|request_id| {
                opc_session_store::consumer::SessionConsumerV2FencedTransitionBatchResult::new(
                    request_id,
                    Err(SessionConsumerV2FencedTransitionError::RequestConflict),
                )
            })
            .collect()))
    }

    #[test]
    fn persistent_v2_effect_boundary_keeps_capability_reads_retryable() {
        let read = SessionConsumerV2Request::new(
            scope(),
            SessionConsumerV2Operation::FencedTransitionV2Capability,
        );
        assert!(matches!(
            v2_persistent_error(&read, true, SessionConsumerClientError::Unavailable),
            PersistentSessionConsumerV2ExecuteError::ReadUnavailable {
                cause: SessionConsumerClientError::Unavailable,
            }
        ));

        let mutation = v2_effectful_request(0x51);
        let expected = mutation.request_id().expect("mutation has full V2 ID");
        let error = v2_persistent_error(&mutation, true, SessionConsumerClientError::Unavailable);
        assert!(matches!(
            &error,
            PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id }
                if *request_id == expected
        ));
        assert_eq!(error.exact_retry_id(), Some(expected));
    }

    #[tokio::test]
    async fn stateless_v2_batch_write_boundary_preserves_every_ordered_recovery_id() {
        let batch = v2_effectful_batch_request(&[0x52, 0x53, 0x54]);
        let expected = v2_batch_request_ids(&batch);
        let outbound = ConsumerV2WireRequest::Call(ConsumerV2Call {
            correlation: NonZeroU32::MIN,
            attempt_nonce: [0; 16],
            request_commitment: super::v2_request_commitment(&batch).expect("test commitment"),
            request: Box::new(batch.clone()),
        });

        let mut prewrite = PhaseFailWriter {
            accepted: 0,
            fail_after: None,
            fail_flush: false,
        };
        let progress = super::FrameWriteProgress::new();
        super::write_frame_bounded_until_classified_with_progress(
            &mut prewrite,
            &outbound,
            0,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &progress,
        )
        .await
        .expect_err("an over-cap batch must fail before the frame prefix");
        assert_eq!(prewrite.accepted, 0);
        assert!(!progress.accepted_any());
        assert!(matches!(
            v2_persistent_error(
                &batch,
                progress.accepted_any(),
                SessionConsumerClientError::Unavailable,
            ),
            PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Unavailable
            }
        ));

        for (phase, fail_after, fail_flush) in [
            ("partial prefix", Some(2), false),
            ("partial payload", Some(12), false),
            ("complete frame/flush", None, true),
        ] {
            let mut writer = FailOnceCountingWriter {
                accepted: 0,
                fail_after,
                fail_flush,
                failed: false,
                write_polls_after_failure: 0,
                flush_polls_after_failure: 0,
            };
            let progress = super::FrameWriteProgress::new();
            super::write_frame_bounded_until_classified_with_progress(
                &mut writer,
                &outbound,
                MAX_NEGOTIATED_FRAME_SIZE,
                tokio::time::Instant::now() + Duration::from_secs(1),
                &progress,
            )
            .await
            .expect_err("controlled batch write phase must fail");
            assert!(
                progress.accepted_any(),
                "{phase} crossed the write boundary"
            );
            let error = v2_persistent_error(
                &batch,
                progress.accepted_any(),
                SessionConsumerClientError::Unavailable,
            );
            assert!(
                matches!(
                    &error,
                    PersistentSessionConsumerV2ExecuteError::OutcomeUnknownBatch { request_ids }
                        if request_ids == &expected
                ),
                "{phase} preserves every full V2 identity"
            );
            assert_eq!(
                error.exact_retry_id(),
                None,
                "a batch has no singleton retry ID"
            );
            assert_eq!(error.exact_retry_ids(), Some(expected.as_slice()));
            assert_eq!(
                writer.write_polls_after_failure, 0,
                "{phase} failure cannot retry or send a fallback request"
            );
            assert_eq!(
                writer.flush_polls_after_failure, 0,
                "{phase} failure cannot flush a fallback request"
            );
        }
    }

    #[tokio::test]
    async fn stateless_v2_singleton_write_boundary_preserves_the_exact_recovery_id() {
        let request = v2_effectful_request(0x58);
        let expected = request.request_id().expect("singleton has its full V2 ID");
        let outbound = ConsumerV2WireRequest::Call(ConsumerV2Call {
            correlation: NonZeroU32::MIN,
            attempt_nonce: [0; 16],
            request_commitment: super::v2_request_commitment(&request).expect("test commitment"),
            request: Box::new(request.clone()),
        });

        let mut zero_byte = PhaseFailWriter {
            accepted: 0,
            fail_after: None,
            fail_flush: false,
        };
        let progress = super::FrameWriteProgress::new();
        super::write_frame_bounded_until_classified_with_progress(
            &mut zero_byte,
            &outbound,
            1,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &progress,
        )
        .await
        .expect_err("an over-cap singleton Call fails before its frame prefix");
        assert_eq!(zero_byte.accepted, 0);
        assert!(matches!(
            v2_persistent_error(
                &request,
                progress.accepted_any(),
                SessionConsumerClientError::Unavailable,
            ),
            PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Unavailable
            }
        ));

        for (phase, fail_after, fail_flush) in [
            ("partial prefix", Some(2), false),
            ("partial payload", Some(12), false),
            ("complete frame/flush", None, true),
        ] {
            let mut writer = FailOnceCountingWriter {
                accepted: 0,
                fail_after,
                fail_flush,
                failed: false,
                write_polls_after_failure: 0,
                flush_polls_after_failure: 0,
            };
            let progress = super::FrameWriteProgress::new();
            super::write_frame_bounded_until_classified_with_progress(
                &mut writer,
                &outbound,
                MAX_NEGOTIATED_FRAME_SIZE,
                tokio::time::Instant::now() + Duration::from_secs(1),
                &progress,
            )
            .await
            .expect_err("controlled singleton write phase must fail");
            assert!(progress.accepted_any(), "{phase} crossed the Call boundary");
            assert!(matches!(
                v2_persistent_error(
                    &request,
                    progress.accepted_any(),
                    SessionConsumerClientError::Unavailable,
                ),
                PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id }
                    if request_id == expected
            ));
            assert_eq!(writer.write_polls_after_failure, 0, "{phase} cannot retry");
            assert_eq!(
                writer.flush_polls_after_failure, 0,
                "{phase} cannot flush a retry"
            );
        }
    }

    #[test]
    fn v2_batch_response_requires_exact_ordered_full_id_correlation() {
        let batch = v2_effectful_batch_request(&[0x55, 0x56, 0x57]);
        let expected = v2_batch_request_ids(&batch);
        let valid = v2_batch_response_with_ids(expected.clone());
        assert!(super::v2_response_matches_request(&batch, &valid));

        let mut reordered = expected.clone();
        reordered.swap(0, 1);
        assert!(!super::v2_response_matches_request(
            &batch,
            &v2_batch_response_with_ids(reordered)
        ));
        let mut duplicate = expected.clone();
        duplicate[1] = duplicate[0];
        assert!(!super::v2_response_matches_request(
            &batch,
            &v2_batch_response_with_ids(duplicate)
        ));
        assert!(!super::v2_response_matches_request(
            &batch,
            &v2_batch_response_with_ids(expected[..2].to_vec())
        ));
        let mut unknown = expected.clone();
        unknown[1] = v2_effectful_request(0x58)
            .request_id()
            .expect("full but unrelated V2 ID");
        assert!(!super::v2_response_matches_request(
            &batch,
            &v2_batch_response_with_ids(unknown)
        ));
        let mut extra = expected.clone();
        extra.push(v2_effectful_request(0x5f).request_id().expect("full V2 ID"));
        assert!(!super::v2_response_matches_request(
            &batch,
            &v2_batch_response_with_ids(extra)
        ));
    }

    #[test]
    fn v2_batch_service_ambiguity_requires_the_exact_ordered_recovery_vector() {
        let batch = v2_effectful_batch_request(&[0x59, 0x5a]);
        let expected = v2_batch_request_ids(&batch);
        let error = opc_session_store::consumer::SessionConsumerV2FencedTransitionBatchError::outcome_unknown(
            expected.clone(),
        )
        .expect("exact ordered V2 IDs are a valid ambiguity receipt");
        let response = SessionConsumerV2Response::FencedTransitionV2Batch(Err(error));
        assert!(super::v2_response_matches_request(&batch, &response));
        assert!(super::v2_response_is_outcome_unknown(&response));
        assert!(matches!(
            super::v2_outcome_unknown(&batch),
            Some(PersistentSessionConsumerV2ExecuteError::OutcomeUnknownBatch { request_ids })
                if request_ids == expected
        ));

        let error = opc_session_store::consumer::SessionConsumerV2FencedTransitionBatchError::outcome_unknown(
            vec![expected[1], expected[0]],
        )
        .expect("reordered identities remain structurally encodable");
        assert!(!super::v2_response_matches_request(
            &batch,
            &SessionConsumerV2Response::FencedTransitionV2Batch(Err(error))
        ));

        let missing = opc_session_store::consumer::SessionConsumerV2FencedTransitionBatchError::outcome_unknown(
            expected[..1].to_vec(),
        )
        .expect("a partial but structurally valid ambiguity vector can be rejected by correlation");
        assert!(!super::v2_response_matches_request(
            &batch,
            &SessionConsumerV2Response::FencedTransitionV2Batch(Err(missing))
        ));

        let unknown = opc_session_store::consumer::SessionConsumerV2FencedTransitionBatchError::outcome_unknown(
            vec![expected[0], v2_effectful_request(0x60).request_id().expect("full unrelated V2 ID")],
        )
        .expect("an equal-length but unrelated ambiguity vector is structurally valid");
        assert!(!super::v2_response_matches_request(
            &batch,
            &SessionConsumerV2Response::FencedTransitionV2Batch(Err(unknown))
        ));
    }

    #[tokio::test]
    async fn v2_batch_response_respects_the_negotiated_frame_cap() {
        let batch = v2_effectful_batch_request(&[0x5b, 0x5c]);
        let response = ConsumerV2WireResponse::Response(ConsumerV2CallResponse {
            correlation: NonZeroU32::MIN,
            attempt_nonce: [0; 16],
            request_commitment: [0; 32],
            response: Box::new(v2_batch_response_with_ids(v2_batch_request_ids(&batch))),
        });
        let mut writer = PhaseFailWriter {
            accepted: 0,
            fail_after: None,
            fail_flush: false,
        };
        assert!(matches!(
            super::write_frame_bounded_until(
                &mut writer,
                &response,
                1,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await,
            Err(ProtocolError::FrameTooLarge(_))
        ));
        assert_eq!(
            writer.accepted, 0,
            "an over-cap batch response writes no prefix"
        );
    }

    #[test]
    fn revision_four_call_envelope_never_decodes_as_revision_three() {
        let v2 = ConsumerV2WireRequest::Call(ConsumerV2Call {
            correlation: NonZeroU32::MIN,
            attempt_nonce: [0; 16],
            request_commitment: [0; 32],
            request: Box::new(SessionConsumerV2Request::new(
                scope(),
                SessionConsumerV2Operation::FencedTransitionV2Capability,
            )),
        });
        let encoded = serde_json::to_vec(&v2).expect("revision four call encodes");
        assert!(decode_consumer_frame_payload::<ConsumerV2WireRequest>(&encoded).is_ok());
        assert!(
            decode_consumer_frame_payload::<ConsumerWireRequest>(&encoded).is_err(),
            "a revision-three envelope cannot interpret a V2 operation"
        );
    }

    #[test]
    fn revision_four_epoch_capability_response_matches_its_typed_request() {
        let request = SessionConsumerV2Request::new(
            scope(),
            SessionConsumerV2Operation::FencedTransitionV2Capability,
        );
        let response = SessionConsumerV2Response::FencedTransitionV2Capability(Ok(
            FencedTransitionV2Capability::V2,
        ));
        assert!(super::v2_response_matches_request(&request, &response));
    }

    #[test]
    fn v2_alpn_and_revision_are_distinct_from_v1() {
        assert_ne!(
            super::SESSION_QUORUM_CONSUMER_ALPN,
            super::SESSION_QUORUM_CONSUMER_V2_ALPN
        );
        assert_ne!(
            super::SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
            super::SESSION_QUORUM_CONSUMER_V2_TRANSPORT_REVISION
        );
    }

    #[test]
    fn v2_fenced_transition_wire_rejects_unbound_errors_after_effectful_call() {
        let key = SessionKey {
            tenant: TenantId::new("v2-error-correlation").expect("test tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"v2-error-correlation")
                .try_into()
                .expect("bounded stable ID"),
        };
        let transition = opc_session_store::FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(1).expect("nonzero history epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0x74; 16]),
            FencedTransitionLease::acquire(
                key,
                OwnerId::new("v2-error-correlation-owner").expect("test owner"),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .expect("bounded acquire"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("bounded V2 transition");
        let request = SessionConsumerV2Request::new(
            scope(),
            SessionConsumerV2Operation::FencedTransitionV2 {
                request: Box::new(transition),
            },
        );

        for error in [
            SessionConsumerV2FencedTransitionError::RequestConflict,
            SessionConsumerV2FencedTransitionError::OutcomeUnknown,
            SessionConsumerV2FencedTransitionError::Expired,
            SessionConsumerV2FencedTransitionError::HistoryFull,
            SessionConsumerV2FencedTransitionError::RetentionExhausted,
            SessionConsumerV2FencedTransitionError::StorageExhausted,
            SessionConsumerV2FencedTransitionError::Retired,
            SessionConsumerV2FencedTransitionError::EpochNotActive,
        ] {
            let response = SessionConsumerV2Response::FencedTransitionV2(Err(error));
            let encoded = serde_json::to_vec(&response).expect("typed V2 error encodes");
            let decoded: SessionConsumerV2Response =
                serde_json::from_slice(&encoded).expect("typed V2 error decodes");
            assert_eq!(decoded, response);
            assert_eq!(
                super::v2_response_matches_request(&request, &response),
                error.is_pre_dispatch_deterministic(),
                "V2 error classification must preserve the effect boundary"
            );
        }

        let canonical_payload = SessionConsumerV2FencedTransitionError::PayloadTooLarge {
            actual: (opc_session_store::FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES + 1) as u64,
            max: opc_session_store::FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES as u64,
        };
        let canonical = SessionConsumerV2Response::FencedTransitionV2(Err(canonical_payload));
        let canonical_wire = serde_json::to_vec(&canonical).expect("canonical V2 error encodes");
        let canonical: SessionConsumerV2Response =
            serde_json::from_slice(&canonical_wire).expect("canonical V2 error decodes");
        assert!(
            !super::v2_response_matches_request(&request, &canonical),
            "an unbound fixed-width payload error cannot complete an effectful request"
        );
        for error in [
            SessionConsumerV2FencedTransitionError::PayloadTooLarge {
                actual: u64::MAX,
                max: 1,
            },
            SessionConsumerV2FencedTransitionError::PayloadTooLarge {
                actual: opc_session_store::FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES as u64,
                max: opc_session_store::FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES as u64,
            },
        ] {
            let malformed = SessionConsumerV2Response::FencedTransitionV2(Err(error));
            let encoded = serde_json::to_vec(&malformed)
                .expect("a syntactically valid malformed V2 error still encodes");
            let malformed: SessionConsumerV2Response = serde_json::from_slice(&encoded)
                .expect("a custom server's malformed V2 error still decodes");
            assert!(
                !super::v2_response_matches_request(&request, &malformed),
                "noncanonical V2 execution payload error {error:?} must close both transport matchers"
            );
        }
    }

    #[test]
    fn v2_status_wire_accepts_a_retained_deterministic_error() {
        let key = SessionKey {
            tenant: TenantId::new("v2-status-error-correlation").expect("test tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"v2-status-error-correlation")
                .try_into()
                .expect("bounded stable ID"),
        };
        let transition = opc_session_store::FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(1).expect("nonzero history epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0x77; 16]),
            FencedTransitionLease::acquire(
                key,
                OwnerId::new("v2-status-error-correlation-owner").expect("test owner"),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .expect("bounded acquire"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("bounded V2 transition");
        let request = SessionConsumerV2Request::new(
            scope(),
            SessionConsumerV2Operation::FencedTransitionV2Status {
                request: Box::new(transition),
            },
        );
        for error in [
            SessionConsumerV2FencedTransitionError::TopologyAuthorityRevoked,
            SessionConsumerV2FencedTransitionError::Store(SessionConsumerStoreError::NotFound),
            SessionConsumerV2FencedTransitionError::Store(SessionConsumerStoreError::StaleFence),
            SessionConsumerV2FencedTransitionError::Store(SessionConsumerStoreError::CasConflict),
            SessionConsumerV2FencedTransitionError::InvalidSessionTtl,
            SessionConsumerV2FencedTransitionError::InvalidRecordExpiry,
            SessionConsumerV2FencedTransitionError::LeaseHeld,
            SessionConsumerV2FencedTransitionError::LeaseExpired,
            SessionConsumerV2FencedTransitionError::PayloadTooLarge {
                actual: (opc_session_store::FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES + 1)
                    as u64,
                max: opc_session_store::FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES as u64,
            },
            SessionConsumerV2FencedTransitionError::StorageExhausted,
        ] {
            let response = SessionConsumerV2Response::FencedTransitionV2Status(Ok(
                SessionConsumerV2FencedTransitionStatus::Recorded(Box::new(Err(error))),
            ));
            let encoded = serde_json::to_vec(&response).expect("closed V2 status encodes");
            assert_eq!(
                serde_json::from_slice::<SessionConsumerV2Response>(&encoded)
                    .expect("closed V2 status decodes"),
                response
            );
            assert!(
                super::v2_response_matches_request(&request, &response),
                "a retained deterministic error has no outcome body to correlate, but is exact V2 status: {error:?}"
            );
        }
    }

    #[test]
    fn v2_status_wire_rejects_nonreceipt_store_errors() {
        let request = v2_serialized_body_conflict(true);
        let response = SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::Recorded(Box::new(Err(
                SessionConsumerV2FencedTransitionError::Store(
                    SessionConsumerStoreError::Unavailable,
                ),
            ))),
        ));

        assert!(
            !super::v2_response_matches_request(&request, &response),
            "a custom server cannot turn an unavailable backend into a retained receipt"
        );
        let malformed_payload = SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::Recorded(Box::new(Err(
                SessionConsumerV2FencedTransitionError::PayloadTooLarge { actual: 1, max: 2 },
            ))),
        ));
        assert!(
            !super::v2_response_matches_request(&request, &malformed_payload),
            "a custom server cannot use arbitrary platform-independent payload bounds"
        );
    }

    #[tokio::test]
    async fn revision_four_wire_dispatches_same_full_id_body_conflicts() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("v2-conflict-client");
        let server_identity = material_spiffe("v2-conflict-server");
        let client_material = RotatableClientMaterial::new(client_identity.as_str());
        let v2_calls = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(V2ConflictTestConsumer {
            v2_calls: Arc::clone(&v2_calls),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity.clone()],
            std::iter::empty(),
        )
        .expect("V2 conflict authorizer");
        let (server, address) = SessionQuorumConsumerServer::new(
            service,
            client_material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for V2 conflict lane");
        let client = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            client_material.config(),
        );

        let conflict = v2_serialized_body_conflict(false);
        assert_eq!(
            client.execute_v2(conflict).await,
            Ok(SessionConsumerV2Response::FencedTransitionV2(Err(
                SessionConsumerV2FencedTransitionError::RequestConflict,
            )))
        );
        assert_eq!(
            client.execute_v2(v2_serialized_body_conflict(true)).await,
            Ok(SessionConsumerV2Response::FencedTransitionV2Status(Ok(
                SessionConsumerV2FencedTransitionStatus::RequestConflict,
            )))
        );
        assert_eq!(
            v2_calls.load(Ordering::SeqCst),
            2,
            "both conflict forms reach the revision-four service"
        );

        let mut malformed =
            serde_json::to_value(v2_serialized_body_conflict(false)).expect("conflict encodes");
        let serde_json::Value::Object(fields) = &mut malformed else {
            panic!("V2 envelope is an object");
        };
        fields.insert("request_id".into(), serde_json::Value::Null);
        let malformed: SessionConsumerV2Request =
            serde_json::from_value(malformed).expect("mismatched envelope decodes");
        assert_eq!(
            client.execute_v2(malformed).await,
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            })
        );
        assert_eq!(
            v2_calls.load(Ordering::SeqCst),
            2,
            "outer-ID mismatches remain transport rejections"
        );

        assert_eq!(
            client
                .execute(SessionConsumerRequest::new(
                    scope(),
                    SessionConsumerRequestId::from_bytes([0x76; 16]),
                    SessionConsumerOperation::Capabilities,
                ))
                .await,
            Ok(SessionConsumerResponse::Rejected(
                SessionConsumerRejection::Unavailable,
            ))
        );
        assert_eq!(
            v2_calls.load(Ordering::SeqCst),
            2,
            "the frozen revision-three lane never dispatches a V2 request"
        );
        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn stateless_v2_effectful_rejection_after_dispatch_is_exact_unknown() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("v2-effectful-rejection-client");
        let server_identity = material_spiffe("v2-effectful-rejection-server");
        let material = RotatableClientMaterial::new(client_identity.as_str());
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Semaphore::new(0));
        let service = Arc::new(V2EnteredRejectingTestConsumer {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity],
            std::iter::empty(),
        )
        .expect("effectful rejection authorizer");
        let (server, address) = SessionQuorumConsumerServer::new(
            service,
            material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .with_operation_timeout(Duration::from_secs(5))
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for effectful V2 rejection test");
        let client = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            material.config(),
        )
        .with_operation_timeout(Duration::from_secs(5));

        let singleton = v2_effectful_request(0x61);
        let singleton_id = singleton.request_id().expect("singleton has full V2 ID");
        let singleton_call = tokio::spawn({
            let client = client.clone();
            async move { client.execute_v2(singleton).await }
        });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("singleton Call reached the service");
        release.add_permits(1);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), singleton_call)
                .await
                .expect("singleton rejection remains bounded")
                .expect("join singleton V2 caller"),
            Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown {
                request_id: singleton_id,
            })
        );

        let batch = v2_effectful_batch_request(&[0x62, 0x63]);
        let batch_ids = v2_batch_request_ids(&batch);
        let batch_call = tokio::spawn({
            let client = client.clone();
            async move { client.execute_v2(batch).await }
        });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("batch Call reached the service");
        release.add_permits(1);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), batch_call)
                .await
                .expect("batch rejection remains bounded")
                .expect("join batch V2 caller"),
            Err(
                PersistentSessionConsumerV2ExecuteError::OutcomeUnknownBatch {
                    request_ids: batch_ids,
                }
            )
        );

        let persistent = PersistentSessionConsumerClient::from_stateless(client)
            .expect("construct persistent V2 client from stateless lineage");
        let request = v2_effectful_request(0x64);
        let request_id = request
            .request_id()
            .expect("persistent request has full V2 ID");
        let persistent_call = tokio::spawn({
            let persistent = persistent.clone();
            async move { persistent.execute_v2(&request).await }
        });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("persistent singleton Call reached the service");
        release.add_permits(1);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), persistent_call)
                .await
                .expect("persistent singleton rejection remains bounded")
                .expect("join persistent singleton V2 caller"),
            Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id })
        );
        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn stateless_v2_authenticated_peer_unbound_or_lost_response_is_exact_unknown() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("v2-raw-response-client");
        let server_identity = material_spiffe("v2-raw-response-server");
        let material = RotatableClientMaterial::new(client_identity.as_str());
        let server_material = material.trusted_server_config(server_identity.as_str());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind raw authenticated V2 peer");
        let address = listener
            .local_addr()
            .expect("raw authenticated V2 peer address");
        let peer = tokio::spawn(async move {
            for scenario in 0_u8..4 {
                let (tcp, _) = listener.accept().await.expect("accept V2 client");
                let handshake = server_material
                    .begin_handshake()
                    .expect("raw peer server handshake snapshot");
                let acceptor = tokio_rustls::TlsAcceptor::from(super::consumer_server_tls_config(
                    handshake.rustls_config(),
                ));
                let mut tls = acceptor.accept(tcp).await.expect("complete raw V2 TLS");
                handshake.admit().expect("admit raw V2 TLS peer");
                assert!(matches!(
                    super::read_consumer_frame::<_, ConsumerV2WireRequest>(
                        &mut tls,
                        super::MAX_NEGOTIATED_FRAME_SIZE,
                    )
                    .await
                    .expect("read V2 Hello"),
                    ConsumerV2WireRequest::Hello(_)
                ));
                super::write_frame_bounded_until(
                    &mut tls,
                    &ConsumerV2WireResponse::HelloAck(ConsumerHelloAck {
                        transport_revision: super::SESSION_QUORUM_CONSUMER_V2_TRANSPORT_REVISION,
                        scope: scope(),
                        request_frame_size: u32::try_from(super::MAX_NEGOTIATED_FRAME_SIZE)
                            .expect("test V2 frame cap fits u32"),
                    }),
                    super::MAX_NEGOTIATED_FRAME_SIZE,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await
                .expect("write V2 HelloAck");
                let ConsumerV2WireRequest::Call(ConsumerV2Call { correlation, .. }) =
                    super::read_consumer_frame::<_, ConsumerV2WireRequest>(
                        &mut tls,
                        super::MAX_NEGOTIATED_FRAME_SIZE,
                    )
                    .await
                    .expect("read V2 Call")
                else {
                    panic!("raw peer received V2 Call after Hello");
                };
                let response = match scenario {
                    // A valid wire error contains no complete V2 identity or
                    // body witness, so a peer can substitute it.
                    0 => Some(ConsumerV2WireResponse::Response(ConsumerV2CallResponse {
                        correlation,
                        attempt_nonce: [0; 16],
                        request_commitment: [0; 32],
                        response: Box::new(SessionConsumerV2Response::FencedTransitionV2(Err(
                            SessionConsumerV2FencedTransitionError::OutcomeUnknown,
                        ))),
                    })),
                    // Even a generic rejection with the exact outer
                    // correlation carries no mutation recovery identity.
                    1 => Some(ConsumerV2WireResponse::Response(ConsumerV2CallResponse {
                        correlation,
                        attempt_nonce: [0; 16],
                        request_commitment: [0; 32],
                        response: Box::new(SessionConsumerV2Response::Rejected(
                            SessionConsumerRejection::Unavailable,
                        )),
                    })),
                    // Outer correlation is an ordering aid, not the V2
                    // effect identity; a mismatch remains ambiguous.
                    2 => Some(ConsumerV2WireResponse::Response(ConsumerV2CallResponse {
                        correlation: NonZeroU32::new(correlation.get() + 1)
                            .expect("test correlation cannot wrap"),
                        attempt_nonce: [0; 16],
                        request_commitment: [0; 32],
                        response: Box::new(SessionConsumerV2Response::Rejected(
                            SessionConsumerRejection::Unavailable,
                        )),
                    })),
                    // Drop without writing a response after a complete Call.
                    _ => None,
                };
                if let Some(response) = response {
                    super::write_frame_bounded_until(
                        &mut tls,
                        &response,
                        super::MAX_NEGOTIATED_FRAME_SIZE,
                        tokio::time::Instant::now() + Duration::from_secs(1),
                    )
                    .await
                    .expect("write substituted V2 response");
                }
            }
        });
        let client = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            material.config(),
        )
        .with_operation_timeout(Duration::from_secs(2));
        for nonce in [0x64, 0x65, 0x66, 0x67] {
            let request = v2_effectful_request(nonce);
            let request_id = request.request_id().expect("effectful request has full ID");
            assert_eq!(
                client.execute_v2(request).await,
                Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id })
            );
        }
        peer.await.expect("join raw authenticated V2 peer");
    }

    #[tokio::test]
    async fn persistent_v2_two_frame_stale_tuple_poisoning_preserves_effect_boundary() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("persistent-v2-two-frame-client");
        let server_identity = material_spiffe("persistent-v2-two-frame-server");
        let material = RotatableClientMaterial::new(client_identity.as_str());
        let server_material = material.trusted_server_config(server_identity.as_str());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind persistent raw authenticated V2 peer");
        let address = listener
            .local_addr()
            .expect("persistent raw authenticated V2 peer address");
        let first_request = SessionConsumerV2Request::new(
            scope(),
            SessionConsumerV2Operation::FencedTransitionV2Capability,
        );
        let second_request = v2_effectful_request(0x69);
        let first_result =
            SessionConsumerV2Response::Rejected(SessionConsumerRejection::MalformedRequest);
        let backend_dispatches = Arc::new(AtomicUsize::new(0));
        let client_call_frames = Arc::new(AtomicUsize::new(0));
        let peer_first_request = first_request.clone();
        let peer_first_result = first_result.clone();
        let peer = tokio::spawn({
            let backend_dispatches = Arc::clone(&backend_dispatches);
            let client_call_frames = Arc::clone(&client_call_frames);
            async move {
                let (tcp, _) = listener
                    .accept()
                    .await
                    .expect("accept persistent V2 client");
                let handshake = server_material
                    .begin_handshake()
                    .expect("persistent raw peer server handshake snapshot");
                let acceptor = tokio_rustls::TlsAcceptor::from(super::consumer_server_tls_config(
                    handshake.rustls_config(),
                ));
                let mut tls = acceptor
                    .accept(tcp)
                    .await
                    .expect("complete persistent raw V2 TLS");
                handshake.admit().expect("admit persistent raw V2 TLS peer");
                assert!(matches!(
                    super::read_consumer_frame::<_, ConsumerV2WireRequest>(
                        &mut tls,
                        super::MAX_NEGOTIATED_FRAME_SIZE,
                    )
                    .await
                    .expect("read persistent V2 Hello"),
                    ConsumerV2WireRequest::Hello(_)
                ));
                super::write_frame_bounded_until(
                    &mut tls,
                    &ConsumerV2WireResponse::HelloAck(ConsumerHelloAck {
                        transport_revision: super::SESSION_QUORUM_CONSUMER_V2_TRANSPORT_REVISION,
                        scope: scope(),
                        request_frame_size: u32::try_from(super::MAX_NEGOTIATED_FRAME_SIZE)
                            .expect("test V2 frame cap fits u32"),
                    }),
                    super::MAX_NEGOTIATED_FRAME_SIZE,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await
                .expect("write persistent V2 HelloAck");

                let ConsumerV2WireRequest::Call(ConsumerV2Call {
                    correlation: first_correlation,
                    attempt_nonce: first_attempt_nonce,
                    request_commitment: first_commitment,
                    request: received_first_request,
                }) = super::read_consumer_frame::<_, ConsumerV2WireRequest>(
                    &mut tls,
                    super::MAX_NEGOTIATED_FRAME_SIZE,
                )
                .await
                .expect("read first persistent V2 Call")
                else {
                    panic!("persistent raw peer received a control frame after Hello");
                };
                client_call_frames.fetch_add(1, Ordering::SeqCst);
                assert_eq!(*received_first_request, peer_first_request);
                assert_eq!(first_correlation, NonZeroU32::MIN);
                assert_eq!(
                    first_commitment,
                    super::v2_request_commitment(&peer_first_request).expect("test commitment"),
                    "first Call carries its exact V2 body commitment"
                );
                assert!(super::v2_response_matches_request(
                    &peer_first_request,
                    &peer_first_result
                ));
                backend_dispatches.fetch_add(1, Ordering::SeqCst);

                // Send a complete valid result for Call 1, then immediately
                // leave a well-formed response for the predictable next
                // correlation buffered on this same persistent lane. Its
                // outer correlation is right, but both tuple witnesses are
                // stale from Call 1 and cannot complete Call 2.
                let first_frame = ConsumerV2WireResponse::Response(ConsumerV2CallResponse {
                    correlation: first_correlation,
                    attempt_nonce: first_attempt_nonce,
                    request_commitment: first_commitment,
                    response: Box::new(peer_first_result.clone()),
                });
                let second_correlation = NonZeroU32::new(
                    first_correlation
                        .get()
                        .checked_add(1)
                        .expect("test correlation cannot wrap"),
                )
                .expect("next test correlation remains nonzero");
                let second_frame = ConsumerV2WireResponse::Response(ConsumerV2CallResponse {
                    correlation: second_correlation,
                    attempt_nonce: first_attempt_nonce,
                    request_commitment: first_commitment,
                    response: Box::new(peer_first_result),
                });
                crate::protocol::write_two_frames_coalesced(
                    &mut tls,
                    &first_frame,
                    &second_frame,
                    super::MAX_NEGOTIATED_FRAME_SIZE,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await
                .expect("queue coalesced forged second persistent V2 response");

                match super::read_consumer_frame::<_, ConsumerV2WireRequest>(
                    &mut tls,
                    super::MAX_NEGOTIATED_FRAME_SIZE,
                )
                .await
                {
                    Ok(ConsumerV2WireRequest::Call(_)) => {
                        client_call_frames.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(ConsumerV2WireRequest::Hello(_)) => {
                        panic!("persistent V2 client repeated Hello on one lane");
                    }
                    Err(_) => {}
                }
            }
        });
        let stateless = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            material.config(),
        )
        .with_operation_timeout(Duration::from_secs(2));
        let persistent = PersistentSessionConsumerClient::from_stateless(stateless)
            .expect("construct persistent V2 client");

        assert_eq!(
            persistent.execute_v2(&first_request).await,
            Ok(first_result.clone()),
            "Call 1 receives its exact typed result before the forged frame"
        );
        assert_eq!(
            persistent.v2_diagnostics(),
            super::PersistentSessionConsumerV2Diagnostics {
                setup_successes: 1,
                reused: 0,
                reconnects: 1,
                active: 0,
                idle: 0,
            },
            "the actor installs poison and retires before Call 1 becomes visible"
        );
        persistent
            .request_reauthentication()
            .expect("reauthentication retires lanes without erasing poison debt");

        assert_eq!(
            persistent.execute_v2(&second_request).await,
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            }),
            "the continuously owned read side must retire the lane before Call 2 writes"
        );
        peer.await
            .expect("join persistent raw authenticated V2 peer");
        assert_eq!(
            client_call_frames.load(Ordering::SeqCst),
            1,
            "one coalesced forged future frame permits zero Call 2 bytes"
        );
        assert_eq!(
            backend_dispatches.load(Ordering::SeqCst),
            1,
            "the forged queued frame cannot create a second backend effect"
        );
        assert_eq!(
            persistent.v2_diagnostics(),
            super::PersistentSessionConsumerV2Diagnostics {
                setup_successes: 1,
                reused: 0,
                reconnects: 1,
                active: 0,
                idle: 0,
            },
            "Call 2 consumes poison before selecting or reconnecting a lane"
        );
        let _ = persistent.shutdown().await;
    }

    #[tokio::test]
    async fn persistent_v2_delayed_extra_frame_installs_poison_before_next_checkout() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("persistent-v2-delayed-extra-client");
        let server_identity = material_spiffe("persistent-v2-delayed-extra-server");
        let material = RotatableClientMaterial::new(client_identity.as_str());
        let server_material = material.trusted_server_config(server_identity.as_str());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind delayed-extra V2 peer");
        let address = listener.local_addr().expect("delayed-extra V2 address");
        let first_request = v2_effectful_request(0x6b);
        let second_request = v2_effectful_request(0x6c);
        let first_result = SessionConsumerV2Response::FencedTransitionV2(Err(
            SessionConsumerV2FencedTransitionError::RequestConflict,
        ));
        let client_call_frames = Arc::new(AtomicUsize::new(0));
        let backend_dispatches = Arc::new(AtomicUsize::new(0));
        let (release_extra, released_extra) = tokio::sync::oneshot::channel();
        let (extra_written, observed_extra_written) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn({
            let peer_first_request = first_request.clone();
            let peer_first_result = first_result.clone();
            let client_call_frames = Arc::clone(&client_call_frames);
            let backend_dispatches = Arc::clone(&backend_dispatches);
            async move {
                let (tcp, _) = listener
                    .accept()
                    .await
                    .expect("accept delayed-extra V2 peer");
                let handshake = server_material
                    .begin_handshake()
                    .expect("delayed-extra server handshake snapshot");
                let acceptor = tokio_rustls::TlsAcceptor::from(super::consumer_server_tls_config(
                    handshake.rustls_config(),
                ));
                let mut tls = acceptor
                    .accept(tcp)
                    .await
                    .expect("complete delayed-extra V2 TLS");
                handshake.admit().expect("admit delayed-extra V2 peer");
                assert!(matches!(
                    super::read_consumer_frame::<_, ConsumerV2WireRequest>(
                        &mut tls,
                        super::MAX_NEGOTIATED_FRAME_SIZE,
                    )
                    .await
                    .expect("read delayed-extra V2 Hello"),
                    ConsumerV2WireRequest::Hello(_)
                ));
                super::write_frame_bounded_until(
                    &mut tls,
                    &ConsumerV2WireResponse::HelloAck(ConsumerHelloAck {
                        transport_revision: super::SESSION_QUORUM_CONSUMER_V2_TRANSPORT_REVISION,
                        scope: scope(),
                        request_frame_size: u32::try_from(super::MAX_NEGOTIATED_FRAME_SIZE)
                            .expect("test V2 frame cap fits u32"),
                    }),
                    super::MAX_NEGOTIATED_FRAME_SIZE,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await
                .expect("write delayed-extra V2 HelloAck");

                let ConsumerV2WireRequest::Call(ConsumerV2Call {
                    correlation,
                    attempt_nonce,
                    request_commitment,
                    request,
                }) = super::read_consumer_frame::<_, ConsumerV2WireRequest>(
                    &mut tls,
                    super::MAX_NEGOTIATED_FRAME_SIZE,
                )
                .await
                .expect("read delayed-extra Call 1")
                else {
                    panic!("delayed-extra peer received control after Hello");
                };
                client_call_frames.fetch_add(1, Ordering::SeqCst);
                backend_dispatches.fetch_add(1, Ordering::SeqCst);
                assert_eq!(*request, peer_first_request);
                let exact_response = ConsumerV2WireResponse::Response(ConsumerV2CallResponse {
                    correlation,
                    attempt_nonce,
                    request_commitment,
                    response: Box::new(peer_first_result.clone()),
                });
                super::write_frame_bounded_until(
                    &mut tls,
                    &exact_response,
                    super::MAX_NEGOTIATED_FRAME_SIZE,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await
                .expect("write exact delayed-extra Call 1 response");

                released_extra
                    .await
                    .expect("release delayed extra only after Call 1 is visible");
                let forged = ConsumerV2WireResponse::Response(ConsumerV2CallResponse {
                    correlation: NonZeroU32::new(
                        correlation
                            .get()
                            .checked_add(1)
                            .expect("test correlation cannot wrap"),
                    )
                    .expect("next test correlation remains nonzero"),
                    attempt_nonce,
                    request_commitment,
                    response: Box::new(peer_first_result),
                });
                super::write_frame_bounded_until(
                    &mut tls,
                    &forged,
                    super::MAX_NEGOTIATED_FRAME_SIZE,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await
                .expect("write delayed forged future frame");
                extra_written
                    .send(())
                    .expect("publish delayed-extra write completion");

                match super::read_consumer_frame::<_, ConsumerV2WireRequest>(
                    &mut tls,
                    super::MAX_NEGOTIATED_FRAME_SIZE,
                )
                .await
                {
                    Ok(ConsumerV2WireRequest::Call(_)) => {
                        client_call_frames.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(ConsumerV2WireRequest::Hello(_)) => {
                        panic!("delayed-extra V2 client repeated Hello on one lane");
                    }
                    Err(_) => {}
                }
            }
        });
        let stateless = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            material.config(),
        )
        .with_operation_timeout(Duration::from_secs(2));
        let persistent = PersistentSessionConsumerClient::from_stateless(stateless)
            .expect("construct delayed-extra persistent V2 client");

        assert_eq!(
            persistent.execute_v2(&first_request).await,
            Ok(first_result),
            "Call 1 is published before the peer sends its delayed extra frame"
        );
        let poisoned = persistent.v2_pool.drained_notify.notified();
        tokio::pin!(poisoned);
        poisoned.as_mut().enable();
        release_extra
            .send(())
            .expect("release delayed forged future frame");
        observed_extra_written
            .await
            .expect("observe delayed-extra transport write");
        poisoned.await;
        {
            let idle = persistent
                .v2_pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(matches!(
                idle.front(),
                Some(PersistentV2PoolEntry::Poison(_))
            ));
        }
        assert_eq!(
            persistent.execute_v2(&second_request).await,
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            })
        );
        peer.await.expect("join delayed-extra V2 peer");
        assert_eq!(client_call_frames.load(Ordering::SeqCst), 1);
        assert_eq!(backend_dispatches.load(Ordering::SeqCst), 1);
        let _ = persistent.shutdown().await;
    }

    #[tokio::test]
    async fn persistent_v2_idle_partial_frame_precedes_a_different_healthy_lane() {
        let config = PersistentSessionConsumerConfig::try_new(
            2,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            1,
            Duration::ZERO,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("two-lane partial-frame pool");
        let pool = v2_admission_test_pool(config);
        let (healthy_commands, mut healthy_actor) = mpsc::channel(1);
        let (healthy_retirement, _healthy_retirement_rx) = watch::channel(None);
        let established = tokio::time::Instant::now();
        let lifecycle = ConnectionLifecycle::new(
            pool.client.lifecycle_policy,
            established,
            None,
            None,
            pool.client.reauthentication.generation(),
            Some(pool.client.tls_config.material_status().epoch()),
        )
        .expect("valid partial-frame lifecycle");
        let (lane_io, mut peer_io) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(lane_io);
        let (partial_commands, partial_command_rx) = mpsc::channel(1);
        let (partial_retirement, actor_retirement) = watch::channel(None);
        let physical = Arc::new(Semaphore::new(2));
        let healthy_physical_permit = Arc::clone(&physical)
            .try_acquire_owned()
            .expect("reserve healthy-lane global admission");
        let physical_permit = Arc::clone(&physical)
            .try_acquire_owned()
            .expect("reserve partial-frame global admission");
        let partial_state = PersistentV2LaneState::new();
        pool.active.store(2, Ordering::Relaxed);
        let healthy_lifetime = PersistentV2LaneLifetime {
            pool_connection: Arc::downgrade(&pool),
            state: PersistentV2LaneState::new(),
            _pool_width_admission: Some(
                Arc::clone(&pool.actor_lanes)
                    .try_acquire_owned()
                    .expect("reserve healthy-lane pool width"),
            ),
            _physical_admission: Some(healthy_physical_permit),
        };
        let actor = tokio::spawn(run_persistent_v2_lane(PersistentV2LaneActor {
            reader: Box::new(reader),
            writer: Box::new(writer),
            request_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            lifecycle,
            rotation_jitter: Duration::ZERO,
            client: pool.client.clone(),
            reauthentication_changes: pool.client.reauthentication.subscribe(),
            material_changes: Some(pool.client.tls_config.subscribe_material_changes()),
            retirement: actor_retirement,
            forced: pool.shutdown_forced_tx.subscribe(),
            shutdown_io: Arc::clone(&pool.shutdown_io),
            commands: partial_command_rx,
            lifetime: PersistentV2LaneLifetime {
                pool_connection: Arc::downgrade(&pool),
                state: Arc::clone(&partial_state),
                _pool_width_admission: Some(
                    Arc::clone(&pool.actor_lanes)
                        .try_acquire_owned()
                        .expect("reserve partial-frame pool width"),
                ),
                _physical_admission: Some(physical_permit),
            },
        }));
        {
            let mut idle = pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            idle.push_back(PersistentV2PoolEntry::Lane(PersistentV2Connection {
                commands: healthy_commands,
                idle_deadline: established + Duration::from_secs(1),
                retirement: healthy_retirement,
                admitted_generation: pool.client.reauthentication.generation(),
                admitted_material_epoch: pool.client.tls_config.material_status().epoch(),
                state: PersistentV2LaneState::new(),
            }));
            idle.push_back(PersistentV2PoolEntry::Lane(PersistentV2Connection {
                commands: partial_commands,
                idle_deadline: established + Duration::from_secs(1),
                retirement: partial_retirement,
                admitted_generation: pool.client.reauthentication.generation(),
                admitted_material_epoch: pool.client.tls_config.material_status().epoch(),
                state: partial_state,
            }));
        }

        let classified = pool.drained_notify.notified();
        tokio::pin!(classified);
        classified.as_mut().enable();
        peer_io
            .write_all(&[0])
            .await
            .expect("write one authenticated plaintext prefix byte");
        peer_io
            .flush()
            .await
            .expect("flush one authenticated plaintext prefix byte");
        classified.await;
        actor.await.expect("join partial-frame lane actor");
        assert_eq!(pool.active.load(Ordering::Acquire), 1);
        assert_eq!(pool.actor_lanes.available_permits(), 1);
        {
            let idle = pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(matches!(
                idle.front(),
                Some(PersistentV2PoolEntry::Poison(_))
            ));
        }
        assert_eq!(
            pool.execute(&v2_effectful_request(0x6e)).await,
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            }),
            "partial bytes on one lane create pool-wide debt before another lane can write"
        );
        assert!(matches!(
            healthy_actor.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(pool.setup_successes.load(Ordering::Relaxed), 0);
        assert_eq!(pool.reused.load(Ordering::Relaxed), 0);
        drop(healthy_lifetime);
        assert_eq!(pool.active.load(Ordering::Acquire), 0);
        assert_eq!(pool.actor_lanes.available_permits(), 2);
        assert!(Arc::clone(&physical).try_acquire_many_owned(2).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persistent_v2_positive_read_reserves_debt_before_checkout_races() {
        let config = PersistentSessionConsumerConfig::try_new(
            2,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            1,
            Duration::ZERO,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("two-lane positive-read reservation pool");
        let pool = v2_admission_test_pool(config);
        let established = tokio::time::Instant::now();
        let lifecycle = ConnectionLifecycle::new(
            pool.client.lifecycle_policy,
            established,
            None,
            None,
            pool.client.reauthentication.generation(),
            Some(pool.client.tls_config.material_status().epoch()),
        )
        .expect("valid positive-read reservation lifecycle");
        let (lane_io, mut peer_io) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(lane_io);
        let (_partial_commands, partial_command_rx) = mpsc::channel(1);
        let (_partial_retirement, actor_retirement) = watch::channel(None);
        let physical = Arc::new(Semaphore::new(1));
        pool.active.store(1, Ordering::Relaxed);
        let actor = tokio::spawn(run_persistent_v2_lane(PersistentV2LaneActor {
            reader: Box::new(reader),
            writer: Box::new(writer),
            request_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            lifecycle,
            rotation_jitter: Duration::ZERO,
            client: pool.client.clone(),
            reauthentication_changes: pool.client.reauthentication.subscribe(),
            material_changes: Some(pool.client.tls_config.subscribe_material_changes()),
            retirement: actor_retirement,
            forced: pool.shutdown_forced_tx.subscribe(),
            shutdown_io: Arc::clone(&pool.shutdown_io),
            commands: partial_command_rx,
            lifetime: PersistentV2LaneLifetime {
                pool_connection: Arc::downgrade(&pool),
                state: PersistentV2LaneState::new(),
                _pool_width_admission: Some(
                    Arc::clone(&pool.actor_lanes)
                        .try_acquire_owned()
                        .expect("reserve partial-frame pool width"),
                ),
                _physical_admission: Some(
                    Arc::clone(&physical)
                        .try_acquire_owned()
                        .expect("reserve partial-frame physical admission"),
                ),
            },
        }));
        let idle_deadline = established + Duration::from_secs(1);
        let (first_commands, mut first_actor) = mpsc::channel(1);
        let (first_retirement, _first_retirement_rx) = watch::channel(None);
        let (second_commands, mut second_actor) = mpsc::channel(1);
        let (second_retirement, _second_retirement_rx) = watch::channel(None);
        {
            let mut idle = pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            idle.push_back(PersistentV2PoolEntry::Lane(PersistentV2Connection {
                commands: first_commands,
                idle_deadline,
                retirement: first_retirement,
                admitted_generation: pool.client.reauthentication.generation(),
                admitted_material_epoch: pool.client.tls_config.material_status().epoch(),
                state: PersistentV2LaneState::new(),
            }));
            idle.push_back(PersistentV2PoolEntry::Lane(PersistentV2Connection {
                commands: second_commands,
                idle_deadline,
                retirement: second_retirement,
                admitted_generation: pool.client.reauthentication.generation(),
                admitted_material_epoch: pool.client.tls_config.material_status().epoch(),
                state: PersistentV2LaneState::new(),
            }));
        }

        // Pause after the exact authority transition that used to occur only
        // after the read observer had returned to the actor. The other test
        // worker exercises checkout, readiness, and prewarm in that former
        // window while the actor still has both TLS halves.
        let hook = Arc::new(PersistentV2PositiveReadReservationHook::new());
        *pool
            .positive_read_reservation_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&hook));
        let observed = hook.observed.notified();
        tokio::pin!(observed);
        observed.as_mut().enable();
        peer_io
            .write_all(&[0])
            .await
            .expect("write one authenticated plaintext prefix byte");
        peer_io
            .flush()
            .await
            .expect("flush one authenticated plaintext prefix byte");
        observed.await;

        // The reader is still inside poll_read with the queue authority held.
        // Start Call 2 only after that exact barrier, then release the poll;
        // its post-admission selection must consume poison before either
        // healthy actor can receive a Call byte.
        let (call_started, call_started_rx) = oneshot::channel();
        let call_pool = Arc::clone(&pool);
        let call = tokio::spawn(async move {
            let _ = call_started.send(());
            call_pool.execute(&v2_effectful_request(0x70)).await
        });
        call_started_rx
            .await
            .expect("Call 2 is started after the reader barrier");
        assert_eq!(pool.reconnects.load(Ordering::Relaxed), 0);
        hook.resume();
        assert_eq!(
            call.await.expect("join deterministic Call 2"),
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            }),
            "the next checkout consumes reserved debt before a lane/write"
        );
        assert!(matches!(
            first_actor.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            second_actor.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(pool.setup_successes.load(Ordering::Relaxed), 0);
        assert_eq!(pool.reused.load(Ordering::Relaxed), 0);

        actor.await.expect("join paused partial-frame lane actor");
        drop(peer_io);
        pool.start_shutdown();
        pool.wait_shutdown_complete().await;
    }

    #[test]
    fn persistent_v2_poisoned_source_is_not_reported_as_live_capacity() {
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_RECONNECT_JITTER,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("one-lane V2 poison diagnostics pool");
        let pool = v2_admission_test_pool(config);
        let state = PersistentV2LaneState::new();
        state.healthy.store(true, Ordering::Release);
        let (commands, _actor) = mpsc::channel(1);
        let (retirement, _retirement_rx) = watch::channel(None);
        pool.idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(PersistentV2PoolEntry::Lane(PersistentV2Connection {
                commands,
                idle_deadline: tokio::time::Instant::now() + Duration::from_secs(1),
                retirement,
                admitted_generation: pool.client.reauthentication.generation(),
                admitted_material_epoch: pool.client.tls_config.material_status().epoch(),
                state: Arc::clone(&state),
            }));
        let physical = Arc::new(Semaphore::new(1));
        pool.active.store(1, Ordering::Relaxed);
        pool.healthy_active.store(1, Ordering::Relaxed);
        let lifetime = PersistentV2LaneLifetime {
            pool_connection: Arc::downgrade(&pool),
            state,
            _pool_width_admission: Some(
                Arc::clone(&pool.actor_lanes)
                    .try_acquire_owned()
                    .expect("reserve poisoned-source pool width"),
            ),
            _physical_admission: Some(
                Arc::clone(&physical)
                    .try_acquire_owned()
                    .expect("reserve poisoned-source physical admission"),
            ),
        };

        lifetime.install_poison_ticket();
        assert_eq!(
            pool.diagnostics(),
            super::PersistentSessionConsumerV2Diagnostics {
                setup_successes: 0,
                reused: 0,
                reconnects: 0,
                active: 0,
                idle: 0,
            },
            "the source and its poison ticket are not authenticated idle capacity"
        );
        let idle = pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(matches!(
            idle.front(),
            Some(PersistentV2PoolEntry::Poison(_))
        ));
        assert_eq!(
            idle.len(),
            2,
            "the bounded ticket precedes its source handle"
        );
        drop(idle);
        drop(lifetime);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persistent_v2_poison_transition_serializes_diagnostics() {
        let pool = v2_admission_test_pool(PersistentSessionConsumerConfig::default());
        let state = PersistentV2LaneState::new();
        state.healthy.store(true, Ordering::Release);
        pool.active.store(1, Ordering::Release);
        pool.healthy_active.store(1, Ordering::Release);
        let hook = Arc::new(PersistentV2PoisonAccountingHook::new());
        *pool
            .poison_accounting_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&hook));
        let transitioned = hook.transition_observed.notified();
        tokio::pin!(transitioned);
        transitioned.as_mut().enable();
        let lifetime = PersistentV2LaneLifetime {
            pool_connection: Arc::downgrade(&pool),
            state,
            _pool_width_admission: None,
            _physical_admission: None,
        };
        let poison = std::thread::spawn(move || lifetime.install_poison_ticket());
        transitioned.await;
        let diagnostic_started = hook.diagnostic_observed.notified();
        tokio::pin!(diagnostic_started);
        diagnostic_started.as_mut().enable();
        let diagnostics = tokio::spawn({
            let pool = Arc::clone(&pool);
            async move { pool.diagnostics() }
        });
        diagnostic_started.await;
        hook.resume();
        poison.join().expect("join poison accounting transition");
        assert_eq!(
            diagnostics
                .await
                .expect("join serialized poison diagnostics")
                .active,
            0,
            "diagnostics cannot observe an active poisoned source between state and accounting"
        );
    }

    #[tokio::test]
    async fn persistent_v2_prewarm_replaces_staged_lane_after_material_rotation() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("persistent-v2-staged-rotation-client");
        let server_identity = material_spiffe("persistent-v2-staged-rotation-server");
        let material = Arc::new(RotatableClientMaterial::new(client_identity.as_str()));
        let service = Arc::new(V2CountingRejectingTestConsumer {
            v2_calls: Arc::new(AtomicUsize::new(0)),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity],
            std::iter::empty(),
        )
        .expect("staged rotation authorizer");
        let (server, address) = SessionQuorumConsumerServer::new(
            service,
            material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for staged V2 rotation");
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_RECONNECT_JITTER,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("one-lane staged rotation configuration");
        let persistent = PersistentSessionConsumerClient::try_from_stateless(
            StatelessSessionConsumerClient::new(
                address,
                rustls_pki_types::ServerName::IpAddress(address.ip().into()),
                server_identity,
                scope(),
                material.config(),
            ),
            config,
        )
        .expect("persistent staged rotation client");
        let hook = Arc::new(PersistentV2PrewarmFinalPublicationHook::new());
        *persistent
            .v2_pool
            .prewarm_final_publication_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&hook));
        let observed = hook.observed.notified();
        tokio::pin!(observed);
        observed.as_mut().enable();
        let prewarm = tokio::spawn({
            let pool = Arc::clone(&persistent.v2_pool);
            async move { pool.prewarm().await }
        });
        observed.await;
        assert_eq!(
            persistent.v2_pool.setup_successes.load(Ordering::Acquire),
            1,
            "one staged lane authenticated before the material epoch changes"
        );
        material.rotate();
        hook.resume();
        prewarm
            .await
            .expect("join staged material rotation prewarm")
            .expect("stale staged lane is replaced before publication");
        assert_eq!(persistent.v2_diagnostics().active, 1);
        assert_eq!(persistent.v2_diagnostics().idle, 1);
        assert_eq!(
            persistent.v2_pool.setup_successes.load(Ordering::Acquire),
            2,
            "the stale staged lane retires and one replacement is admitted"
        );
        {
            let idle = persistent
                .v2_pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let PersistentV2PoolEntry::Lane(connection) =
                idle.front().expect("replacement lane is published")
            else {
                panic!("staged material rotation publishes a V2 lane");
            };
            assert_eq!(
                connection.admitted_material_epoch,
                persistent
                    .v2_pool
                    .client
                    .tls_config
                    .material_status()
                    .epoch()
            );
        }
        let _ = persistent.shutdown().await;
        server.abort_and_wait().await;
    }

    #[tokio::test(start_paused = true)]
    async fn persistent_v2_prewarm_does_not_publish_after_setup_deadline() {
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            Duration::from_millis(1),
            DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
            Duration::ZERO,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("one-lane staged deadline configuration");
        let pool = v2_admission_test_pool(config);
        let (commands, _actor) = mpsc::channel(1);
        let (retirement, _retirement_rx) = watch::channel(None);
        pool.idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(PersistentV2PoolEntry::Lane(PersistentV2Connection {
                commands,
                idle_deadline: tokio::time::Instant::now() + Duration::from_secs(1),
                retirement,
                admitted_generation: pool.client.reauthentication.generation(),
                admitted_material_epoch: pool.client.tls_config.material_status().epoch(),
                state: PersistentV2LaneState::new(),
            }));
        let hook = Arc::new(PersistentV2PrewarmFinalPublicationHook::new());
        *pool
            .prewarm_final_publication_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&hook));
        let observed = hook.observed.notified();
        tokio::pin!(observed);
        observed.as_mut().enable();
        let prewarm = tokio::spawn({
            let pool = Arc::clone(&pool);
            async move { pool.prewarm().await }
        });
        observed.await;
        tokio::time::advance(Duration::from_millis(1)).await;
        hook.resume();
        assert_eq!(
            prewarm.await.expect("join staged deadline prewarm"),
            Err(SessionConsumerClientError::Deadline),
            "a descheduled prewarm cannot publish a lane after its original setup deadline"
        );
        assert_eq!(
            pool.diagnostics().idle,
            1,
            "late prewarm publishes no new lane"
        );
    }

    #[tokio::test]
    async fn persistent_v2_counted_poison_debt_survives_prewarm_for_two_distinct_lanes() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("persistent-v2-counted-poison-client");
        let server_identity = material_spiffe("persistent-v2-counted-poison-server");
        let material = RotatableClientMaterial::new(client_identity.as_str());
        let calls = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(V2CountingRejectingTestConsumer {
            v2_calls: Arc::clone(&calls),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity],
            std::iter::empty(),
        )
        .expect("counted poison authorizer");
        let (server, address) = SessionQuorumConsumerServer::new(
            service,
            material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for counted poison lane");
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_RECONNECT_JITTER,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("one-lane counted poison configuration");
        let persistent = PersistentSessionConsumerClient::try_from_stateless(
            StatelessSessionConsumerClient::new(
                address,
                rustls_pki_types::ServerName::IpAddress(address.ip().into()),
                server_identity,
                scope(),
                material.config(),
            ),
            config,
        )
        .expect("persistent counted poison client");

        // Lane A poisons before any authenticated lane exists. Its debt must
        // survive the width-one prewarm that creates lane B.
        let first_state = PersistentV2LaneState::new();
        {
            let mut idle = persistent
                .v2_pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            PersistentV2LaneLifetime::install_poison_ticket_for_state_locked(
                &first_state,
                &persistent.v2_pool,
                &mut idle,
            );
        }
        persistent
            .prewarm_v2()
            .await
            .expect("prewarm preserves lane A debt while creating lane B");
        let second_state = {
            let idle = persistent
                .v2_pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(PersistentV2PoolEntry::Lane(connection)) = idle
                .iter()
                .find(|entry| matches!(entry, PersistentV2PoolEntry::Lane(_)))
            else {
                panic!("prewarm publishes lane B behind lane A debt");
            };
            Arc::clone(&connection.state)
        };
        {
            let mut idle = persistent
                .v2_pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            PersistentV2LaneLifetime::install_poison_ticket_for_state_locked(
                &second_state,
                &persistent.v2_pool,
                &mut idle,
            );
        }
        {
            let idle = persistent
                .v2_pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(matches!(
                idle.front(),
                Some(PersistentV2PoolEntry::Poison(debt)) if debt.get() == 2
            ));
        }
        let before = persistent.v2_diagnostics();
        assert_eq!(
            persistent.execute_v2(&v2_effectful_request(0x6a)).await,
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            }),
            "the first checkout consumes lane A debt before reconnect or Call write"
        );
        assert_eq!(
            persistent.execute_v2(&v2_effectful_request(0x6b)).await,
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            }),
            "the second checkout consumes lane B debt before reconnect or Call write"
        );
        let after = persistent.v2_diagnostics();
        assert_eq!(after.setup_successes, before.setup_successes);
        assert_eq!(after.reconnects, before.reconnects);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "poison emits no Call write"
        );
        let _ = persistent.shutdown().await;
        server.abort_and_wait().await;
    }

    #[test]
    fn persistent_v2_saturated_poison_debt_stays_fail_closed() {
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_RECONNECT_JITTER,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("one-lane saturated poison configuration");
        let pool = v2_admission_test_pool(config);
        pool.idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_front(PersistentV2PoolEntry::Poison(
                NonZeroUsize::new(usize::MAX).expect("usize maximum is nonzero"),
            ));

        assert!(pool.take_front_poison_or_idle_lane().is_err());
        assert!(pool.take_front_poison_or_idle_lane().is_err());
        assert!(matches!(
            pool.idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .front(),
            Some(PersistentV2PoolEntry::Poison(debt)) if debt.get() == usize::MAX
        ));
    }

    #[tokio::test]
    async fn stateless_v2_clone_admission_holds_each_slot_through_response() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("v2-clone-admission-client");
        let server_identity = material_spiffe("v2-clone-admission-server");
        let material = RotatableClientMaterial::new(client_identity.as_str());
        let entered = Arc::new(AtomicUsize::new(0));
        let changed = Arc::new(Notify::new());
        let release = Arc::new(Semaphore::new(0));
        let service = Arc::new(V2AdmissionBlockingTestConsumer {
            entered: Arc::clone(&entered),
            changed: Arc::clone(&changed),
            release: Arc::clone(&release),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity],
            std::iter::empty(),
        )
        .expect("V2 clone-admission authorizer");
        let (server, address) = SessionQuorumConsumerServer::new(
            service,
            material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .with_operation_timeout(Duration::from_secs(5))
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for V2 clone-admission test");
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let resolver_count = Arc::clone(&resolver_calls);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            resolver_count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(address) })
        });
        let client = StatelessSessionConsumerClient::new_with_resolver(
            resolver,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            material.config(),
        )
        .with_operation_timeout(Duration::from_secs(5));
        let mut calls = Vec::new();
        for nonce in 0_u8..u8::try_from(MAX_STATELESS_SESSION_CONSUMER_REQUEST_CONNECTIONS)
            .expect("fixed stateless V2 width fits u8")
        {
            let client = client.clone();
            calls.push(tokio::spawn(async move {
                client
                    .execute_v2(v2_effectful_request(0x70_u8.saturating_add(nonce)))
                    .await
            }));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let notified = changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if entered.load(Ordering::SeqCst)
                    == MAX_STATELESS_SESSION_CONSUMER_REQUEST_CONNECTIONS
                {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("every V2 slot reaches the blocked service");
        assert_eq!(
            resolver_calls.load(Ordering::SeqCst),
            MAX_STATELESS_SESSION_CONSUMER_REQUEST_CONNECTIONS
        );
        assert_eq!(
            client.execute_v2(v2_effectful_request(0x7f)).await,
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Overloaded,
            })
        );
        assert_eq!(
            resolver_calls.load(Ordering::SeqCst),
            MAX_STATELESS_SESSION_CONSUMER_REQUEST_CONNECTIONS,
            "the overloaded clone fails before resolution"
        );

        release.add_permits(MAX_STATELESS_SESSION_CONSUMER_REQUEST_CONNECTIONS);
        for call in calls {
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(2), call)
                    .await
                    .expect("released V2 Call remains bounded")
                    .expect("join released V2 caller"),
                Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { .. })
            ));
        }
        let resumed = tokio::spawn({
            let client = client.clone();
            async move { client.execute_v2(v2_effectful_request(0x80)).await }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let notified = changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if entered.load(Ordering::SeqCst)
                    == MAX_STATELESS_SESSION_CONSUMER_REQUEST_CONNECTIONS.saturating_add(1)
                {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("a released physical V2 slot admits another clone Call");
        release.add_permits(1);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), resumed)
                .await
                .expect("resumed V2 Call remains bounded")
                .expect("join resumed V2 caller"),
            Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { .. })
        ));
        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn persistent_v2_prewarm_reuses_and_reauthenticates_at_fixed_width() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("persistent-v2-client");
        let server_identity = material_spiffe("persistent-v2-server");
        let material = RotatableClientMaterial::new(client_identity.as_str());
        let calls = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(V2CountingRejectingTestConsumer {
            v2_calls: Arc::clone(&calls),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity.clone()],
            std::iter::empty(),
        )
        .expect("persistent V2 authorizer");
        let (server, address) = SessionQuorumConsumerServer::new(
            service,
            material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for persistent V2 lanes");
        let control = SessionReauthenticationControl::new();
        let stateless = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            material.config(),
        )
        .with_reauthentication_control(control.clone());
        let config = PersistentSessionConsumerConfig::try_new(
            MAX_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_RECONNECT_JITTER,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("fixed maximum pool config");
        let persistent = PersistentSessionConsumerClient::try_from_stateless(stateless, config)
            .expect("persistent client");

        // Both ALPN-isolated pools reach their legal maximum together. This
        // proves V2 cannot be starved by a fully prewarmed V1 pool.
        persistent.prewarm().await.expect("prewarm V1 width");
        persistent.prewarm_v2().await.expect("prewarm V2 width");
        let before = persistent.v2_diagnostics();
        assert_eq!(before.active, 16);
        assert_eq!(before.idle, 16);
        let readiness = persistent.v2_readiness().await;
        assert!(readiness.ready);
        assert_eq!(readiness.configured_request_connections, 16);
        assert_eq!(readiness.ready_request_connections, 16);

        let retired_lane = {
            let mut idle = persistent
                .v2_pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            idle.push_front(PersistentV2PoolEntry::poison());
            let lane = idle
                .iter()
                .rposition(|entry| matches!(entry, PersistentV2PoolEntry::Lane(_)))
                .expect("prewarmed pool contains an authenticated lane");
            idle.remove(lane)
                .expect("remove one authenticated lane while retaining poison debt")
        };
        drop(retired_lane);
        persistent
            .prewarm_v2()
            .await
            .expect("retained poison does not satisfy the missing lane deficit");
        let poison_readiness = persistent.v2_readiness().await;
        assert!(
            !poison_readiness.ready,
            "retained front poison prevents immediate call readiness"
        );
        assert_eq!(poison_readiness.configured_request_connections, 16);
        assert_eq!(poison_readiness.ready_request_connections, 15);
        {
            let idle = persistent
                .v2_pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(
                idle.iter()
                    .filter(|entry| matches!(entry, PersistentV2PoolEntry::Lane(_)))
                    .count(),
                16,
                "prewarm restores exact authenticated lane width"
            );
            assert!(matches!(
                idle.front(),
                Some(PersistentV2PoolEntry::Poison(_))
            ));
        }
        let before_poison_checkout = persistent.v2_diagnostics();
        assert_eq!(
            persistent.execute_v2(&v2_effectful_request(0x91)).await,
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            }),
            "retained poison stays front-priority after width restoration"
        );
        let after_poison_checkout = persistent.v2_diagnostics();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "poison emits no Call 2 bytes"
        );
        assert_eq!(
            after_poison_checkout.setup_successes, before_poison_checkout.setup_successes,
            "poison does not reconnect"
        );
        assert_eq!(
            after_poison_checkout.reused, before_poison_checkout.reused,
            "poison does not select an available lane"
        );

        for _ in 0..2 {
            assert_eq!(
                persistent
                    .execute_v2(&SessionConsumerV2Request::new(
                        scope(),
                        SessionConsumerV2Operation::FencedTransitionV2Capability,
                    ))
                    .await,
                Ok(SessionConsumerV2Response::Rejected(
                    SessionConsumerRejection::Unavailable
                ))
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(persistent.v2_diagnostics().reused >= 2);

        control
            .request_reauthentication()
            .expect("advance the shared reauthentication generation");
        persistent
            .prewarm_v2()
            .await
            .expect("replace stale V2 lanes under the fixed width");
        let after = persistent.v2_diagnostics();
        assert_eq!(after.active, 16);
        assert_eq!(after.idle, 16);
        assert!(after.setup_successes >= before.setup_successes.saturating_add(16));
        let _ = persistent.shutdown().await;
        assert_eq!(persistent.v2_diagnostics().active, 0);
        assert_eq!(
            persistent.v2_pool.actor_lanes.available_permits(),
            config.request_connections,
            "shutdown returns every pool-local actor-width permit"
        );
        assert_eq!(
            persistent
                .v2_pool
                .client
                .physical_admission
                .v2_requests
                .available_permits(),
            MAX_STATELESS_SESSION_CONSUMER_REQUEST_CONNECTIONS,
            "shutdown returns every global V2 physical admission"
        );
        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn persistent_v2_width_one_pool_uses_correlations_one_then_two() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("persistent-v2-correlation-client");
        let server_identity = material_spiffe("persistent-v2-correlation-server");
        let material = RotatableClientMaterial::new(client_identity.as_str());
        let calls = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(V2CountingRejectingTestConsumer {
            v2_calls: Arc::clone(&calls),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity],
            std::iter::empty(),
        )
        .expect("correlation authorizer");
        let (server, address) = SessionQuorumConsumerServer::new(
            service,
            material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for correlation sequence");
        let stateless = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            material.config(),
        );
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_RECONNECT_JITTER,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("one-lane correlation config");
        let persistent = PersistentSessionConsumerClient::try_from_stateless(stateless, config)
            .expect("one-lane correlation client");
        persistent
            .prewarm_v2()
            .await
            .expect("prewarm one exact correlation lane");
        let request = SessionConsumerV2Request::new(
            scope(),
            SessionConsumerV2Operation::FencedTransitionV2Capability,
        );
        let expected = Ok(SessionConsumerV2Response::Rejected(
            SessionConsumerRejection::Unavailable,
        ));
        assert_eq!(persistent.execute_v2(&request).await, expected.clone());
        assert_eq!(persistent.execute_v2(&request).await, expected);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            persistent.v2_diagnostics(),
            super::PersistentSessionConsumerV2Diagnostics {
                setup_successes: 1,
                reused: 2,
                reconnects: 0,
                active: 1,
                idle: 1,
            },
            "the same server-enforced lane accepts correlation 1 then 2"
        );
        let _ = persistent.shutdown().await;
        server.abort_and_wait().await;
    }

    #[tokio::test(start_paused = true)]
    async fn persistent_v2_published_lane_reuses_until_material_rotation_deadline() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("persistent-v2-published-rotation-client");
        let server_identity = material_spiffe("persistent-v2-published-rotation-server");
        let material = Arc::new(RotatableClientMaterial::new(client_identity.as_str()));
        let client_config = material.config();
        let lifecycle = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(30),
            Duration::from_secs(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .expect("bounded published V2 material rotation lifecycle");
        let rotation_jitter = client_config
            .begin_handshake()
            .expect("published V2 rotation handshake snapshot")
            .consumer_rotation_jitter(&server_identity)
            .min(lifecycle.rotation_jitter());
        assert!(
            !rotation_jitter.is_zero(),
            "the fixed authenticated V2 edge must exercise cooperative material reuse"
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(V2CountingRejectingTestConsumer {
            v2_calls: Arc::clone(&calls),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity],
            std::iter::empty(),
        )
        .expect("published V2 rotation authorizer");
        let (server, address) = SessionQuorumConsumerServer::new(
            service,
            material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for published V2 rotation");
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_RECONNECT_JITTER,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("one-lane published V2 rotation configuration");
        let persistent = PersistentSessionConsumerClient::try_from_stateless(
            StatelessSessionConsumerClient::new(
                address,
                rustls_pki_types::ServerName::IpAddress(address.ip().into()),
                server_identity,
                scope(),
                client_config,
            )
            .with_connection_lifecycle(lifecycle),
            config,
        )
        .expect("published V2 rotation client");
        let request = SessionConsumerV2Request::new(
            scope(),
            SessionConsumerV2Operation::FencedTransitionV2Capability,
        );
        let expected = Ok(SessionConsumerV2Response::Rejected(
            SessionConsumerRejection::Unavailable,
        ));

        assert_eq!(persistent.execute_v2(&request).await, expected.clone());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(persistent.v2_diagnostics().setup_successes, 1);

        material.rotate();
        tokio::time::advance(
            rotation_jitter
                .checked_sub(Duration::from_nanos(1))
                .expect("nonzero material jitter exceeds one nanosecond"),
        )
        .await;
        let connection = persistent
            .v2_pool
            .take_front_poison_or_idle_lane()
            .expect("a published V2 lane is not poison")
            .expect("the published V2 socket remains reusable before its deadline");
        assert_eq!(
            persistent.v2_diagnostics(),
            super::PersistentSessionConsumerV2Diagnostics {
                setup_successes: 1,
                reused: 0,
                reconnects: 0,
                active: 1,
                idle: 0,
            },
            "checking out the published socket before its deadline changes no setup or dispatch count"
        );
        persistent
            .v2_pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(PersistentV2PoolEntry::Lane(connection));

        let retired = persistent.v2_pool.drained_notify.notified();
        tokio::pin!(retired);
        retired.as_mut().enable();
        tokio::time::advance(Duration::from_nanos(1)).await;
        retired.await;
        assert_eq!(persistent.execute_v2(&request).await, expected);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            persistent.v2_diagnostics().setup_successes,
            2,
            "the post-deadline call reconnects only after the actor retires its published lane"
        );
        let _ = persistent.shutdown().await;
        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn v2_alpn_dispatches_execute_v2_and_rejects_a_revision_three_hello() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("v2-lane-client");
        let server_identity = material_spiffe("v2-lane-server");
        let client_material = RotatableClientMaterial::new(client_identity.as_str());
        let v2_calls = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(V2CountingRejectingTestConsumer {
            v2_calls: Arc::clone(&v2_calls),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity.clone()],
            std::iter::empty(),
        )
        .expect("V2 lane authorizer");
        let (server, address) = SessionQuorumConsumerServer::new(
            service,
            client_material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for V2 lane");
        let client = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            client_material.config(),
        );

        // The established revision-3 lane remains served by the same
        // listener and never dispatches through execute_v2.
        let v1_request = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::from_bytes([0x71; 16]),
            SessionConsumerOperation::Capabilities,
        );
        assert_eq!(
            client.execute(v1_request).await,
            Ok(SessionConsumerResponse::Rejected(
                SessionConsumerRejection::Unavailable,
            ))
        );
        assert_eq!(v2_calls.load(Ordering::SeqCst), 0);

        let v2_request = SessionConsumerV2Request::new(
            scope(),
            SessionConsumerV2Operation::FencedTransitionV2Capability,
        );
        assert_eq!(
            client.execute_v2(v2_request).await,
            Ok(SessionConsumerV2Response::Rejected(
                SessionConsumerRejection::Unavailable
            ))
        );
        assert_eq!(v2_calls.load(Ordering::SeqCst), 1);

        // An ALPN-V2 TLS connection that sends a revision-3 bootstrap must
        // receive no acknowledgement. The matching Hello shape is deliberate
        // here: it proves the authenticated revision check, rather than a
        // decoder accident, closes the cross-revision lane.
        let tcp = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect raw V2 TLS client");
        let handshake = client_material
            .config()
            .begin_handshake()
            .expect("V2 client handshake snapshot");
        let connector = tokio_rustls::TlsConnector::from(super::consumer_client_tls_config_v2(
            handshake.rustls_config(),
        ));
        let mut tls = connector
            .connect(
                rustls_pki_types::ServerName::IpAddress(address.ip().into()),
                tcp,
            )
            .await
            .expect("complete V2 TLS handshake");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(super::SESSION_QUORUM_CONSUMER_V2_ALPN)
        );
        super::write_frame_bounded_until(
            &mut tls,
            &ConsumerWireRequest::Hello(ConsumerHello {
                transport_revision: super::SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
                scope: scope(),
                response_frame_size: u32::try_from(super::MAX_NEGOTIATED_FRAME_SIZE)
                    .expect("test frame size fits u32"),
            }),
            super::MAX_NEGOTIATED_FRAME_SIZE,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect("write cross-revision Hello");
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            super::read_consumer_frame::<_, super::ConsumerV2WireResponse>(
                &mut tls,
                super::MAX_NEGOTIATED_FRAME_SIZE,
            ),
        )
        .await;
        assert!(
            !matches!(response, Ok(Ok(super::ConsumerV2WireResponse::HelloAck(_)))),
            "revision three bootstrap cannot publish the V2 lane"
        );
        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn v2_server_final_admission_rejects_stale_material_before_hello_ack() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("v2-final-admission-client");
        let server_identity = material_spiffe("v2-final-admission-server");
        let server_material = Arc::new(RotatableServerMaterial::new(server_identity.as_str()));
        let dispatches = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(V2CountingRejectingTestConsumer {
            v2_calls: Arc::clone(&dispatches),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity.clone()],
            std::iter::empty(),
        )
        .expect("V2 final-admission authorizer");
        let rotated_material = Arc::clone(&server_material);
        let (server, address) =
            SessionQuorumConsumerServer::new(service, server_material.config(), authorizer)
                .with_final_admission_test_hook(Arc::new(move || rotated_material.rotate()))
                .listen("127.0.0.1:0".parse().expect("loopback address"))
                .await
                .expect("listen for V2 final-admission race");
        let client = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            server_material.trusted_client_config(client_identity.as_str()),
        );

        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                client.execute_v2(SessionConsumerV2Request::new(
                    scope(),
                    SessionConsumerV2Operation::FencedTransitionV2Capability,
                )),
            )
            .await
            .expect("stale V2 admission stays bounded"),
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Unavailable,
            }),
            "a material epoch change at the final admission boundary publishes no V2 HelloAck"
        );
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);
        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn v2_dispatched_call_closes_on_explicit_reauthentication_without_rejection() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("v2-reauth-client");
        let server_identity = material_spiffe("v2-reauth-server");
        let material = RotatableClientMaterial::new(client_identity.as_str());
        let entered = Arc::new(Notify::new());
        let service = Arc::new(V2BlockingTestConsumer {
            entered: Arc::clone(&entered),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity.clone()],
            std::iter::empty(),
        )
        .expect("V2 reauthentication authorizer");
        let reauthentication = SessionReauthenticationControl::new();
        let lifecycle = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::ZERO,
        )
        .expect("short V2 reauthentication lifecycle");
        let (server, address) = SessionQuorumConsumerServer::new(
            service,
            material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .with_connection_lifecycle(lifecycle)
        .with_reauthentication_control(reauthentication.clone())
        .with_operation_timeout(Duration::from_millis(500))
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for V2 reauthentication test");
        let client = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            material.config(),
        )
        .with_operation_timeout(Duration::from_secs(5));
        let request = v2_effectful_request(0x81);
        let request_id = request.request_id().expect("V2 call has a full ID");
        let call = tokio::spawn(async move { client.execute_v2(request).await });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("V2 call reached the effectful service boundary");
        reauthentication
            .request_reauthentication()
            .expect("advance shared V2 reauthentication generation");
        let result = tokio::time::timeout(Duration::from_secs(1), call)
            .await
            .expect("reauthenticated V2 lane closes promptly")
            .expect("join V2 caller");
        assert_eq!(
            result,
            Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id })
        );
        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn stateless_v2_client_reauthentication_after_call_bytes_is_outcome_unknown() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("stateless-v2-client-reauth-client");
        let server_identity = material_spiffe("stateless-v2-client-reauth-server");
        let material = RotatableClientMaterial::new(client_identity.as_str());
        let entered = Arc::new(Notify::new());
        let service = Arc::new(V2BlockingTestConsumer {
            entered: Arc::clone(&entered),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity.clone()],
            std::iter::empty(),
        )
        .expect("stateless V2 client reauthentication authorizer");
        let (server, address) = SessionQuorumConsumerServer::new(
            service,
            material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .with_operation_timeout(Duration::from_secs(5))
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for stateless V2 client reauthentication test");
        let reauthentication = SessionReauthenticationControl::new();
        let lifecycle = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::ZERO,
        )
        .expect("short client V2 reauthentication lifecycle");
        let client = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            material.config(),
        )
        .with_connection_lifecycle(lifecycle)
        .with_reauthentication_control(reauthentication.clone())
        .with_operation_timeout(Duration::from_secs(5));
        let request = v2_effectful_request(0x86);
        let request_id = request
            .request_id()
            .expect("effectful V2 request has its ID");
        let call = tokio::spawn(async move { client.execute_v2(request).await });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("stateless V2 Call reached the effectful service boundary");
        reauthentication
            .request_reauthentication()
            .expect("advance client reauthentication generation after Call bytes");
        let result = tokio::time::timeout(Duration::from_secs(1), call)
            .await
            .expect("client reauthentication retires the stateless V2 Call")
            .expect("join stateless V2 client caller");
        assert!(matches!(
            result,
            Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown {
                request_id: recovered,
            }) if recovered == request_id
        ));
        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn v2_dispatched_call_closes_on_listener_cancellation_without_rejection() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("v2-cancel-client");
        let server_identity = material_spiffe("v2-cancel-server");
        let material = RotatableClientMaterial::new(client_identity.as_str());
        let entered = Arc::new(Notify::new());
        let service = Arc::new(V2BlockingTestConsumer {
            entered: Arc::clone(&entered),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity.clone()],
            std::iter::empty(),
        )
        .expect("V2 cancellation authorizer");
        let (server, address) = SessionQuorumConsumerServer::new(
            service,
            material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .with_operation_timeout(Duration::from_secs(5))
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for V2 cancellation test");
        let client = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            material.config(),
        )
        .with_operation_timeout(Duration::from_secs(5));
        let request = v2_effectful_request(0x85);
        let request_id = request.request_id().expect("V2 call has a full ID");
        let call = tokio::spawn(async move { client.execute_v2(request).await });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("V2 cancellation call was dispatched");
        server.abort();
        let result = tokio::time::timeout(Duration::from_secs(1), call)
            .await
            .expect("listener cancellation closes the dispatched V2 lane")
            .expect("join V2 caller");
        assert_eq!(
            result,
            Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id })
        );
        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn v2_dispatched_call_drains_on_material_epoch_change() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("v2-material-client");
        let server_identity = material_spiffe("v2-material-server");
        let material = Arc::new(RotatableServerMaterial::new(server_identity.as_str()));
        let entered = Arc::new(Notify::new());
        let service = Arc::new(V2BlockingTestConsumer {
            entered: Arc::clone(&entered),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity.clone()],
            std::iter::empty(),
        )
        .expect("V2 material-rotation authorizer");
        let lifecycle = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::ZERO,
        )
        .expect("short V2 material drain lifecycle");
        let (server, address) =
            SessionQuorumConsumerServer::new(service, material.config(), authorizer)
                .with_connection_lifecycle(lifecycle)
                .with_operation_timeout(Duration::from_millis(500))
                .listen("127.0.0.1:0".parse().expect("loopback address"))
                .await
                .expect("listen for V2 material-rotation test");
        let client = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            material.trusted_client_config(client_identity.as_str()),
        )
        .with_operation_timeout(Duration::from_secs(5));
        let request = v2_effectful_request(0x84);
        let request_id = request.request_id().expect("V2 call has a full ID");
        let call = tokio::spawn(async move { client.execute_v2(request).await });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("V2 material-rotation call was dispatched");
        material.rotate();
        let result = tokio::time::timeout(Duration::from_secs(1), call)
            .await
            .expect("material rotation closes the dispatched V2 lane")
            .expect("join V2 caller");
        assert_eq!(
            result,
            Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id })
        );
        server.abort_and_wait().await;
    }

    #[tokio::test(start_paused = true)]
    async fn v2_slow_effectful_dispatch_deadline_closes_without_unavailable_rejection() {
        let entered = Arc::new(Notify::new());
        let service = Arc::new(V2BlockingTestConsumer {
            entered: Arc::clone(&entered),
        });
        let request = v2_effectful_request(0x82);
        let request_id = request.request_id().expect("V2 call has a full ID");
        let identity = SessionConsumerIdentity::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/consumer/instance/v2-deadline",
        )
        .expect("valid redaction-safe V2 deadline identity");
        let entered_call = entered.notified();
        tokio::pin!(entered_call);
        entered_call.as_mut().enable();
        let execute = service.execute_v2(&identity, request.clone());
        tokio::pin!(execute);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
        let (dispatch, ()) = tokio::join!(
            await_consumer_v2_dispatch_until(execute.as_mut(), deadline),
            async {
                entered_call.await;
                tokio::time::advance(Duration::from_millis(20)).await;
            }
        );
        assert!(matches!(dispatch, ConsumerV2DispatchResult::DeadlineClose));
        assert_eq!(
            v2_persistent_error(&request, true, SessionConsumerClientError::Unavailable,),
            PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id }
        );
    }

    #[tokio::test]
    async fn v2_maximum_authentication_age_drains_a_dispatched_lane() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("v2-age-client");
        let server_identity = material_spiffe("v2-age-server");
        let material = RotatableClientMaterial::new(client_identity.as_str());
        let entered = Arc::new(Notify::new());
        let service = Arc::new(V2BlockingTestConsumer {
            entered: Arc::clone(&entered),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity.clone()],
            std::iter::empty(),
        )
        .expect("V2 maximum-age authorizer");
        let lifecycle = ConnectionLifecyclePolicy::try_new(
            Duration::from_millis(150),
            Duration::from_millis(5),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::ZERO,
        )
        .expect("short V2 maximum-age lifecycle");
        let (server, address) = SessionQuorumConsumerServer::new(
            service,
            material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .with_connection_lifecycle(lifecycle)
        .with_operation_timeout(Duration::from_millis(500))
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for V2 maximum-age test");
        let client = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            material.config(),
        )
        .with_operation_timeout(Duration::from_secs(5));
        let request = v2_effectful_request(0x83);
        let request_id = request.request_id().expect("V2 call has a full ID");
        let call = tokio::spawn(async move { client.execute_v2(request).await });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("V2 maximum-age call was dispatched");
        let result = tokio::time::timeout(Duration::from_secs(1), call)
            .await
            .expect("maximum authentication age retires the V2 lane")
            .expect("join V2 caller");
        assert_eq!(
            result,
            Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id })
        );
        server.abort_and_wait().await;
    }

    async fn authenticated_consumer_physical_create_request(
        request_id: u8,
        payload_len: usize,
    ) -> FencedTransitionRequest {
        let key = SessionKey {
            tenant: TenantId::new("consumer-physical-admission").expect("test tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"consumer-physical-admission")
                .try_into()
                .expect("bounded stable ID"),
        };
        let owner = OwnerId::new("consumer-physical-admission-owner").expect("test owner");
        let lease = FencedTransitionLease::acquire(
            key.clone(),
            owner.clone(),
            FenceToken::new(0),
            Duration::from_secs(30),
        )
        .expect("bounded acquire");
        let mut record = StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner,
            fence: lease.committed_fence().expect("committed fence"),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("consumer-physical-admission"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([0]),
        };
        let provider = MemoryKeyProvider::new();
        provider
            .insert_active_key(
                KeyId::new("consumer-physical-admission-key").expect("test key ID"),
                KeyPurpose::Session,
                record.key.tenant.clone(),
                Zeroizing::new([0x85; AES_256_GCM_SIV_KEY_LEN]),
            )
            .expect("install test key");
        let envelope_overhead =
            EncryptedSessionPayload::encrypt(&provider, &record, "consumer-physical-admission")
                .await
                .expect("seal envelope probe")
                .len()
                .checked_sub(1)
                .expect("envelope includes the probe byte");
        record.payload =
            EncryptedSessionPayload::new(vec![
                0x86;
                payload_len.checked_sub(envelope_overhead).expect(
                    "payload budget exceeds envelope overhead"
                )
            ]);
        record.payload =
            EncryptedSessionPayload::encrypt(&provider, &record, "consumer-physical-admission")
                .await
                .expect("seal exact envelope");
        assert_eq!(record.payload.len(), payload_len);
        FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([request_id; 16]),
            lease,
            FencedTransitionMutation::create(record),
        )
        .expect("physical create request")
    }

    async fn authenticated_consumer_record_free_request(
        request_id: u8,
        refresh: bool,
    ) -> FencedTransitionRequest {
        let key = SessionKey {
            tenant: TenantId::new("consumer-record-free-admission").expect("test tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"consumer-record-free-admission")
                .try_into()
                .expect("bounded stable ID"),
        };
        let lease = FakeSessionBackend::new()
            .acquire(
                &key,
                OwnerId::new("consumer-record-free-admission-owner").expect("test owner"),
                Duration::from_secs(60),
            )
            .await
            .expect("lease");
        let mutation = if refresh {
            FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::from_secs(30))
                .expect("refresh")
        } else {
            FencedTransitionMutation::delete(Generation::new(1))
        };
        FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([request_id; 16]),
            FencedTransitionLease::renew(lease, Duration::from_secs(30)).expect("renewal"),
            mutation,
        )
        .expect("record-free request")
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

    struct FailOnceCountingWriter {
        accepted: usize,
        fail_after: Option<usize>,
        fail_flush: bool,
        failed: bool,
        write_polls_after_failure: usize,
        flush_polls_after_failure: usize,
    }

    impl AsyncWrite for FailOnceCountingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.failed {
                self.write_polls_after_failure = self.write_polls_after_failure.saturating_add(1);
                self.accepted = self.accepted.saturating_add(bytes.len());
                return Poll::Ready(Ok(bytes.len()));
            }
            if let Some(fail_after) = self.fail_after {
                if self.accepted >= fail_after {
                    self.failed = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "controlled one-shot write failure",
                    )));
                }
                let accepted = bytes.len().min(fail_after - self.accepted);
                self.accepted = self.accepted.saturating_add(accepted);
                return Poll::Ready(Ok(accepted));
            }
            self.accepted = self.accepted.saturating_add(bytes.len());
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            if self.failed {
                self.flush_polls_after_failure = self.flush_polls_after_failure.saturating_add(1);
                return Poll::Ready(Ok(()));
            }
            if self.fail_flush {
                self.failed = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "controlled one-shot flush failure",
                )));
            }
            Poll::Ready(Ok(()))
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

    struct NotifyingPendingWriter {
        polled: Arc<Notify>,
    }

    impl AsyncWrite for NotifyingPendingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.polled.notify_waiters();
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct FlushGate {
        polled: Notify,
        released: AtomicBool,
        waker: StdMutex<Option<std::task::Waker>>,
    }

    impl FlushGate {
        fn release(&self) {
            self.released.store(true, Ordering::Release);
            if let Some(waker) = self
                .waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                waker.wake();
            }
        }
    }

    struct AcceptThenParkFlushWriter {
        accepted: Arc<AtomicUsize>,
        gate: Arc<FlushGate>,
    }

    impl AsyncWrite for AcceptThenParkFlushWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.accepted.fetch_add(bytes.len(), Ordering::SeqCst);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.gate.polled.notify_waiters();
            if self.gate.released.load(Ordering::Acquire) {
                return Poll::Ready(Ok(()));
            }
            *self
                .gate
                .waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(context.waker().clone());
            if self.gate.released.load(Ordering::Acquire) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct RotateThenReadyWriter {
        material: Arc<RotatableServerMaterial>,
        rotated: bool,
    }

    impl AsyncWrite for RotateThenReadyWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if !self.rotated {
                self.material.rotate();
                self.rotated = true;
            }
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
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

    struct DeclaredFrameReader {
        prefix: [u8; 4],
        offset: usize,
        requested: Arc<StdMutex<Vec<usize>>>,
    }

    impl AsyncRead for DeclaredFrameReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.requested
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(buffer.remaining());
            if self.offset == self.prefix.len() {
                return Poll::Pending;
            }
            let remaining = &self.prefix[self.offset..];
            let amount = remaining.len().min(buffer.remaining());
            buffer.put_slice(&remaining[..amount]);
            self.offset = self.offset.saturating_add(amount);
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct AggregateFrameTracker {
        live: AtomicUsize,
        high_water: AtomicUsize,
        requested_bytes: AtomicUsize,
        changed: Notify,
    }

    struct AggregateDeclaredFrameReader {
        prefix: [u8; 4],
        offset: usize,
        tracker: Arc<AggregateFrameTracker>,
        payload_requested: bool,
    }

    impl AsyncRead for AggregateDeclaredFrameReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.offset < self.prefix.len() {
                let remaining = &self.prefix[self.offset..];
                let amount = remaining.len().min(buffer.remaining());
                buffer.put_slice(&remaining[..amount]);
                self.offset = self.offset.saturating_add(amount);
                return Poll::Ready(Ok(()));
            }
            if !self.payload_requested {
                assert_eq!(buffer.remaining(), FRAME_READ_CHUNK_BYTES);
                self.payload_requested = true;
                self.tracker
                    .requested_bytes
                    .fetch_add(buffer.remaining(), Ordering::SeqCst);
                let live = self.tracker.live.fetch_add(1, Ordering::SeqCst) + 1;
                self.tracker.high_water.fetch_max(live, Ordering::SeqCst);
                self.tracker.changed.notify_waiters();
            }
            Poll::Pending
        }
    }

    impl Drop for AggregateDeclaredFrameReader {
        fn drop(&mut self) {
            if self.payload_requested {
                self.tracker.live.fetch_sub(1, Ordering::SeqCst);
                self.tracker.changed.notify_waiters();
            }
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

    fn v2_admission_test_pool(
        config: PersistentSessionConsumerConfig,
    ) -> Arc<PersistentSessionConsumerV2Pool> {
        let (client, _material) = stateless_test_client(SessionReauthenticationControl::new());
        let (shutdown_forced_tx, _) = watch::channel(false);
        Arc::new(PersistentSessionConsumerV2Pool {
            client,
            config,
            lanes: Arc::new(Semaphore::new(config.request_connections)),
            actor_lanes: Arc::new(Semaphore::new(config.request_connections)),
            pending: Arc::new(Semaphore::new(
                config
                    .request_connections
                    .saturating_add(config.pending_calls),
            )),
            prewarm: Arc::new(Semaphore::new(1)),
            idle: StdMutex::new(VecDeque::new()),
            shutdown: AtomicBool::new(false),
            shutdown_forced_tx,
            shutdown_io: Arc::new(PersistentConsumerIoBarrier::new()),
            shutdown_complete: AtomicBool::new(false),
            shutdown_complete_notify: Notify::new(),
            activity: StdMutex::new(PersistentV2Activity {
                calls: 0,
                prewarms: 0,
            }),
            drained_notify: Notify::new(),
            idle_reaper_started: AtomicBool::new(false),
            idle_reaper_armed: Notify::new(),
            idle_reaper_processed: Notify::new(),
            shutdown_activity_wait_armed: Notify::new(),
            positive_read_reservation_hook: StdMutex::new(None),
            prewarm_final_publication_hook: StdMutex::new(None),
            poison_accounting_hook: StdMutex::new(None),
            setup_successes: AtomicU64::new(0),
            reused: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            active: AtomicU64::new(0),
            healthy_active: AtomicU64::new(0),
            poisoned: AtomicU64::new(0),
            live_accounting: StdMutex::new(()),
        })
    }

    fn independent_pool_admission_test_client() -> (
        PersistentSessionConsumerClient,
        PersistentSessionConsumerConfig,
    ) {
        let config = PersistentSessionConsumerConfig::try_new(
            2,
            3,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
            Duration::ZERO,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("independent fixed-pool test config");
        let (stateless, _material) = stateless_test_client(SessionReauthenticationControl::new());
        (
            PersistentSessionConsumerClient::try_from_stateless(stateless, config)
                .expect("valid independent fixed-pool client"),
            config,
        )
    }

    fn seed_v2_idle_lanes(
        client: &PersistentSessionConsumerClient,
        receivers: &mut Vec<mpsc::Receiver<PersistentV2LaneCall>>,
    ) {
        let idle_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let mut idle = client
            .v2_pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for _ in 0..client.v2_pool.config.request_connections {
            let (commands, receiver) = mpsc::channel(1);
            let (retirement, _retirement_rx) = watch::channel(None);
            receivers.push(receiver);
            idle.push_back(PersistentV2PoolEntry::Lane(PersistentV2Connection {
                commands,
                idle_deadline,
                retirement,
                admitted_generation: client.v2_pool.client.reauthentication.generation(),
                admitted_material_epoch: client.v2_pool.client.tls_config.material_status().epoch(),
                state: PersistentV2LaneState::new(),
            }));
        }
    }

    async fn persistent_v2_idle_declared_frame_requests(declared: u32) -> Vec<usize> {
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            1,
            Duration::ZERO,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("one-lane declared-frame pool");
        let pool = v2_admission_test_pool(config);
        let established = tokio::time::Instant::now();
        let lifecycle = ConnectionLifecycle::new(
            pool.client.lifecycle_policy,
            established,
            None,
            None,
            pool.client.reauthentication.generation(),
            Some(pool.client.tls_config.material_status().epoch()),
        )
        .expect("valid declared-frame lifecycle");
        let requested = Arc::new(StdMutex::new(Vec::new()));
        let (commands, command_rx) = mpsc::channel(1);
        let (_retirement, actor_retirement) = watch::channel(None);
        let physical = Arc::new(Semaphore::new(1));
        pool.active.store(1, Ordering::Relaxed);
        let drained = pool.drained_notify.notified();
        tokio::pin!(drained);
        drained.as_mut().enable();
        let actor = tokio::spawn(run_persistent_v2_lane(PersistentV2LaneActor {
            reader: Box::new(DeclaredFrameReader {
                prefix: declared.to_be_bytes(),
                offset: 0,
                requested: Arc::clone(&requested),
            }),
            writer: Box::new(tokio::io::sink()),
            request_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            lifecycle,
            rotation_jitter: Duration::ZERO,
            client: pool.client.clone(),
            reauthentication_changes: pool.client.reauthentication.subscribe(),
            material_changes: Some(pool.client.tls_config.subscribe_material_changes()),
            retirement: actor_retirement,
            forced: pool.shutdown_forced_tx.subscribe(),
            shutdown_io: Arc::clone(&pool.shutdown_io),
            commands: command_rx,
            lifetime: PersistentV2LaneLifetime {
                pool_connection: Arc::downgrade(&pool),
                state: PersistentV2LaneState::new(),
                _pool_width_admission: Some(
                    Arc::clone(&pool.actor_lanes)
                        .try_acquire_owned()
                        .expect("reserve declared-frame pool width"),
                ),
                _physical_admission: Some(
                    Arc::clone(&physical)
                        .try_acquire_owned()
                        .expect("reserve declared-frame global admission"),
                ),
            },
        }));
        drained.await;
        actor.await.expect("join declared-frame actor");
        assert!(commands.is_closed());
        assert_eq!(pool.active.load(Ordering::Acquire), 0);
        assert_eq!(pool.actor_lanes.available_permits(), 1);
        assert!(Arc::clone(&physical).try_acquire_owned().is_ok());
        let idle = pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(matches!(
            idle.front(),
            Some(PersistentV2PoolEntry::Poison(_))
        ));
        drop(idle);
        Arc::try_unwrap(requested)
            .expect("declared-frame observer has one owner")
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[tokio::test]
    async fn persistent_v2_admission_is_fail_fast_and_pool_wait_bounded() {
        let config = |pending_calls| {
            PersistentSessionConsumerConfig::try_new(
                1,
                pending_calls,
                Duration::from_millis(25),
                1,
                Duration::from_millis(100),
                1,
                Duration::ZERO,
                Duration::from_millis(100),
            )
            .expect("bounded V2 test config")
        };
        let zero = v2_admission_test_pool(config(0));
        let _active_pending = Arc::clone(&zero.pending)
            .try_acquire_owned()
            .expect("occupy the sole total-admission permit");
        let _active_lane = Arc::clone(&zero.lanes)
            .try_acquire_owned()
            .expect("occupy the sole lane");
        let started = tokio::time::Instant::now();
        assert!(matches!(
            zero.admit_call(started, started + Duration::from_secs(1))
                .await,
            Err(SessionConsumerClientError::Overloaded)
        ));
        assert!(started.elapsed() < Duration::from_millis(10));

        let queued = v2_admission_test_pool(config(1));
        let _active_pending = Arc::clone(&queued.pending)
            .try_acquire_owned()
            .expect("occupy the active call admission");
        let _active_lane = Arc::clone(&queued.lanes)
            .try_acquire_owned()
            .expect("occupy the only lane");
        let started = tokio::time::Instant::now();
        assert!(matches!(
            queued
                .admit_call(started, started + Duration::from_secs(1))
                .await,
            Err(SessionConsumerClientError::Overloaded)
        ));
        assert!(started.elapsed() >= Duration::from_millis(20));
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn full_v1_logical_admission_does_not_block_v2_admission_prewarm_or_readiness() {
        let (client, config) = independent_pool_admission_test_client();
        let mut v2_receivers = Vec::new();
        seed_v2_idle_lanes(&client, &mut v2_receivers);
        let v1_lanes = (0..config.request_connections)
            .map(|_| {
                Arc::clone(&client.pool.lanes)
                    .try_acquire_owned()
                    .expect("hold every V1 logical lane")
            })
            .collect::<Vec<_>>();
        let v1_pending = (0..config
            .request_connections
            .saturating_add(config.pending_calls))
            .map(|_| {
                Arc::clone(&client.pool.pending)
                    .try_acquire_owned()
                    .expect("fill every V1 pending admission")
            })
            .collect::<Vec<_>>();

        let started = tokio::time::Instant::now();
        let v2_admission = client
            .v2_pool
            .admit_call(started, started + Duration::from_secs(1))
            .await
            .expect("V2 admission remains independent from a full V1 pool");
        drop(v2_admission);
        client
            .prewarm_v2()
            .await
            .expect("V2 prewarm remains independent from a full V1 pool");
        assert!(
            client.v2_readiness().await.ready,
            "V2 readiness remains true with all V2 fixed lanes idle"
        );

        drop((v1_pending, v1_lanes, v2_receivers));
    }

    #[tokio::test(start_paused = true)]
    async fn full_v2_logical_admission_does_not_block_v1_admission() {
        let (client, config) = independent_pool_admission_test_client();
        let v2_lanes = (0..config.request_connections)
            .map(|_| {
                Arc::clone(&client.v2_pool.lanes)
                    .try_acquire_owned()
                    .expect("hold every V2 logical lane")
            })
            .collect::<Vec<_>>();
        let v2_pending = (0..config
            .request_connections
            .saturating_add(config.pending_calls))
            .map(|_| {
                Arc::clone(&client.v2_pool.pending)
                    .try_acquire_owned()
                    .expect("fill every V2 pending admission")
            })
            .collect::<Vec<_>>();

        let started = tokio::time::Instant::now();
        let v1_admission = client
            .pool
            .admit_call(started, started + Duration::from_secs(1))
            .await
            .expect("V1 admission remains independent from a full V2 pool");
        drop(v1_admission);
        drop((v2_pending, v2_lanes));
    }

    #[test]
    fn persistent_v1_v2_pools_have_distinct_exact_logical_and_physical_caps() {
        let (client, config) = independent_pool_admission_test_client();
        assert!(
            !Arc::ptr_eq(&client.pool.lanes, &client.v2_pool.lanes)
                && !Arc::ptr_eq(&client.pool.pending, &client.v2_pool.pending),
            "V1 and V2 must not share logical admission semaphores"
        );

        let v1_lanes = (0..config.request_connections)
            .map(|_| Arc::clone(&client.pool.lanes).try_acquire_owned().unwrap())
            .collect::<Vec<_>>();
        assert!(Arc::clone(&client.pool.lanes).try_acquire_owned().is_err());
        let v2_lanes = (0..config.request_connections)
            .map(|_| {
                Arc::clone(&client.v2_pool.lanes)
                    .try_acquire_owned()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(Arc::clone(&client.v2_pool.lanes)
            .try_acquire_owned()
            .is_err());

        let pending_limit = config
            .request_connections
            .saturating_add(config.pending_calls);
        let v1_pending = (0..pending_limit)
            .map(|_| {
                Arc::clone(&client.pool.pending)
                    .try_acquire_owned()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(Arc::clone(&client.pool.pending)
            .try_acquire_owned()
            .is_err());
        let v2_pending = (0..pending_limit)
            .map(|_| {
                Arc::clone(&client.v2_pool.pending)
                    .try_acquire_owned()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(Arc::clone(&client.v2_pool.pending)
            .try_acquire_owned()
            .is_err());

        let v1_physical = (0..MAX_STATELESS_SESSION_CONSUMER_REQUEST_CONNECTIONS)
            .map(|_| {
                client
                    .pool
                    .client
                    .physical_admission
                    .try_acquire_v1()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(client
            .pool
            .client
            .physical_admission
            .try_acquire_v1()
            .is_err());
        let v2_physical = (0..MAX_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS)
            .map(|_| {
                client
                    .pool
                    .client
                    .physical_admission
                    .try_acquire_v2()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(client
            .pool
            .client
            .physical_admission
            .try_acquire_v2()
            .is_err());

        drop((
            v1_lanes,
            v2_lanes,
            v1_pending,
            v2_pending,
            v1_physical,
            v2_physical,
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn pool_admission_consumes_the_original_complete_operation_deadline() {
        let control = SessionReauthenticationControl::new();
        let (mut stateless, _material) = stateless_test_client(control);
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        stateless.resolve = Arc::new({
            let resolver_calls = Arc::clone(&resolver_calls);
            move || {
                let resolver_calls = Arc::clone(&resolver_calls);
                Box::pin(async move {
                    resolver_calls.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<io::Result<std::net::SocketAddr>>().await
                })
            }
        });
        stateless.operation_timeout = Duration::from_millis(240);
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            1,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            1,
            Duration::from_secs(1),
            1,
            Duration::ZERO,
            Duration::from_secs(1),
        )
        .expect("one-lane admission-deadline test config");
        let client = PersistentSessionConsumerClient::try_from_stateless(stateless, config)
            .expect("valid admission-deadline client");
        let _active_pending = Arc::clone(&client.pool.pending)
            .try_acquire_owned()
            .expect("hold one active-call admission");
        let active_lane = Arc::clone(&client.pool.lanes)
            .try_acquire_owned()
            .expect("hold the sole request lane");
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_millis(240);
        let request = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::from_bytes([3; 16]),
            SessionConsumerOperation::Capabilities,
        );
        let queued = client.execute(&request);
        tokio::pin!(queued);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(queued.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(
            client.pool.pending.available_permits(),
            0,
            "the queued call owns exactly one bounded pending admission"
        );
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);

        tokio::time::advance(Duration::from_millis(120)).await;
        drop(active_lane);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(queued.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_millis(120)).await;
        assert_eq!(
            queued.await,
            Err(PersistentSessionConsumerExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Deadline,
            })
        );
        assert_eq!(tokio::time::Instant::now(), deadline);
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
        let diagnostics = client.diagnostics().await;
        assert_eq!(diagnostics.setup_attempts, 1);
        assert_eq!(diagnostics.setup_failures, 1);
        assert_eq!(diagnostics.setup_successes, 0);
        assert_eq!(diagnostics.not_transmitted, 1);
        assert_eq!(diagnostics.deadline, 1);
        assert_eq!(diagnostics.overload, 0);
        assert_eq!(diagnostics.reconnects, 0);
        client.shutdown().await;
    }

    #[tokio::test]
    async fn persistent_v2_front_poison_linearizes_before_lane_selection() {
        let config = PersistentSessionConsumerConfig::try_new(
            2,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_RECONNECT_JITTER,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("ordered two-lane V2 test pool");
        let pool = v2_admission_test_pool(config);
        let (commands, _actor) = mpsc::channel(1);
        let (retirement, _retirement_rx) = watch::channel(None);
        {
            let mut idle = pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            idle.push_back(PersistentV2PoolEntry::poison());
            idle.push_back(PersistentV2PoolEntry::Lane(PersistentV2Connection {
                commands,
                idle_deadline: tokio::time::Instant::now() + Duration::from_secs(1),
                retirement,
                admitted_generation: pool.client.reauthentication.generation(),
                admitted_material_epoch: pool.client.tls_config.material_status().epoch(),
                state: PersistentV2LaneState::new(),
            }));
        }

        assert!(matches!(pool.take_front_poison_or_idle_lane(), Err(())));
        assert_eq!(pool.pending.available_permits(), 2);
        assert_eq!(pool.lanes.available_permits(), 2);
        assert!(matches!(pool.take_front_poison_or_idle_lane(), Ok(Some(_))));
    }

    #[test]
    fn persistent_v2_prewarm_setup_deadline_is_not_the_lane_wait_deadline() {
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            Duration::from_millis(25),
            1,
            Duration::from_millis(100),
            1,
            Duration::ZERO,
            Duration::from_millis(100),
        )
        .expect("bounded V2 test config");
        let mut pool = v2_admission_test_pool(config);
        Arc::get_mut(&mut pool)
            .expect("test pool has a single owner")
            .client
            .pre_request_connection_timeout = Some(Duration::from_millis(60));
        let started = tokio::time::Instant::now();
        let deadline = pool
            .setup_deadline(started, None)
            .expect("bounded setup deadline");
        assert!(deadline > started + config.pool_wait_timeout);
        assert_eq!(deadline, started + Duration::from_millis(60));
    }

    #[tokio::test]
    async fn persistent_v2_actor_declared_frame_allocation_is_lazy_and_oversize_safe() {
        let exact = persistent_v2_idle_declared_frame_requests(
            u32::try_from(MAX_NEGOTIATED_FRAME_SIZE).expect("frame cap fits u32"),
        )
        .await;
        assert_eq!(exact, vec![4, FRAME_READ_CHUNK_BYTES]);
        let oversized = persistent_v2_idle_declared_frame_requests(
            u32::try_from(MAX_NEGOTIATED_FRAME_SIZE)
                .expect("frame cap fits u32")
                .saturating_add(1),
        )
        .await;
        assert_eq!(
            oversized,
            vec![4],
            "an over-limit declaration is rejected before a payload buffer or read"
        );
    }

    #[tokio::test]
    async fn persistent_v2_declared_frame_aggregate_never_exceeds_actor_width() {
        let config = PersistentSessionConsumerConfig::try_new(
            2,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            1,
            Duration::ZERO,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("two-lane aggregate-frame pool");
        let mut pool = v2_admission_test_pool(config);
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let observed_resolver_calls = Arc::clone(&resolver_calls);
        Arc::get_mut(&mut pool)
            .expect("aggregate-frame pool has one owner")
            .client
            .resolve = Arc::new(move || {
            observed_resolver_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok("127.0.0.1:9".parse().expect("test socket address")) })
        });
        let tracker = Arc::new(AggregateFrameTracker::default());
        let physical = Arc::new(Semaphore::new(config.request_connections));
        let mut releases = Vec::new();
        let mut decoders = Vec::new();
        pool.active.store(
            u64::try_from(config.request_connections).expect("fixed width fits u64"),
            Ordering::Relaxed,
        );
        for _ in 0..config.request_connections {
            let (release, released) = oneshot::channel();
            releases.push(release);
            let tracker = Arc::clone(&tracker);
            let pool = Arc::clone(&pool);
            let physical = Arc::clone(&physical);
            decoders.push(tokio::spawn(async move {
                let lifetime = PersistentV2LaneLifetime {
                    pool_connection: Arc::downgrade(&pool),
                    state: PersistentV2LaneState::new(),
                    _pool_width_admission: Some(
                        Arc::clone(&pool.actor_lanes)
                            .try_acquire_owned()
                            .expect("reserve aggregate-frame pool width"),
                    ),
                    _physical_admission: Some(
                        physical
                            .try_acquire_owned()
                            .expect("reserve aggregate-frame global admission"),
                    ),
                };
                let mut reader = AggregateDeclaredFrameReader {
                    prefix: u32::try_from(MAX_NEGOTIATED_FRAME_SIZE)
                        .expect("frame cap fits u32")
                        .to_be_bytes(),
                    offset: 0,
                    tracker,
                    payload_requested: false,
                };
                {
                    let read =
                        crate::protocol::read_frame_payload(&mut reader, MAX_NEGOTIATED_FRAME_SIZE);
                    tokio::pin!(read);
                    std::future::poll_fn(|context| {
                        assert!(std::future::Future::poll(read.as_mut(), context).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    let _ = released.await;
                }
                drop(reader);
                drop(lifetime);
            }));
        }
        loop {
            let changed = tracker.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if tracker.live.load(Ordering::SeqCst) == config.request_connections {
                break;
            }
            changed.await;
        }
        assert_eq!(tracker.high_water.load(Ordering::SeqCst), 2);
        assert_eq!(
            tracker.requested_bytes.load(Ordering::SeqCst),
            config.request_connections * FRAME_READ_CHUNK_BYTES
        );
        assert_eq!(pool.actor_lanes.available_permits(), 0);

        let successor = pool.connect_until(tokio::time::Instant::now() + Duration::from_secs(5));
        tokio::pin!(successor);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(successor.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
        releases
            .remove(0)
            .send(())
            .expect("release first aggregate-frame decoder");
        decoders
            .remove(0)
            .await
            .expect("join released aggregate-frame decoder");
        assert!(successor.await.is_err());
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
        releases
            .remove(0)
            .send(())
            .expect("release final aggregate-frame decoder");
        decoders
            .remove(0)
            .await
            .expect("join final aggregate-frame decoder");
        assert_eq!(tracker.live.load(Ordering::SeqCst), 0);
        assert_eq!(tracker.high_water.load(Ordering::SeqCst), 2);
        assert_eq!(pool.active.load(Ordering::SeqCst), 0);
        assert_eq!(pool.actor_lanes.available_permits(), 2);
        assert!(Arc::clone(&physical).try_acquire_many_owned(2).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn persistent_v2_poison_and_reaper_add_no_timer_latency() {
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            1,
            Duration::ZERO,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("one-lane paused-clock poison pool");
        let pool = v2_admission_test_pool(config);
        pool.idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_front(PersistentV2PoolEntry::poison());
        let reaper_armed = pool.idle_reaper_armed.notified();
        tokio::pin!(reaper_armed);
        reaper_armed.as_mut().enable();
        let started = tokio::time::Instant::now();
        assert_eq!(
            pool.execute(&v2_effectful_request(0x72)).await,
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            })
        );
        assert_eq!(
            tokio::time::Instant::now(),
            started,
            "front-priority poison requires no timer advance"
        );
        reaper_armed.await;
        let (closed_commands, closed_actor) = mpsc::channel(1);
        drop(closed_actor);
        let (closed_retirement, _closed_retirement_rx) = watch::channel(None);
        {
            let mut idle = pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            idle.push_front(PersistentV2PoolEntry::poison());
            idle.push_back(PersistentV2PoolEntry::Lane(PersistentV2Connection {
                commands: closed_commands,
                idle_deadline: started + Duration::from_secs(1),
                retirement: closed_retirement,
                admitted_generation: pool.client.reauthentication.generation(),
                admitted_material_epoch: pool.client.tls_config.material_status().epoch(),
                state: PersistentV2LaneState::new(),
            }));
        }
        let reaper_processed = pool.idle_reaper_processed.notified();
        tokio::pin!(reaper_processed);
        reaper_processed.as_mut().enable();
        tokio::time::advance(Duration::from_millis(100)).await;
        reaper_processed.await;
        let idle = pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(matches!(
            idle.front(),
            Some(PersistentV2PoolEntry::Poison(_))
        ));
        assert_eq!(idle.len(), 1, "the same reaper tick prunes the dead lane");
    }

    #[tokio::test]
    async fn persistent_v2_shutdown_waits_for_tracked_admitted_activity() {
        let pool = v2_admission_test_pool(PersistentSessionConsumerConfig::default());
        let activity = pool
            .register_activity(PersistentV2ActivityKind::Call)
            .expect("register admitted V2 call");
        let barrier = Arc::clone(&pool.shutdown_io);
        pool.start_shutdown();
        assert!(pool.shutdown.load(Ordering::Acquire));
        assert!(
            !barrier.is_forced(),
            "admitted activity still owns the drain"
        );
        drop(activity);
        pool.wait_shutdown_complete().await;
        assert!(barrier.is_forced(), "pool driver forces I/O after drain");
        assert_eq!(pool.active.load(Ordering::Acquire), 0);
        assert_eq!(
            pool.actor_lanes.available_permits(),
            pool.config.request_connections
        );
    }

    #[tokio::test(start_paused = true)]
    async fn persistent_v2_shutdown_cannot_lose_the_last_activity_release() {
        let pool = v2_admission_test_pool(PersistentSessionConsumerConfig::default());
        let activity = pool
            .register_activity(PersistentV2ActivityKind::Call)
            .expect("register the final admitted V2 call");
        let armed = pool.shutdown_activity_wait_armed.notified();
        tokio::pin!(armed);
        armed.as_mut().enable();
        let started = tokio::time::Instant::now();
        pool.start_shutdown();
        armed.await;
        drop(activity);
        pool.wait_shutdown_complete().await;
        assert_eq!(
            tokio::time::Instant::now(),
            started,
            "the final activity notification completes shutdown without a drain timer"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persistent_v2_shutdown_observes_permits_released_before_actor_completion() {
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            1,
            Duration::ZERO,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("one-lane shutdown permit pool");
        let pool = v2_admission_test_pool(config);
        let physical = Arc::new(Semaphore::new(1));
        let lifetime = PersistentV2LaneLifetime {
            pool_connection: Arc::downgrade(&pool),
            state: PersistentV2LaneState::new(),
            _pool_width_admission: Some(
                Arc::clone(&pool.actor_lanes)
                    .try_acquire_owned()
                    .expect("reserve shutdown actor width"),
            ),
            _physical_admission: Some(
                Arc::clone(&physical)
                    .try_acquire_owned()
                    .expect("reserve shutdown physical admission"),
            ),
        };
        pool.active.store(1, Ordering::Release);
        let (release, released) = oneshot::channel();
        let holder = tokio::spawn(async move {
            let _ = released.await;
            drop(lifetime);
        });
        pool.start_shutdown();
        let completed = pool.wait_shutdown_complete();
        tokio::pin!(completed);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(completed.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(pool.actor_lanes.available_permits(), 0);
        assert_eq!(physical.available_permits(), 0);
        release.send(()).expect("release the final lane lifetime");
        completed.await;
        assert_eq!(pool.active.load(Ordering::Acquire), 0);
        assert_eq!(pool.actor_lanes.available_permits(), 1);
        assert_eq!(physical.available_permits(), 1);
        holder.await.expect("join the lifetime holder");
    }

    #[tokio::test]
    async fn persistent_v2_connection_drop_recovers_active_and_physical_admission() {
        let config = PersistentSessionConsumerConfig::default();
        let pool = v2_admission_test_pool(config);
        let physical = Arc::new(Semaphore::new(1));
        let physical_permit = Arc::clone(&physical)
            .try_acquire_owned()
            .expect("reserve one physical V2 admission");
        let established = tokio::time::Instant::now();
        let lifecycle = ConnectionLifecycle::new(
            pool.client.lifecycle_policy,
            established,
            None,
            None,
            pool.client.reauthentication.generation(),
            Some(pool.client.tls_config.material_status().epoch()),
        )
        .expect("valid synthetic V2 lifecycle");
        let (lane_io, _peer_io) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(lane_io);
        let (commands, command_rx) = mpsc::channel(1);
        let (retirement, actor_retirement) = watch::channel(None);
        pool.active.store(1, Ordering::Relaxed);
        tokio::spawn(run_persistent_v2_lane(PersistentV2LaneActor {
            reader: Box::new(reader),
            writer: Box::new(writer),
            request_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            lifecycle,
            rotation_jitter: Duration::ZERO,
            client: pool.client.clone(),
            reauthentication_changes: pool.client.reauthentication.subscribe(),
            material_changes: Some(pool.client.tls_config.subscribe_material_changes()),
            retirement: actor_retirement,
            forced: pool.shutdown_forced_tx.subscribe(),
            shutdown_io: Arc::clone(&pool.shutdown_io),
            commands: command_rx,
            lifetime: PersistentV2LaneLifetime {
                pool_connection: Arc::downgrade(&pool),
                state: PersistentV2LaneState::new(),
                _pool_width_admission: Some(
                    Arc::clone(&pool.actor_lanes)
                        .try_acquire_owned()
                        .expect("reserve connection-drop pool width"),
                ),
                _physical_admission: Some(physical_permit),
            },
        }));
        let connection = PersistentV2Connection {
            commands,
            idle_deadline: established + Duration::from_secs(1),
            retirement,
            admitted_generation: pool.client.reauthentication.generation(),
            admitted_material_epoch: pool.client.tls_config.material_status().epoch(),
            state: PersistentV2LaneState::new(),
        };
        let drained = pool.drained_notify.notified();
        tokio::pin!(drained);
        drained.as_mut().enable();
        drop(connection);
        drained.await;
        assert_eq!(pool.active.load(Ordering::Relaxed), 0);
        assert!(Arc::clone(&physical).try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn persistent_v2_idle_zero_byte_eof_is_replenishable_without_poison() {
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            1,
            Duration::ZERO,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("one-lane idle-EOF pool");
        let mut pool = v2_admission_test_pool(config);
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let observed_resolver_calls = Arc::clone(&resolver_calls);
        Arc::get_mut(&mut pool)
            .expect("idle-EOF pool has one owner")
            .client
            .resolve = Arc::new(move || {
            observed_resolver_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok("127.0.0.1:9".parse().expect("test socket address")) })
        });
        let established = tokio::time::Instant::now();
        let lifecycle = ConnectionLifecycle::new(
            pool.client.lifecycle_policy,
            established,
            None,
            None,
            pool.client.reauthentication.generation(),
            Some(pool.client.tls_config.material_status().epoch()),
        )
        .expect("valid idle-EOF lifecycle");
        let (commands, command_rx) = mpsc::channel(1);
        let (_retirement, actor_retirement) = watch::channel(None);
        let physical = Arc::new(Semaphore::new(1));
        pool.active.store(1, Ordering::Relaxed);
        let drained = pool.drained_notify.notified();
        tokio::pin!(drained);
        drained.as_mut().enable();
        let actor = tokio::spawn(run_persistent_v2_lane(PersistentV2LaneActor {
            reader: Box::new(tokio::io::empty()),
            writer: Box::new(tokio::io::sink()),
            request_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            lifecycle,
            rotation_jitter: Duration::ZERO,
            client: pool.client.clone(),
            reauthentication_changes: pool.client.reauthentication.subscribe(),
            material_changes: Some(pool.client.tls_config.subscribe_material_changes()),
            retirement: actor_retirement,
            forced: pool.shutdown_forced_tx.subscribe(),
            shutdown_io: Arc::clone(&pool.shutdown_io),
            commands: command_rx,
            lifetime: PersistentV2LaneLifetime {
                pool_connection: Arc::downgrade(&pool),
                state: PersistentV2LaneState::new(),
                _pool_width_admission: Some(
                    Arc::clone(&pool.actor_lanes)
                        .try_acquire_owned()
                        .expect("reserve idle-EOF pool width"),
                ),
                _physical_admission: Some(
                    Arc::clone(&physical)
                        .try_acquire_owned()
                        .expect("reserve idle-EOF global admission"),
                ),
            },
        }));
        drained.await;
        actor.await.expect("join idle-EOF actor");
        assert!(commands.is_closed());
        assert_eq!(pool.active.load(Ordering::SeqCst), 0);
        assert_eq!(pool.actor_lanes.available_permits(), 1);
        assert!(Arc::clone(&physical).try_acquire_owned().is_ok());
        assert!(pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .all(|entry| !matches!(entry, PersistentV2PoolEntry::Poison(_))));
        assert_eq!(
            pool.execute(&v2_effectful_request(0x75)).await,
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Unavailable,
            }),
            "a clean idle EOF attempts a replacement rather than consuming poison"
        );
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn persistent_v2_cancelled_command_retires_without_a_write() {
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            1,
            Duration::ZERO,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("one-lane cancelled-command pool");
        let mut pool = v2_admission_test_pool(config);
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let observed_resolver_calls = Arc::clone(&resolver_calls);
        Arc::get_mut(&mut pool)
            .expect("cancelled-command pool has one owner")
            .client
            .resolve = Arc::new(move || {
            observed_resolver_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok("127.0.0.1:9".parse().expect("test socket address")) })
        });
        let physical = Arc::new(Semaphore::new(1));
        let physical_permit = Arc::clone(&physical)
            .try_acquire_owned()
            .expect("reserve cancelled-command physical admission");
        let established = tokio::time::Instant::now();
        let lifecycle = ConnectionLifecycle::new(
            pool.client.lifecycle_policy,
            established,
            None,
            None,
            pool.client.reauthentication.generation(),
            Some(pool.client.tls_config.material_status().epoch()),
        )
        .expect("valid cancelled-command lifecycle");
        let (lane_io, _peer_io) = tokio::io::duplex(64);
        let (reader, _unused_writer) = tokio::io::split(lane_io);
        let write_polled = Arc::new(Notify::new());
        let observed_write_poll = write_polled.notified();
        tokio::pin!(observed_write_poll);
        observed_write_poll.as_mut().enable();
        let (commands, command_rx) = mpsc::channel(1);
        let (_retirement, actor_retirement) = watch::channel(None);
        let request = v2_effectful_request(0x6d);
        let request_commitment =
            super::v2_request_commitment(&request).expect("cancelled-command request commitment");
        let (completion, completed) = tokio::sync::oneshot::channel();
        let write_progress = Arc::new(crate::protocol::FrameWriteProgress::new());
        commands
            .try_send(super::PersistentV2LaneCall {
                request,
                attempt_nonce: [0x6d; 16],
                request_commitment,
                deadline: established + Duration::from_secs(1),
                completion,
                write_progress: Arc::clone(&write_progress),
            })
            .expect("queue cancelled-command actor request");
        pool.active.store(1, Ordering::Relaxed);
        let actor = tokio::spawn(run_persistent_v2_lane(PersistentV2LaneActor {
            reader: Box::new(reader),
            writer: Box::new(NotifyingPendingWriter {
                polled: Arc::clone(&write_polled),
            }),
            request_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            lifecycle,
            rotation_jitter: Duration::ZERO,
            client: pool.client.clone(),
            reauthentication_changes: pool.client.reauthentication.subscribe(),
            material_changes: Some(pool.client.tls_config.subscribe_material_changes()),
            retirement: actor_retirement,
            forced: pool.shutdown_forced_tx.subscribe(),
            shutdown_io: Arc::clone(&pool.shutdown_io),
            commands: command_rx,
            lifetime: PersistentV2LaneLifetime {
                pool_connection: Arc::downgrade(&pool),
                state: PersistentV2LaneState::new(),
                _pool_width_admission: Some(
                    Arc::clone(&pool.actor_lanes)
                        .try_acquire_owned()
                        .expect("reserve cancelled-command pool width"),
                ),
                _physical_admission: Some(physical_permit),
            },
        }));

        observed_write_poll.await;
        let successor = pool.connect_until(established + Duration::from_secs(1));
        tokio::pin!(successor);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(successor.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
        assert_eq!(pool.active.load(Ordering::Relaxed), 1);
        assert_eq!(pool.actor_lanes.available_permits(), 0);

        drop(completed);
        actor.await.expect("join cancelled-command V2 actor");
        assert!(!write_progress.accepted_any());
        assert_eq!(pool.active.load(Ordering::Relaxed), 0);
        assert_eq!(pool.actor_lanes.available_permits(), 0);
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
        assert!(Arc::clone(&physical).try_acquire_owned().is_ok());
        assert!(successor.await.is_err());
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
        assert_eq!(pool.active.load(Ordering::Relaxed), 0);
        assert_eq!(pool.actor_lanes.available_permits(), 1);
    }

    #[tokio::test]
    async fn persistent_v2_exact_early_response_survives_parked_flush_and_eof() {
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            1,
            Duration::ZERO,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("one-lane early-response pool");
        let pool = v2_admission_test_pool(config);
        let established = tokio::time::Instant::now();
        let lifecycle = ConnectionLifecycle::new(
            pool.client.lifecycle_policy,
            established,
            None,
            None,
            pool.client.reauthentication.generation(),
            Some(pool.client.tls_config.material_status().epoch()),
        )
        .expect("valid early-response lifecycle");
        let request = v2_effectful_request(0x71);
        let attempt_nonce = [0x71; 16];
        let request_commitment =
            super::v2_request_commitment(&request).expect("early-response commitment");
        let response = SessionConsumerV2Response::FencedTransitionV2(Err(
            SessionConsumerV2FencedTransitionError::RequestConflict,
        ));
        let wire_response = ConsumerV2WireResponse::Response(ConsumerV2CallResponse {
            correlation: NonZeroU32::MIN,
            attempt_nonce,
            request_commitment,
            response: Box::new(response.clone()),
        });
        let payload = serde_json::to_vec(&wire_response).expect("encode exact early response");
        let mut encoded = u32::try_from(payload.len())
            .expect("early response frame fits u32")
            .to_be_bytes()
            .to_vec();
        encoded.extend_from_slice(&payload);
        let reader_ready = Arc::new(AtomicBool::new(false));
        let reader_accepted = Arc::new(AtomicUsize::new(0));
        let writer_accepted = Arc::new(AtomicUsize::new(0));
        let flush_gate = Arc::new(FlushGate::default());
        let flush_polled = flush_gate.polled.notified();
        tokio::pin!(flush_polled);
        flush_polled.as_mut().enable();
        let (commands, command_rx) = mpsc::channel(1);
        let (_retirement, actor_retirement) = watch::channel(None);
        let (completion, completed) = oneshot::channel();
        let write_progress = Arc::new(crate::protocol::FrameWriteProgress::new());
        commands
            .try_send(PersistentV2LaneCall {
                request,
                attempt_nonce,
                request_commitment,
                deadline: established + Duration::from_secs(1),
                completion,
                write_progress: Arc::clone(&write_progress),
            })
            .expect("queue early-response Call");
        let physical = Arc::new(Semaphore::new(1));
        pool.active.store(1, Ordering::Relaxed);
        let actor = tokio::spawn(run_persistent_v2_lane(PersistentV2LaneActor {
            reader: Box::new(GatedCountingReader {
                encoded,
                offset: 0,
                ready: Arc::clone(&reader_ready),
                accepted: Arc::clone(&reader_accepted),
            }),
            writer: Box::new(AcceptThenParkFlushWriter {
                accepted: Arc::clone(&writer_accepted),
                gate: Arc::clone(&flush_gate),
            }),
            request_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            lifecycle,
            rotation_jitter: Duration::ZERO,
            client: pool.client.clone(),
            reauthentication_changes: pool.client.reauthentication.subscribe(),
            material_changes: Some(pool.client.tls_config.subscribe_material_changes()),
            retirement: actor_retirement,
            forced: pool.shutdown_forced_tx.subscribe(),
            shutdown_io: Arc::clone(&pool.shutdown_io),
            commands: command_rx,
            lifetime: PersistentV2LaneLifetime {
                pool_connection: Arc::downgrade(&pool),
                state: PersistentV2LaneState::new(),
                _pool_width_admission: Some(
                    Arc::clone(&pool.actor_lanes)
                        .try_acquire_owned()
                        .expect("reserve early-response pool width"),
                ),
                _physical_admission: Some(
                    Arc::clone(&physical)
                        .try_acquire_owned()
                        .expect("reserve early-response global admission"),
                ),
            },
        }));

        flush_polled.await;
        assert!(write_progress.accepted_any());
        assert!(writer_accepted.load(Ordering::SeqCst) > 0);
        reader_ready.store(true, Ordering::Release);
        flush_gate.release();
        assert_eq!(
            completed.await.expect("early-response actor completion"),
            Ok(response)
        );
        assert!(
            commands.is_closed(),
            "EOF retires before publishing completion"
        );
        actor.await.expect("join early-response actor");
        assert!(reader_accepted.load(Ordering::SeqCst) > 0);
        assert_eq!(pool.active.load(Ordering::Acquire), 0);
        assert_eq!(pool.actor_lanes.available_permits(), 1);
        assert!(Arc::clone(&physical).try_acquire_owned().is_ok());
        let idle = pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(idle
            .iter()
            .all(|entry| !matches!(entry, PersistentV2PoolEntry::Poison(_))));
    }

    #[tokio::test]
    async fn persistent_v2_actor_closes_before_publishing_call_4096() {
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_WATCH_CONNECTIONS,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SETUP_TIMEOUT,
            1,
            Duration::ZERO,
            DEFAULT_PERSISTENT_SESSION_CONSUMER_SHUTDOWN_DRAIN,
        )
        .expect("one-lane correlation-cap pool");
        let pool = v2_admission_test_pool(config);
        let established = tokio::time::Instant::now();
        let lifecycle = ConnectionLifecycle::new(
            pool.client.lifecycle_policy,
            established,
            None,
            None,
            pool.client.reauthentication.generation(),
            Some(pool.client.tls_config.material_status().epoch()),
        )
        .expect("valid correlation-cap lifecycle");
        let (lane_io, mut peer_io) = tokio::io::duplex(64 * 1024);
        let (reader, writer) = tokio::io::split(lane_io);
        let (commands, command_rx) = mpsc::channel(1);
        let (_retirement, actor_retirement) = watch::channel(None);
        let physical = Arc::new(Semaphore::new(1));
        pool.active.store(1, Ordering::Relaxed);
        let actor = tokio::spawn(run_persistent_v2_lane(PersistentV2LaneActor {
            reader: Box::new(reader),
            writer: Box::new(writer),
            request_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            lifecycle,
            rotation_jitter: Duration::ZERO,
            client: pool.client.clone(),
            reauthentication_changes: pool.client.reauthentication.subscribe(),
            material_changes: Some(pool.client.tls_config.subscribe_material_changes()),
            retirement: actor_retirement,
            forced: pool.shutdown_forced_tx.subscribe(),
            shutdown_io: Arc::clone(&pool.shutdown_io),
            commands: command_rx,
            lifetime: PersistentV2LaneLifetime {
                pool_connection: Arc::downgrade(&pool),
                state: PersistentV2LaneState::new(),
                _pool_width_admission: Some(
                    Arc::clone(&pool.actor_lanes)
                        .try_acquire_owned()
                        .expect("reserve correlation-cap pool width"),
                ),
                _physical_admission: Some(
                    Arc::clone(&physical)
                        .try_acquire_owned()
                        .expect("reserve correlation-cap global admission"),
                ),
            },
        }));
        let response = SessionConsumerV2Response::FencedTransitionV2(Err(
            SessionConsumerV2FencedTransitionError::RequestConflict,
        ));
        let peer_response = response.clone();
        let peer = tokio::spawn(async move {
            for expected in 1..=MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION {
                let ConsumerV2WireRequest::Call(ConsumerV2Call {
                    correlation,
                    attempt_nonce,
                    request_commitment,
                    request,
                }) = super::read_consumer_frame::<_, ConsumerV2WireRequest>(
                    &mut peer_io,
                    MAX_NEGOTIATED_FRAME_SIZE,
                )
                .await
                .expect("read bounded correlation Call")
                else {
                    panic!("actor emitted a control frame after setup");
                };
                assert_eq!(
                    correlation,
                    NonZeroU32::new(u32::try_from(expected).expect("bounded correlation fits u32"))
                        .expect("bounded correlation is nonzero")
                );
                assert!(super::v2_response_matches_request(&request, &peer_response));
                super::write_frame_bounded_until(
                    &mut peer_io,
                    &ConsumerV2WireResponse::Response(ConsumerV2CallResponse {
                        correlation,
                        attempt_nonce,
                        request_commitment,
                        response: Box::new(peer_response.clone()),
                    }),
                    MAX_NEGOTIATED_FRAME_SIZE,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await
                .expect("write bounded correlation response");
            }
            assert!(super::read_consumer_frame::<_, ConsumerV2WireRequest>(
                &mut peer_io,
                MAX_NEGOTIATED_FRAME_SIZE,
            )
            .await
            .is_err());
        });

        for call in 1..=MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION {
            let request =
                v2_effectful_request(u8::try_from(call % 251).expect("bounded test nonce fits u8"));
            let request_commitment =
                super::v2_request_commitment(&request).expect("correlation-cap commitment");
            let (completion, completed) = oneshot::channel();
            commands
                .send(PersistentV2LaneCall {
                    request,
                    attempt_nonce: [u8::try_from(call % 251)
                        .expect("bounded attempt nonce fits u8");
                        16],
                    request_commitment,
                    deadline: established + Duration::from_secs(30),
                    completion,
                    write_progress: Arc::new(crate::protocol::FrameWriteProgress::new()),
                })
                .await
                .expect("queue bounded correlation Call");
            assert_eq!(
                completed.await.expect("bounded correlation completion"),
                Ok(response.clone())
            );
            if call < MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION {
                assert!(!commands.is_closed());
            }
        }
        assert!(
            commands.is_closed(),
            "the actor closes admission before publishing Call 4096"
        );
        peer.await.expect("join bounded correlation peer");
        actor.await.expect("join bounded correlation actor");
        assert_eq!(pool.active.load(Ordering::Acquire), 0);
        assert_eq!(pool.actor_lanes.available_permits(), 1);
        assert!(Arc::clone(&physical).try_acquire_owned().is_ok());
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
                rotation_jitter: client
                    .tls_config
                    .begin_handshake()
                    .expect("test client handshake snapshot")
                    .consumer_rotation_jitter(&client.expected_server_identity),
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
            let mut writer = FailOnceCountingWriter {
                accepted: 0,
                fail_after,
                fail_flush,
                failed: false,
                write_polls_after_failure: 0,
                flush_polls_after_failure: 0,
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
    fn revision_three_semantics_bind_ttl_records_batches_watches_and_future_operations() {
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
            &SessionConsumerResponse::AcquireLease(Ok(lease.clone())),
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
                &SessionConsumerResponse::AcquireLease(Ok(wrong)),
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
            &SessionConsumerResponse::AcquireLease(Ok(lease_guard(
                key.clone(),
                owner.clone(),
                FenceToken::new(8),
                authority_time,
                maximum_expiry,
                10,
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
            &SessionConsumerResponse::AcquireLease(Ok(lease_guard(
                key.clone(),
                owner.clone(),
                FenceToken::new(9),
                authority_time,
                authority_time,
                11,
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
            &SessionConsumerResponse::RenewLease(Ok(renewed.clone())),
        ));
        assert!(response_matches_request(
            &renew,
            &SessionConsumerResponse::RenewLease(Ok(lease.clone())),
        ));
        assert!(!response_matches_request(
            &renew,
            &SessionConsumerResponse::RenewLease(Ok(lease_guard(
                key.clone(),
                owner.clone(),
                lease.fence(),
                lease.acquired_at(),
                renewed_expiry,
                lease.credential_id().saturating_add(1),
            ))),
        ));

        for shorter_ttl in [Duration::ZERO, Duration::from_secs(7)] {
            let shorter_expiry = checked_session_deadline(renewal_authority, shorter_ttl)
                .expect("short renewal expiry");
            let shorter_renew = SessionConsumerRequest::new(
                scope(),
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::RenewLease {
                    lease: lease.clone(),
                    ttl: shorter_ttl,
                },
            );
            assert!(response_matches_request(
                &shorter_renew,
                &SessionConsumerResponse::RenewLease(Ok(lease_guard(
                    key.clone(),
                    owner.clone(),
                    lease.fence(),
                    lease.acquired_at(),
                    shorter_expiry,
                    lease.credential_id(),
                ))),
            ));
        }

        for invalid_authority in [
            lease.expires_at(),
            lease.expires_at().add_seconds(1).unwrap(),
        ] {
            let invalid_expiry =
                checked_session_deadline(invalid_authority, Duration::from_secs(7))
                    .expect("invalid renewal expiry remains representable");
            let expired_renew = SessionConsumerRequest::new(
                scope(),
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::RenewLease {
                    lease: lease.clone(),
                    ttl: Duration::from_secs(7),
                },
            );
            assert!(!response_matches_request(
                &expired_renew,
                &SessionConsumerResponse::RenewLease(Ok(lease_guard(
                    key.clone(),
                    owner.clone(),
                    lease.fence(),
                    lease.acquired_at(),
                    invalid_expiry,
                    lease.credential_id(),
                ))),
            ));
        }

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
        let observe = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::ObserveFencedTransition { key: key.clone() },
        );
        for payload in [
            EncryptedSessionPayload::new([0x41]),
            EncryptedSessionPayload::legacy_plaintext([0x42]),
            EncryptedSessionPayload::unclassified([0x43]),
        ] {
            let observation_record = StoredSessionRecord {
                key: key.clone(),
                generation: Generation::new(1),
                owner: owner.clone(),
                fence: lease.fence(),
                state_class: StateClass::AuthoritativeSession,
                state_type: StateType::from_static("fenced-observation-encoding"),
                expires_at: None,
                payload,
            };
            let observation: FencedTransitionObservation =
                serde_json::from_value(serde_json::json!({
                    "record": observation_record,
                    "current_fence": lease.fence(),
                }))
                .expect("valid fenced observation shape");
            assert!(!response_matches_request(
                &observe,
                &SessionConsumerResponse::ObserveFencedTransition(Ok(observation)),
            ));
        }
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
            &SessionConsumerResponse::OutcomeUnknown(SessionConsumerOutcomeUnknown::Mutation {
                request_id: SessionConsumerRequestId::from_bytes([0x9a; 16]),
            }),
        ));
        assert!(response_matches_operation(
            ConsumerOperationKind::UnknownEffectful,
            &SessionConsumerResponse::Rejected(SessionConsumerRejection::MalformedRequest),
        ));
    }

    #[test]
    fn revision_three_fenced_transition_outer_identity_is_byte_exact() {
        let key = SessionKey {
            tenant: TenantId::new("fenced-transition-id").expect("test tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"fenced-transition-id")
                .try_into()
                .expect("bounded stable ID"),
        };
        let transition = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x71; 16]),
            FencedTransitionLease::acquire(
                key,
                OwnerId::new("fenced-transition-owner").expect("test owner"),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .expect("bounded acquire"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("bounded transition");
        let exact_id = SessionConsumerRequestId::from_bytes([0x71; 16]);
        let exact = SessionConsumerRequest::new(
            scope(),
            exact_id,
            SessionConsumerOperation::FencedTransition {
                request: Box::new(transition.clone()),
            },
        );
        assert!(consumer_request_has_exact_fenced_transition_id(&exact));
        assert!(response_matches_request(
            &exact,
            &SessionConsumerResponse::OutcomeUnknown(SessionConsumerOutcomeUnknown::Mutation {
                request_id: exact_id,
            }),
        ));

        let mismatched = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::from_bytes([0x72; 16]),
            SessionConsumerOperation::FencedTransition {
                request: Box::new(transition),
            },
        );
        assert!(!consumer_request_has_exact_fenced_transition_id(
            &mismatched
        ));
        assert!(!response_matches_request(
            &mismatched,
            &SessionConsumerResponse::OutcomeUnknown(SessionConsumerOutcomeUnknown::Mutation {
                request_id: exact_id,
            }),
        ));
    }

    #[test]
    fn authenticated_consumer_binding_survives_configuration_failover() {
        let changed_scope = SessionConsumerScope::new(SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([1; 32]),
            SessionConsensusConfigurationId::from_bytes([9; 32]),
            SessionConsensusConfigurationEpoch::new(2).expect("non-zero configuration epoch"),
        ));
        let local_identity = [0x51; 32];
        let original = authenticated_consumer_binding(Some(local_identity), scope())
            .expect("local identity is available");
        let failover = authenticated_consumer_binding(Some(local_identity), changed_scope)
            .expect("local identity is available");
        let different_consumer = authenticated_consumer_binding(Some([0x52; 32]), scope())
            .expect("local identity is available");

        assert_eq!(original, failover);
        assert_ne!(original, different_consumer);
        assert!(authenticated_consumer_binding(None, scope()).is_err());
    }

    #[test]
    fn authenticated_consumer_physical_token_rejects_another_consumer_binding() {
        let key = SessionKey {
            tenant: TenantId::new("consumer-physical-token").expect("test tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"consumer-physical-token")
                .try_into()
                .expect("bounded stable ID"),
        };
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x83; 16]),
            FencedTransitionLease::acquire(
                key,
                OwnerId::new("consumer-physical-token-owner").expect("test owner"),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .expect("bounded acquire"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("bounded transition");
        let accepted = authenticated_consumer_binding(Some([0x53; 32]), scope())
            .expect("local identity is available");
        let other = authenticated_consumer_binding(Some([0x54; 32]), scope())
            .expect("local identity is available");
        let prepared = PreparedFencedTransition::from_unprotected_request(request)
            .expect("prepare unprotected token")
            .with_authenticated_consumer_binding(accepted)
            .expect("attach consumer marker");

        assert!(prepared
            .request_for_authenticated_consumer(accepted)
            .is_ok());
        assert!(prepared.request_for_authenticated_consumer(other).is_err());
    }

    #[tokio::test]
    async fn authenticated_consumer_rejects_legacy_invalid_physical_tokens_before_transport() {
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let resolving = Arc::clone(&resolver_calls);
        let material = RotatableClientMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/consumer/instance/client",
        );
        let client = StatelessSessionConsumerClient::new_with_resolver(
            Arc::new(move || {
                resolving.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok("127.0.0.1:9".parse().expect("test address")) })
            }),
            rustls_pki_types::ServerName::try_from("consumer.test").expect("test TLS server name"),
            spiffe("server"),
            scope(),
            material.config(),
        );
        let backend = SessionConsumerFencedTransitionBackend::stateless(client)
            .expect("authenticated consumer backend");
        let key = SessionKey {
            tenant: TenantId::new("consumer-legacy-token").expect("test tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"consumer-legacy-token")
                .try_into()
                .expect("bounded stable ID"),
        };
        let owner = OwnerId::new("consumer-legacy-token-owner").expect("test owner");
        let lease = FencedTransitionLease::acquire(
            key.clone(),
            owner.clone(),
            FenceToken::new(0),
            Duration::from_secs(30),
        )
        .expect("bounded acquire");
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x84; 16]),
            lease.clone(),
            FencedTransitionMutation::create(StoredSessionRecord {
                key,
                generation: Generation::new(1),
                owner,
                fence: lease.committed_fence().expect("committed fence"),
                state_class: StateClass::AuthoritativeSession,
                state_type: StateType::from_static("consumer-legacy-token"),
                expires_at: None,
                payload: EncryptedSessionPayload::legacy_plaintext([0x84]),
            }),
        )
        .expect("bounded transition");
        let prepared = PreparedFencedTransition::from_unprotected_request(request)
            .expect("prepare legacy token")
            .with_authenticated_consumer_binding(backend.binding_commitment)
            .expect("attach consumer marker");

        assert!(!backend.fenced_transition_accepts_prepared_physical_token(&prepared));
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            backend.fenced_transition(&prepared).await,
            Err(FencedTransitionExecuteError::NotTransmitted)
        );
        assert!(backend.fenced_transition_status(&prepared).await.is_err());
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn authenticated_consumer_prepare_matches_consensus_physical_admission_boundary() {
        const CONSENSUS_PHYSICAL_MAX_BYTES: usize = 1_048_576;

        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let resolving = Arc::clone(&resolver_calls);
        let material = RotatableClientMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/consumer/instance/client",
        );
        let client = StatelessSessionConsumerClient::new_with_resolver(
            Arc::new(move || {
                resolving.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok("127.0.0.1:9".parse().expect("test address")) })
            }),
            rustls_pki_types::ServerName::try_from("consumer.test").expect("test TLS server name"),
            spiffe("server"),
            scope(),
            material.config(),
        );
        let backend = SessionConsumerFencedTransitionBackend::stateless(client)
            .expect("authenticated consumer backend");

        let exact =
            authenticated_consumer_physical_create_request(0x85, CONSENSUS_PHYSICAL_MAX_BYTES)
                .await;
        assert!(backend.prepare_fenced_transition(exact).await.is_ok());
        let oversized =
            authenticated_consumer_physical_create_request(0x86, CONSENSUS_PHYSICAL_MAX_BYTES + 1)
                .await;
        assert_eq!(
            backend.prepare_fenced_transition(oversized).await,
            Err(StoreError::PayloadTooLarge {
                actual: CONSENSUS_PHYSICAL_MAX_BYTES + 1,
                max: CONSENSUS_PHYSICAL_MAX_BYTES,
            })
        );
        assert!(backend
            .prepare_fenced_transition(
                authenticated_consumer_record_free_request(0x87, false).await,
            )
            .await
            .is_ok());
        assert!(backend
            .prepare_fenced_transition(authenticated_consumer_record_free_request(0x88, true).await)
            .await
            .is_ok());
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn consumer_fenced_transition_adapter_preserves_typed_ambiguity_and_statuses() {
        let key = SessionKey {
            tenant: TenantId::new("adapter-transition").expect("test tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"adapter-transition")
                .try_into()
                .expect("bounded stable ID"),
        };
        let outcome_key = key.clone();
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x81; 16]),
            FencedTransitionLease::acquire(
                key,
                OwnerId::new("adapter-transition-owner").expect("test owner"),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .expect("bounded acquire"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("bounded transition");

        assert_eq!(
            consumer_execute_into_fenced_transition(
                &request,
                Err(
                    SessionConsumerFencedTransitionMutationError::OutcomeUnknown {
                        request_id: FencedTransitionRequestId::from_bytes([0x82; 16]),
                    }
                ),
            ),
            Err(FencedTransitionExecuteError::OutcomeUnknown {
                request_id: request.request_id(),
            }),
        );
        let timestamp = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let mismatched_outcome: FencedTransitionOutcome =
            serde_json::from_value(serde_json::json!({
                "lease": {
                    "key": outcome_key,
                    "owner": OwnerId::new("adapter-transition-owner").expect("test owner"),
                    "fence": FenceToken::new(1),
                    "acquired_at": timestamp,
                    "expires_at": timestamp,
                    "credential_id": 1,
                },
                "committed_generation": Generation::new(1),
                "mutation": "Deleted",
                "recorded_at": timestamp,
                "retained_until": timestamp,
            }))
            .expect("bounded outcome wire shape");
        assert_eq!(
            consumer_execute_into_fenced_transition(&request, Ok(mismatched_outcome)),
            Err(FencedTransitionExecuteError::OutcomeUnknown {
                request_id: request.request_id(),
            }),
        );
        assert_eq!(
            super::consumer_status_into_fenced_transition(
                SessionConsumerFencedTransitionStatus::RequestConflict,
            ),
            Ok(FencedTransitionStatus::RequestConflict),
        );
        assert_eq!(
            super::consumer_status_into_fenced_transition(
                SessionConsumerFencedTransitionStatus::Recorded(Box::new(Err(
                    SessionConsumerFencedTransitionError::Expired,
                ))),
            ),
            Ok(FencedTransitionStatus::Recorded(Box::new(Err(
                StoreError::FencedTransitionRequestExpired,
            )))),
        );
    }

    #[test]
    fn fenced_transition_receipts_reject_nonpersisted_errors_and_preserve_ambiguity() {
        let key = SessionKey {
            tenant: TenantId::new("fenced-transition-receipt").expect("test tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"fenced-transition-receipt")
                .try_into()
                .expect("bounded stable ID"),
        };
        let transition = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x73; 16]),
            FencedTransitionLease::acquire(
                key.clone(),
                OwnerId::new("fenced-transition-receipt-owner").expect("test owner"),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .expect("bounded acquire"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("bounded transition");
        let consumer_request = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::from_bytes([0x73; 16]),
            SessionConsumerOperation::FencedTransition {
                request: Box::new(transition.clone()),
            },
        );
        let status_request = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::from_bytes([0x73; 16]),
            SessionConsumerOperation::FencedTransitionStatus {
                request: Box::new(transition.clone()),
            },
        );

        let storage_exhausted = SessionConsumerFencedTransitionError::StorageExhausted;
        assert!(response_matches_request(
            &consumer_request,
            &SessionConsumerResponse::FencedTransition(Err(storage_exhausted)),
        ));
        assert_eq!(
            fenced_transition_response(
                &transition,
                Ok(SessionConsumerResponse::FencedTransition(Err(
                    storage_exhausted
                ))),
            ),
            Err(SessionConsumerFencedTransitionMutationError::Store(
                StoreError::FencedTransitionStorageExhausted,
            )),
        );
        assert!(response_matches_request(
            &status_request,
            &SessionConsumerResponse::FencedTransitionStatus(Ok(
                SessionConsumerFencedTransitionStatus::Recorded(Box::new(Err(storage_exhausted,))),
            )),
        ));

        for impossible in [
            SessionConsumerStoreError::Unavailable,
            SessionConsumerStoreError::OutcomeUnavailable,
            SessionConsumerStoreError::CapabilityNotSupported,
            SessionConsumerStoreError::ProtectedDataRejected,
            SessionConsumerStoreError::RequestConflict,
        ] {
            assert!(
                !response_matches_request(
                    &status_request,
                    &SessionConsumerResponse::FencedTransitionStatus(Ok(
                        SessionConsumerFencedTransitionStatus::Recorded(Box::new(Err(
                            SessionConsumerFencedTransitionError::Store(impossible),
                        ))),
                    )),
                ),
                "nonpersisted error {impossible:?} must not be accepted as a receipt"
            );
        }

        let wrong_recorded_error = SessionConsumerResponse::FencedTransition(Err(
            SessionConsumerFencedTransitionError::Store(SessionConsumerStoreError::RestoreRejected),
        ));
        assert!(!response_matches_request(
            &consumer_request,
            &wrong_recorded_error,
        ));
        assert_eq!(
            fenced_transition_response(&transition, Ok(wrong_recorded_error)),
            Err(
                SessionConsumerFencedTransitionMutationError::OutcomeUnknown {
                    request_id: transition.request_id(),
                }
            ),
        );

        let timestamp = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let wrong_lease: LeaseGuard = serde_json::from_value(serde_json::json!({
            "key": key,
            "owner": OwnerId::new("fenced-transition-receipt-owner").expect("test owner"),
            "fence": FenceToken::new(1),
            "acquired_at": timestamp,
            "expires_at": timestamp,
            "credential_id": 1,
        }))
        .expect("public lease wire shape");
        let wrong_outcome: FencedTransitionOutcome = serde_json::from_value(serde_json::json!({
            "lease": wrong_lease,
            "committed_generation": Generation::new(1),
            "mutation": "Deleted",
            "recorded_at": timestamp,
            "retained_until": timestamp,
        }))
        .expect("bounded outcome wire shape");
        let wrong_success = SessionConsumerResponse::FencedTransition(Ok(wrong_outcome));
        assert!(!response_matches_request(&consumer_request, &wrong_success));
        assert_eq!(
            fenced_transition_response(&transition, Ok(wrong_success)),
            Err(
                SessionConsumerFencedTransitionMutationError::OutcomeUnknown {
                    request_id: transition.request_id(),
                }
            ),
        );
    }

    #[test]
    fn consumer_capabilities_use_the_fixed_width_checked_wire_dto() {
        let mut capabilities = BackendCapabilities::all_enabled();
        capabilities.max_value_bytes = usize::MAX;
        let wire = consumer_wire_response_from_public(
            ConsumerLeaseWireContext::Other,
            SessionConsumerResponse::Capabilities(capabilities),
        )
        .expect("capabilities fit the private wire");
        let response = ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation: NonZeroU32::MIN,
            response: Box::new(wire),
        });
        let encoded = serde_json::to_value(&response).expect("consumer capabilities encode");
        assert_eq!(
            encoded["body"]["response"]["body"]["max_value_bytes"],
            u64::try_from(usize::MAX).expect("supported pointer width"),
        );
        let encoded = serde_json::to_vec(&response).expect("consumer capabilities encode");
        let decoded = decode_consumer_frame_payload::<ConsumerWireResponse>(&encoded)
            .expect("consumer capabilities decode");
        let ConsumerWireResponse::Response(ConsumerCallResponse { response, .. }) = decoded else {
            panic!("capability response keeps its wire family");
        };
        let ConsumerSessionResponseWire::Capabilities(capabilities) = *response else {
            panic!("capability response keeps its private DTO");
        };
        assert_eq!(
            BackendCapabilities::try_from(capabilities)
                .expect("wire capabilities remain representable")
                .max_value_bytes,
            usize::MAX,
        );
    }

    #[test]
    fn consumer_capabilities_are_clamped_and_verified_against_both_directions() {
        let request_frame_size = MAX_NEGOTIATED_FRAME_SIZE / 2;
        let response_frame_size = MAX_NEGOTIATED_FRAME_SIZE / 4;
        let expected =
            super::consumer_capability_payload_budget(request_frame_size, response_frame_size);
        let mut response = SessionConsumerResponse::Capabilities(
            opc_session_store::BackendCapabilities::all_enabled(),
        );
        super::clamp_consumer_capabilities(&mut response, request_frame_size, response_frame_size);
        let SessionConsumerResponse::Capabilities(capabilities) = response else {
            unreachable!("capability clamp preserves the response family");
        };
        assert_eq!(capabilities.max_value_bytes, expected);
        assert!(super::response_respects_consumer_capability_budget(
            &SessionConsumerResponse::Capabilities(capabilities),
            request_frame_size,
            response_frame_size,
        ));

        let forged = SessionConsumerResponse::Capabilities(BackendCapabilities {
            max_value_bytes: expected + 1,
            ..capabilities
        });
        assert!(!super::response_respects_consumer_capability_budget(
            &forged,
            request_frame_size,
            response_frame_size,
        ));
    }

    #[test]
    fn borrowed_revision_three_envelopes_are_wire_identical() {
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

        let response = consumer_wire_response_from_public(
            ConsumerLeaseWireContext::Other,
            SessionConsumerResponse::Capabilities(BackendCapabilities::all_enabled()),
        )
        .expect("capabilities fit the private wire");
        let owned_response = ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation: NonZeroU32::MIN,
            response: Box::new(response.clone()),
        });
        let borrowed_response =
            BorrowedConsumerWireResponse::Response(BorrowedConsumerCallResponse {
                correlation: NonZeroU32::MIN,
                response: &response,
            });
        assert_eq!(
            serde_json::to_vec(&owned_response).expect("owned response encodes"),
            serde_json::to_vec(&borrowed_response).expect("borrowed response encodes")
        );
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FrozenRevisionOneHello {
        transport_revision: u16,
        scope: SessionConsumerScope,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(
        tag = "kind",
        content = "body",
        rename_all = "snake_case",
        deny_unknown_fields
    )]
    enum FrozenRevisionOneRequest {
        Hello(FrozenRevisionOneHello),
        Call(Box<SessionConsumerRequest>),
    }

    #[derive(Serialize, Deserialize)]
    #[serde(
        tag = "kind",
        content = "body",
        rename_all = "snake_case",
        deny_unknown_fields
    )]
    enum FrozenRevisionOneResponse {
        Response(Box<SessionConsumerResponse>),
    }

    const REVISION_ONE_SCOPE_JSON: &str = concat!(
        "{\"cluster_id\":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],",
        "\"configuration_id\":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],",
        "\"configuration_epoch\":1}"
    );
    const REVISION_ONE_RESPONSE_JSON: &str =
        "{\"kind\":\"response\",\"body\":{\"response\":\"watch_opened\"}}";

    #[test]
    fn frozen_revision_one_frames_never_cross_decode_as_revision_three() {
        let hello = format!(
            "{{\"kind\":\"hello\",\"body\":{{\"transport_revision\":1,\"scope\":{REVISION_ONE_SCOPE_JSON}}}}}"
        );
        let call = format!(
            "{{\"kind\":\"call\",\"body\":{{\"scope\":{REVISION_ONE_SCOPE_JSON},\"request_id\":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],\"operation\":{{\"operation\":\"capabilities\"}}}}}}"
        );
        for payload in [&hello, &call] {
            let decoded: FrozenRevisionOneRequest =
                serde_json::from_slice(payload.as_bytes()).expect("frozen revision-one request");
            assert_eq!(
                serde_json::to_vec(&decoded).expect("re-encode frozen revision-one request"),
                payload.as_bytes()
            );
            assert!(
                decode_consumer_frame_payload::<ConsumerWireRequest>(payload.as_bytes()).is_err()
            );
        }
        let decoded: FrozenRevisionOneResponse =
            serde_json::from_slice(REVISION_ONE_RESPONSE_JSON.as_bytes())
                .expect("frozen revision-one response");
        assert_eq!(
            serde_json::to_vec(&decoded).expect("re-encode frozen revision-one response"),
            REVISION_ONE_RESPONSE_JSON.as_bytes()
        );
        assert!(decode_consumer_frame_payload::<ConsumerWireResponse>(
            REVISION_ONE_RESPONSE_JSON.as_bytes()
        )
        .is_err());

        let current_hello = ConsumerWireRequest::Hello(ConsumerHello {
            transport_revision: super::SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
            scope: scope(),
            response_frame_size: u32::try_from(super::MAX_NEGOTIATED_FRAME_SIZE)
                .expect("consumer frame cap fits u32"),
        });
        assert!(serde_json::from_slice::<FrozenRevisionOneRequest>(
            &serde_json::to_vec(&current_hello).expect("encode revision-two Hello")
        )
        .is_err());
        let current_call = ConsumerWireRequest::Call(ConsumerCall {
            correlation: NonZeroU32::MIN,
            request: Box::new(SessionConsumerRequest::new(
                scope(),
                SessionConsumerRequestId::from_bytes([3; 16]),
                SessionConsumerOperation::Capabilities,
            )),
        });
        assert!(serde_json::from_slice::<FrozenRevisionOneRequest>(
            &serde_json::to_vec(&current_call).expect("encode revision-two Call")
        )
        .is_err());
        let current_response = ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation: NonZeroU32::MIN,
            response: Box::new(ConsumerSessionResponseWire::WatchOpened),
        });
        assert!(serde_json::from_slice::<FrozenRevisionOneResponse>(
            &serde_json::to_vec(&current_response).expect("encode revision-two Response")
        )
        .is_err());
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
        let response = consumer_wire_response_from_public(
            ConsumerLeaseWireContext::Other,
            SessionConsumerResponse::Capabilities(BackendCapabilities::all_enabled()),
        )
        .expect("capabilities fit the private wire");
        let response = ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation: NonZeroU32::MIN,
            response: Box::new(response),
        });
        let mut encoded = serde_json::to_value(response).expect("consumer response encodes");
        encoded["body"]["Capabilities"]["unexpected"] = serde_json::Value::Bool(true);
        let payload = serde_json::to_vec(&encoded).expect("JSON payload");
        assert!(decode_consumer_frame_payload::<ConsumerWireResponse>(&payload).is_err());
    }

    #[test]
    fn consumer_decoder_accepts_only_the_canonical_private_encoding() {
        let response = consumer_wire_response_from_public(
            ConsumerLeaseWireContext::Other,
            SessionConsumerResponse::Capabilities(BackendCapabilities::all_enabled()),
        )
        .expect("capabilities fit the private wire");
        let response = ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation: NonZeroU32::MIN,
            response: Box::new(response),
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
        let response = consumer_wire_response_from_public(
            ConsumerLeaseWireContext::Other,
            SessionConsumerResponse::Capabilities(BackendCapabilities::all_enabled()),
        )
        .expect("capabilities fit the private wire");
        let response = ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation: NonZeroU32::MIN,
            response: Box::new(response),
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

        let response = consumer_wire_response_from_public(
            ConsumerLeaseWireContext::Other,
            SessionConsumerResponse::Capabilities(BackendCapabilities::all_enabled()),
        )
        .expect("capabilities fit the private wire");
        let response = ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation: one,
            response: Box::new(response),
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
    async fn persistent_timeout_cap_preserves_the_legacy_stateless_builder_domain() {
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
                client.clone().with_operation_timeout(
                    DEFAULT_CONSUMER_OPERATION_TIMEOUT + Duration::from_nanos(1),
                ),
                PersistentSessionConsumerConfig::default(),
            ),
            Err(PersistentSessionConsumerConfigError::Timing)
        ));
        assert!(matches!(
            PersistentSessionConsumerClient::try_from_stateless(
                client.clone().with_idle_timeout(Duration::ZERO),
                PersistentSessionConsumerConfig::default(),
            ),
            Err(PersistentSessionConsumerConfigError::Timing)
        ));
        assert!(matches!(
            PersistentSessionConsumerClient::try_from_stateless(
                client
                    .clone()
                    .with_idle_timeout(DEFAULT_CONSUMER_IDLE_TIMEOUT + Duration::from_nanos(1)),
                PersistentSessionConsumerConfig::default(),
            ),
            Err(PersistentSessionConsumerConfigError::Timing)
        ));
        assert!(matches!(
            PersistentSessionConsumerClient::from_stateless(client.with_operation_timeout(
                DEFAULT_CONSUMER_OPERATION_TIMEOUT + Duration::from_nanos(1),
            )),
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
        .with_idle_timeout(DEFAULT_CONSUMER_IDLE_TIMEOUT + Duration::from_secs(1))
        .with_operation_timeout(DEFAULT_CONSUMER_OPERATION_TIMEOUT + Duration::from_secs(1));
        assert_eq!(
            client.capabilities().await,
            Err(SessionConsumerClientError::Unavailable)
        );
        assert_eq!(
            resolver_calls.load(Ordering::SeqCst),
            1,
            "a legacy stateless timeout above the revision-3 ceiling remains source-compatible; the effective wire operation is internally capped"
        );

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
        let (handle, _) = SessionQuorumConsumerServer::new(
            Arc::new(RejectingTestConsumer),
            server_material.config(),
            authorizer,
        )
        .with_max_connections(DEFAULT_CONSUMER_MAX_CONNECTIONS + 1)
        .with_idle_timeout(DEFAULT_CONSUMER_IDLE_TIMEOUT + Duration::from_secs(1))
        .with_operation_timeout(DEFAULT_CONSUMER_OPERATION_TIMEOUT + Duration::from_secs(1))
        .listen("127.0.0.1:0".parse().expect("test listener address"))
        .await
        .expect("legacy stateless listener bounds remain accepted");
        handle.abort_and_wait().await;
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
    async fn listener_abort_interrupts_accepted_and_authenticated_setup_immediately() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("abort-setup-client");
        let server_identity = material_spiffe("abort-setup-server");
        let client_material = RotatableClientMaterial::new(client_identity.as_str());
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity.clone()],
            std::iter::empty(),
        )
        .expect("abort setup authorizer");

        // First stop an accepted socket before TLS begins. The test hook is
        // inside the connection task, so observing it proves `abort()` must
        // wake that task rather than merely closing the accept loop.
        let accepted_hooks = Arc::new(ConsumerServerSetupTestHooks::new());
        let (accepted_server, accepted_address) = SessionQuorumConsumerServer::new(
            Arc::new(RejectingTestConsumer),
            client_material.trusted_server_config(server_identity.as_str()),
            authorizer.clone(),
        )
        .with_setup_test_hooks(Arc::clone(&accepted_hooks))
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for accepted-setup cancellation");
        let mut accepted_tcp = tokio::net::TcpStream::connect(accepted_address)
            .await
            .expect("connect accepted setup socket");
        accepted_hooks.accepted.notified().await;
        accepted_server.abort();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), accepted_tcp.read_u8())
                .await
                .expect("accepted setup closes promptly after abort")
                .is_err(),
            "abort closes the accepted pre-TLS socket without waiting for the setup deadline"
        );
        accepted_server.abort_and_wait().await;

        // Then stop a real authenticated connection with one active Hello
        // prefix byte. Without cancellation in the pinned bootstrap read this
        // would remain live until the independent five-second idle bound.
        let hello_hooks = Arc::new(ConsumerServerSetupTestHooks::new());
        let (hello_server, hello_address) = SessionQuorumConsumerServer::new(
            Arc::new(RejectingTestConsumer),
            client_material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .with_setup_test_hooks(Arc::clone(&hello_hooks))
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for authenticated-setup cancellation");
        let tcp = tokio::net::TcpStream::connect(hello_address)
            .await
            .expect("connect authenticated setup socket");
        hello_hooks.accepted.notified().await;
        hello_hooks.continue_after_accept.notify_one();
        let handshake = client_material
            .config()
            .begin_handshake()
            .expect("client setup handshake snapshot");
        let connector = tokio_rustls::TlsConnector::from(super::consumer_client_tls_config(
            handshake.rustls_config(),
        ));
        let mut tls = connector
            .connect(
                rustls_pki_types::ServerName::IpAddress(hello_address.ip().into()),
                tcp,
            )
            .await
            .expect("complete authenticated setup TLS");
        hello_hooks.tls_complete.notified().await;
        hello_hooks.continue_after_tls.notify_one();
        tls.write_all(&[0])
            .await
            .expect("start one partial Hello prefix");
        tls.flush().await.expect("flush partial Hello prefix");
        tokio::task::yield_now().await;
        hello_server.abort();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), tls.read_u8())
                .await
                .expect("authenticated setup closes promptly after abort")
                .is_err(),
            "abort interrupts the pinned partial-Hello read before its idle deadline"
        );
        hello_server.abort_and_wait().await;
    }

    #[tokio::test(start_paused = true)]
    async fn call_rejection_writer_obeys_cancel_and_shortened_hard_deadline() {
        let server_identity = material_spiffe("rejection-writer-server");
        let client_identity = material_spiffe("rejection-writer-client");
        let material = RotatableServerMaterial::new(server_identity.as_str());
        let config = material.config();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(30),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::ZERO,
        )
        .expect("short rejection drain policy");

        for (rejection, force_by_rotation) in [
            (SessionConsumerRejection::ScopeMismatch, false),
            (SessionConsumerRejection::MalformedRequest, true),
        ] {
            let handshake = config
                .begin_handshake()
                .expect("server rejection handshake snapshot");
            let rotation_jitter = handshake.consumer_rotation_jitter(&client_identity);
            let reauthentication = SessionReauthenticationControl::new();
            let mut reauthentication_changes = reauthentication.subscribe();
            let mut material_changes = Some(config.subscribe_material_changes());
            let mut lifecycle = ConnectionLifecycle::new(
                policy,
                tokio::time::Instant::now(),
                None,
                None,
                reauthentication.generation(),
                Some(handshake.epoch()),
            )
            .expect("rejection writer lifecycle");
            let observed_lifecycle = lifecycle.clone();
            let cancellation = ConsumerServerCancellation::new();
            let mut writer = PendingWriter;
            let write = write_consumer_call_rejection_supervised(
                &mut writer,
                NonZeroU32::MIN,
                rejection,
                super::MAX_NEGOTIATED_FRAME_SIZE,
                tokio::time::Instant::now() + Duration::from_secs(10),
                Duration::from_secs(5),
                &mut lifecycle,
                &config,
                &reauthentication,
                &mut reauthentication_changes,
                &mut material_changes,
                &cancellation,
                rotation_jitter,
            );
            tokio::pin!(write);
            std::future::poll_fn(|context| {
                assert!(std::future::Future::poll(write.as_mut(), context).is_pending());
                Poll::Ready(())
            })
            .await;

            if force_by_rotation {
                reauthentication
                    .request_reauthentication()
                    .expect("shorten rejection hard deadline");
                std::future::poll_fn(|context| {
                    assert!(std::future::Future::poll(write.as_mut(), context).is_pending());
                    Poll::Ready(())
                })
                .await;
                tokio::time::advance(Duration::from_millis(1)).await;
            } else {
                cancellation.cancel();
            }
            let completed = write
                .as_mut()
                .await
                .expect("bounded rejection writer result");
            assert!(
                !completed,
                "scope and validation rejection writes never outlive cancellation or lifecycle"
            );
            if force_by_rotation {
                assert!(observed_lifecycle.hard_overrun_recorded());
            }
        }
    }

    #[tokio::test]
    async fn v2_partial_hello_ack_rejects_material_rotation_before_publication() {
        let server_identity = material_spiffe("server");
        let client_identity = material_spiffe("application-0");
        let material = RotatableServerMaterial::new(server_identity.as_str());
        let config = material.config();
        let handshake = config
            .begin_handshake()
            .expect("V2 HelloAck handshake snapshot");
        assert!(
            handshake.consumer_rotation_jitter(&client_identity) > Duration::ZERO,
            "the fixture must exercise the stale-Ack race with a cooperative nonzero jitter"
        );
        let reauthentication = SessionReauthenticationControl::new();
        let mut reauthentication_changes = reauthentication.subscribe();
        let mut material_changes = Some(config.subscribe_material_changes());
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(30),
            Duration::from_secs(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_secs(1),
        )
        .expect("bounded V2 partial-Ack lifecycle");
        let mut lifecycle = ConnectionLifecycle::new(
            policy,
            tokio::time::Instant::now(),
            None,
            None,
            reauthentication.generation(),
            Some(handshake.epoch()),
        )
        .expect("V2 partial-Ack lifecycle");
        let cancellation = ConsumerServerCancellation::new();
        let mut writer = PendingWriter;
        let write = super::write_consumer_v2_hello_ack_supervised(
            &mut writer,
            scope(),
            super::MAX_NEGOTIATED_FRAME_SIZE,
            super::MAX_NEGOTIATED_FRAME_SIZE,
            tokio::time::Instant::now() + Duration::from_secs(10),
            Duration::from_secs(5),
            &mut lifecycle,
            &config,
            reauthentication.generation(),
            handshake.epoch(),
            &reauthentication,
            &mut reauthentication_changes,
            &mut material_changes,
            &cancellation,
        );
        tokio::pin!(write);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(write.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        material.rotate();
        assert!(
            matches!(
                tokio::time::timeout(Duration::from_secs(1), write)
                    .await
                    .expect("rotated partial V2 HelloAck remains bounded"),
                Err(ProtocolError::Authentication)
            ),
            "a material rotation while the V2 HelloAck is incomplete cannot publish an acknowledged lane"
        );
    }

    #[tokio::test]
    async fn v2_ready_hello_ack_writer_rechecks_material_after_same_poll_rotation() {
        let server_identity = material_spiffe("server");
        let client_identity = material_spiffe("application-0");
        let material = Arc::new(RotatableServerMaterial::new(server_identity.as_str()));
        let config = material.config();
        let handshake = config
            .begin_handshake()
            .expect("V2 same-poll HelloAck handshake snapshot");
        assert!(
            handshake.consumer_rotation_jitter(&client_identity) > Duration::ZERO,
            "the completing writer must rotate a lane whose normal post-Ack cutover is jittered"
        );
        let reauthentication = SessionReauthenticationControl::new();
        let mut reauthentication_changes = reauthentication.subscribe();
        let mut material_changes = Some(config.subscribe_material_changes());
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(30),
            Duration::from_secs(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_secs(1),
        )
        .expect("bounded V2 same-poll Ack lifecycle");
        let mut lifecycle = ConnectionLifecycle::new(
            policy,
            tokio::time::Instant::now(),
            None,
            None,
            reauthentication.generation(),
            Some(handshake.epoch()),
        )
        .expect("V2 same-poll Ack lifecycle");
        let cancellation = ConsumerServerCancellation::new();
        let mut writer = RotateThenReadyWriter {
            material: Arc::clone(&material),
            rotated: false,
        };
        assert!(
            matches!(
                super::write_consumer_v2_hello_ack_supervised(
                    &mut writer,
                    scope(),
                    super::MAX_NEGOTIATED_FRAME_SIZE,
                    super::MAX_NEGOTIATED_FRAME_SIZE,
                    tokio::time::Instant::now() + Duration::from_secs(10),
                    Duration::from_secs(5),
                    &mut lifecycle,
                    &config,
                    reauthentication.generation(),
                    handshake.epoch(),
                    &reauthentication,
                    &mut reauthentication_changes,
                    &mut material_changes,
                    &cancellation,
                )
                .await,
                Err(ProtocolError::Authentication)
            ),
            "a material rotation from the completing Ack writer cannot enter the V2 dispatch loop"
        );
    }

    #[tokio::test]
    async fn v2_effectful_response_write_failure_is_terminal_without_safe_rejection() {
        let server_identity = material_spiffe("v2-response-failure-server");
        let client_identity = material_spiffe("v2-response-failure-client");
        let material = RotatableServerMaterial::new(server_identity.as_str());
        let config = material.config();
        let handshake = config
            .begin_handshake()
            .expect("V2 response-write handshake snapshot");
        let reauthentication = SessionReauthenticationControl::new();
        let mut reauthentication_changes = reauthentication.subscribe();
        let mut material_changes = Some(config.subscribe_material_changes());
        let mut lifecycle = ConnectionLifecycle::new(
            ConnectionLifecyclePolicy::default(),
            tokio::time::Instant::now(),
            None,
            None,
            reauthentication.generation(),
            Some(handshake.epoch()),
        )
        .expect("V2 response-write lifecycle");
        let request = v2_effectful_request(0x86);
        let response = SessionConsumerV2Response::FencedTransitionV2(Err(
            SessionConsumerV2FencedTransitionError::OutcomeUnknown,
        ));
        assert!(
            !super::v2_response_matches_request(&request, &response),
            "the controlled unbound response cannot complete an effectful V2 result"
        );
        for (phase, fail_after, fail_flush) in [
            ("partial_prefix", Some(2), false),
            ("partial_payload", Some(12), false),
            ("flush", None, true),
        ] {
            let mut writer = FailOnceCountingWriter {
                accepted: 0,
                fail_after,
                fail_flush,
                failed: false,
                write_polls_after_failure: 0,
                flush_polls_after_failure: 0,
            };
            let error = super::write_consumer_v2_response_supervised(
                &mut writer,
                super::ConsumerV2WireResponse::Response(super::ConsumerV2CallResponse {
                    correlation: NonZeroU32::MIN,
                    attempt_nonce: [0; 16],
                    request_commitment: [0; 32],
                    response: Box::new(response.clone()),
                }),
                super::MAX_NEGOTIATED_FRAME_SIZE,
                tokio::time::Instant::now() + Duration::from_secs(1),
                Duration::from_secs(1),
                &mut lifecycle,
                &config,
                &reauthentication,
                &mut reauthentication_changes,
                &mut material_changes,
                &ConsumerServerCancellation::new(),
                handshake.consumer_rotation_jitter(&client_identity),
            )
            .await
            .expect_err("a V2 response write failure must close the lane");
            assert!(matches!(error, ProtocolError::Io(_)), "{phase}");
            assert!(
                writer.accepted > 0,
                "{phase} crossed the response-write boundary"
            );
            assert_eq!(
                writer.write_polls_after_failure, 0,
                "{phase} failure cannot start a fallback response write"
            );
            assert_eq!(
                writer.flush_polls_after_failure, 0,
                "{phase} failure cannot flush a fallback response"
            );
        }
    }

    #[tokio::test]
    async fn forced_barrier_covers_plaintext_already_buffered_above_tls() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("buffered-tls-client");
        let server_identity = material_spiffe("buffered-tls-server");
        let client_material = RotatableClientMaterial::new(client_identity.as_str());
        let server_material = client_material.trusted_server_config(server_identity.as_str());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind buffered TLS peer");
        let address = listener.local_addr().expect("buffered TLS peer address");
        let release = Arc::new(Notify::new());
        let server_release = Arc::clone(&release);
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept buffered TLS client");
            tcp.set_nodelay(true).expect("disable fixture Nagle delay");
            let handshake = server_material
                .begin_handshake()
                .expect("server handshake snapshot");
            let acceptor = tokio_rustls::TlsAcceptor::from(super::consumer_server_tls_config(
                handshake.rustls_config(),
            ));
            let mut tls = acceptor.accept(tcp).await.expect("accept buffered TLS");
            handshake.admit().expect("admit unchanged server material");
            assert!(matches!(
                super::read_consumer_frame::<_, ConsumerWireRequest>(
                    &mut tls,
                    super::MAX_NEGOTIATED_FRAME_SIZE,
                )
                .await
                .expect("read client Hello"),
                ConsumerWireRequest::Hello(_)
            ));

            let capabilities = consumer_wire_response_from_public(
                ConsumerLeaseWireContext::Other,
                SessionConsumerResponse::Capabilities(BackendCapabilities::all_enabled()),
            )
            .expect("encode private capability response");
            let responses = [
                ConsumerWireResponse::HelloAck(super::ConsumerHelloAck {
                    transport_revision: super::SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
                    scope: scope(),
                    request_frame_size: u32::try_from(super::MAX_NEGOTIATED_FRAME_SIZE)
                        .expect("consumer frame cap fits u32"),
                }),
                ConsumerWireResponse::Response(ConsumerCallResponse {
                    correlation: NonZeroU32::new(1).expect("nonzero correlation"),
                    response: Box::new(capabilities.clone()),
                }),
                ConsumerWireResponse::Response(ConsumerCallResponse {
                    correlation: NonZeroU32::new(2).expect("nonzero correlation"),
                    response: Box::new(capabilities),
                }),
            ];
            let mut combined = Vec::new();
            for response in responses {
                let payload = serde_json::to_vec(&response).expect("encode buffered response");
                combined.extend_from_slice(
                    &u32::try_from(payload.len())
                        .expect("buffered response length fits u32")
                        .to_be_bytes(),
                );
                combined.extend_from_slice(&payload);
            }
            // One TLS application write puts both post-Ack responses in the
            // same record. Reading the first therefore leaves the second in
            // rustls plaintext, independent of another TCP poll.
            tls.write_all(&combined)
                .await
                .expect("write combined buffered responses");
            tls.flush().await.expect("flush buffered responses");
            server_release.notified().await;
        });

        let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
        let client = StatelessSessionConsumerClient::new_with_resolver(
            resolver,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            client_material.config(),
        );
        let barrier = Arc::new(PersistentConsumerIoBarrier::new());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut connection = client
            .connect(deadline, false, None, false, Some(Arc::clone(&barrier)))
            .await
            .expect("establish production-shaped barrier TLS lane");
        assert!(matches!(
            read_authenticated_consumer_frame_until::<_, ConsumerWireResponse>(
                &mut connection.reader,
                super::MAX_NEGOTIATED_FRAME_SIZE,
                deadline,
            )
            .await
            .expect("read first buffered response"),
            Some(ConsumerWireResponse::Response(ConsumerCallResponse {
                correlation,
                ..
            })) if correlation.get() == 1
        ));

        barrier.force();
        barrier.wait_quiescent().await;
        assert!(matches!(
            read_authenticated_consumer_frame_until::<_, ConsumerWireResponse>(
                &mut connection.reader,
                super::MAX_NEGOTIATED_FRAME_SIZE,
                deadline,
            )
            .await,
            Err(ProtocolError::Io(error)) if error.kind() == io::ErrorKind::ConnectionAborted
        ));
        release.notify_one();
        server.await.expect("join buffered TLS peer");
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
            .consumer_rotation_jitter(&client_identity);
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
    async fn stateless_v2_final_admission_rejects_rotated_generation_and_material_before_call() {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = material_spiffe("v2-final-client");
        let server_identity = material_spiffe("v2-final-server");
        let material = Arc::new(RotatableClientMaterial::new(client_identity.as_str()));
        let dispatches = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(V2CountingRejectingTestConsumer {
            v2_calls: Arc::clone(&dispatches),
        });
        let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
            scope(),
            [client_identity],
            std::iter::empty(),
        )
        .expect("V2 final-admission authorizer");
        let (server, address) = SessionQuorumConsumerServer::new(
            service,
            material.trusted_server_config(server_identity.as_str()),
            authorizer,
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen for stateless V2 final-admission race");
        let reauthentication = SessionReauthenticationControl::new();
        let rotated_material = Arc::clone(&material);
        let rotated_reauthentication = reauthentication.clone();
        let client = StatelessSessionConsumerClient::new(
            address,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            server_identity,
            scope(),
            material.config(),
        )
        .with_reauthentication_control(reauthentication)
        .with_final_admission_test_hook(Arc::new(move || {
            rotated_material.rotate();
            let _ = rotated_reauthentication.request_reauthentication();
        }));

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            client.execute_v2(SessionConsumerV2Request::new(
                scope(),
                SessionConsumerV2Operation::FencedTransitionV2Capability,
            )),
        )
        .await
        .expect("stateless V2 final-admission race stays bounded");
        assert_eq!(
            result,
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Deadline,
            })
        );
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);
        server.abort_and_wait().await;
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
                SessionConsumerRejection::Unauthorized,
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
    fn stateless_clone_lineage_isolates_v1_v2_and_watch_physical_admission() {
        let control = SessionReauthenticationControl::new();
        let (client, _material) = stateless_test_client(control);
        let clone = client.clone();
        let mut v1_requests = Vec::new();
        for _ in 0..MAX_STATELESS_SESSION_CONSUMER_REQUEST_CONNECTIONS {
            v1_requests.push(
                client
                    .physical_admission
                    .try_acquire_v1()
                    .expect("configured V1 cap admits its exact bound"),
            );
        }
        assert!(
            matches!(
                clone.physical_admission.try_acquire_v1(),
                Err(SessionConsumerClientError::Overloaded)
            ),
            "clones share the exact V1 physical admission before resolve or write"
        );
        let mut v2_requests = Vec::new();
        for _ in 0..MAX_PERSISTENT_SESSION_CONSUMER_REQUEST_CONNECTIONS {
            v2_requests.push(
                clone
                    .physical_admission
                    .try_acquire_v2()
                    .expect("configured V2 cap admits alongside a full V1 lane set"),
            );
        }
        assert!(
            matches!(
                client.physical_admission.try_acquire_v2(),
                Err(SessionConsumerClientError::Overloaded)
            ),
            "clones share the exact V2 physical admission before resolve or write"
        );
        let mut watches = Vec::new();
        for _ in 0..MAX_STATELESS_SESSION_CONSUMER_WATCH_CONNECTIONS {
            watches.push(
                clone
                    .physical_admission
                    .try_acquire_watch()
                    .expect("configured watch cap admits alongside full V1 and V2 lanes"),
            );
        }
        assert!(
            matches!(
                client.physical_admission.try_acquire_watch(),
                Err(SessionConsumerClientError::Overloaded)
            ),
            "watch physical admission remains exact and independent"
        );
        drop((v1_requests, v2_requests, watches));
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
        let persistent = PersistentSessionConsumerClient::from_stateless(stateless)
            .expect("valid persistent configuration");

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
        let persistent = PersistentSessionConsumerClient::from_stateless(rotation_stateless)
            .expect("valid persistent configuration");

        let (connection, material_lifecycle) = synthetic_consumer_connection(
            &persistent.pool.client,
            tokio::time::Instant::now()
                + persistent.pool.client.lifecycle_policy.rotation_jitter()
                + Duration::from_secs(1),
            Box::new(tokio::io::sink()),
        );
        let material_jitter = connection
            .rotation_jitter
            .min(persistent.pool.client.lifecycle_policy.rotation_jitter());
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
        let maximum_material_jitter = persistent.pool.client.lifecycle_policy.rotation_jitter();
        assert!(material_jitter <= maximum_material_jitter);
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
        )
        .expect("valid persistent configuration");

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
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(2),
            Duration::from_millis(1),
            Duration::from_millis(1),
            crate::lifecycle::DEFAULT_ROTATION_JITTER,
        )
        .expect("bounded edge-jitter policy");
        let client_a_handshake = client_a_config
            .begin_handshake()
            .expect("client A handshake snapshot");
        let client_a_jitter = client_a_handshake.consumer_rotation_jitter(&server_id);
        let stable_client_a_jitter = client_a_config
            .begin_handshake()
            .expect("second client A handshake snapshot")
            .consumer_rotation_jitter(&server_id);
        let client_b_jitter = client_b_config
            .begin_handshake()
            .expect("client B handshake snapshot")
            .consumer_rotation_jitter(&server_id);
        let server_a_jitter = server_config
            .begin_handshake()
            .expect("server handshake snapshot")
            .consumer_rotation_jitter(&client_a_id);
        assert_eq!(client_a_jitter, stable_client_a_jitter);
        assert_eq!(client_a_jitter, server_a_jitter);
        assert_ne!(client_a_jitter, client_b_jitter);
        assert!(
            !format!("{client_a_handshake:?}").contains(client_a_id.as_str()),
            "handshake diagnostics do not reveal the local authenticated identity"
        );
        let admitted_epoch = client_a_config.material_status().epoch();
        client_a_material.rotate();
        let current_material_status = client_a_config.material_status();
        let current_epoch = current_material_status.epoch();
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
        edge_a.observe_authenticated_rotation(now, 0, current_material_status, client_a_jitter);
        edge_b.observe_authenticated_rotation(now, 0, current_material_status, client_b_jitter);
        let edge_a_jitter = client_a_jitter;
        let edge_b_jitter = client_b_jitter;
        assert_ne!(edge_a_jitter, edge_b_jitter);
        assert_eq!(
            edge_a.retire_at(),
            current_material_status.published_at() + edge_a_jitter
        );
        assert_eq!(
            edge_b.retire_at(),
            current_material_status.published_at() + edge_b_jitter
        );
        assert!(
            edge_a.retire_at() <= current_material_status.published_at() + policy.rotation_jitter()
        );
        assert!(
            edge_b.retire_at() <= current_material_status.published_at() + policy.rotation_jitter()
        );
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
            server_a_jitter,
        ));
        let server_retire_at = server_material_lifecycle.retire_at();
        assert_eq!(server_retire_at, now + edge_a_jitter);
        tokio::time::advance(edge_a_jitter - Duration::from_nanos(1)).await;
        assert!(server_connection_current(
            &mut server_material_lifecycle,
            &server_config,
            &server_control,
            server_a_jitter,
        ));
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert!(!server_connection_current(
            &mut server_material_lifecycle,
            &server_config,
            &server_control,
            server_a_jitter,
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
            server_a_jitter,
        ));
        assert_eq!(
            server_explicit_lifecycle.recorded_retirement_reason(),
            Some(RetirementReason::Explicit)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn late_first_material_observation_uses_the_publication_deadline() {
        let client_id = material_spiffe("late-observation-client");
        let server_id = material_spiffe("late-observation-server");
        let client_material = RotatableClientMaterial::new(client_id.as_str());
        let server_material = RotatableServerMaterial::new(server_id.as_str());
        let client_config = client_material.config();
        let server_config = server_material.config();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(2),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_secs(10),
        )
        .expect("bounded late-observation policy");
        let client_jitter = client_config
            .begin_handshake()
            .expect("client handshake snapshot")
            .consumer_rotation_jitter(&server_id);
        let server_jitter = server_config
            .begin_handshake()
            .expect("server handshake snapshot")
            .consumer_rotation_jitter(&client_id);
        let started_at = tokio::time::Instant::now();
        let client_epoch = client_config.material_status().epoch();
        let server_epoch = server_config.material_status().epoch();
        let client_control = SessionReauthenticationControl::new();
        let server_control = SessionReauthenticationControl::new();
        let mut client_lifecycle = ConnectionLifecycle::new(
            policy,
            started_at,
            None,
            None,
            client_control.generation(),
            Some(client_epoch),
        )
        .expect("client lifecycle");
        let mut server_lifecycle = ConnectionLifecycle::new(
            policy,
            started_at,
            None,
            None,
            server_control.generation(),
            Some(server_epoch),
        )
        .expect("server lifecycle");

        client_material.rotate();
        server_material.rotate();
        let client_published_at = client_config.material_status().published_at();
        let server_published_at = server_config.material_status().published_at();
        tokio::time::advance(policy.rotation_jitter() + Duration::from_nanos(1)).await;

        assert!(!consumer_connection_current(
            &mut client_lifecycle,
            &client_config,
            &client_control,
            client_jitter,
        ));
        assert!(!server_connection_current(
            &mut server_lifecycle,
            &server_config,
            &server_control,
            server_jitter,
        ));
        assert_eq!(
            client_lifecycle.retire_at(),
            client_published_at + client_jitter
        );
        assert_eq!(
            server_lifecycle.retire_at(),
            server_published_at + server_jitter
        );
        assert_eq!(
            client_lifecycle.recorded_retirement_reason(),
            Some(RetirementReason::MaterialEpoch)
        );
        assert_eq!(
            server_lifecycle.recorded_retirement_reason(),
            Some(RetirementReason::MaterialEpoch)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn checked_out_lane_discard_is_counted_once_and_idle_return_is_not() {
        let control = SessionReauthenticationControl::new();
        let (stateless, _material) = stateless_test_client(control);
        let persistent = PersistentSessionConsumerClient::from_stateless(stateless)
            .expect("valid persistent configuration");

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
        let client = PersistentSessionConsumerClient::from_stateless(stateless)
            .expect("valid persistent configuration");
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
        let first = PersistentSessionConsumerClient::from_stateless(stateless.clone())
            .expect("valid persistent configuration");
        let sibling = PersistentSessionConsumerClient::from_stateless(stateless)
            .expect("valid persistent configuration");
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
            )
            .expect("valid persistent configuration");
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
                .record_error(result.into_client_error(), may_have_sent, true);
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
            let persistent = PersistentSessionConsumerClient::from_stateless(client)
                .expect("valid persistent configuration");
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
                .record_error(result.into_client_error(), may_have_sent, true);
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

    #[test]
    fn forced_barrier_rejects_an_enter_that_sampled_running_before_force() {
        let barrier = Arc::new(PersistentConsumerIoBarrier::new());
        let (sampled_tx, sampled_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let resume_rx = Arc::new(std::sync::Mutex::new(resume_rx));
        barrier.set_enter_hook(Some(Arc::new({
            let resume_rx = Arc::clone(&resume_rx);
            move || {
                sampled_tx.send(()).expect("publish pre-CAS sample");
                resume_rx
                    .lock()
                    .expect("lock barrier hook receiver")
                    .recv()
                    .expect("resume barrier admission");
            }
        })));

        let contender = std::thread::spawn({
            let barrier = Arc::clone(&barrier);
            move || barrier.enter().is_some()
        });
        sampled_rx.recv().expect("barrier sampled Running");
        barrier.force();
        resume_tx.send(()).expect("release admission CAS");
        assert!(!contender.join().expect("join admission contender"));
        assert!(barrier.is_forced());
        assert_eq!(
            barrier.state.load(Ordering::Acquire) & PersistentConsumerIoBarrier::ACTIVE_MASK,
            0
        );
    }

    #[tokio::test]
    async fn forced_barrier_blocks_every_later_setup_io_poll() {
        let barrier = Arc::new(PersistentConsumerIoBarrier::new());
        let polls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());
        let waker = Arc::new(std::sync::Mutex::new(None::<std::task::Waker>));
        let future = std::future::poll_fn({
            let polls = Arc::clone(&polls);
            let started = Arc::clone(&started);
            let waker = Arc::clone(&waker);
            move |context| {
                polls.fetch_add(1, Ordering::SeqCst);
                *waker.lock().expect("store setup I/O waker") = Some(context.waker().clone());
                started.notify_one();
                Poll::Pending::<io::Result<()>>
            }
        });
        let setup = tokio::spawn({
            let barrier = Arc::clone(&barrier);
            async move { poll_persistent_consumer_setup_io(future, Some(&barrier)).await }
        });

        started.notified().await;
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        barrier.force();
        waker
            .lock()
            .expect("load setup I/O waker")
            .take()
            .expect("setup I/O registered a waker")
            .wake();
        let error = setup
            .await
            .expect("join setup I/O")
            .expect_err("forced setup I/O is rejected before the inner future is repolled");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        barrier.wait_quiescent().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forced_barrier_waits_for_an_already_executing_setup_poll() {
        let barrier = Arc::new(PersistentConsumerIoBarrier::new());
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let setup = tokio::spawn({
            let barrier = Arc::clone(&barrier);
            async move {
                poll_persistent_consumer_setup_io(
                    std::future::poll_fn(move |_| {
                        entered_tx.send(()).expect("publish executing setup poll");
                        release_rx.recv().expect("release executing setup poll");
                        Poll::Ready(Ok::<_, io::Error>(()))
                    }),
                    Some(&barrier),
                )
                .await
            }
        });
        tokio::task::spawn_blocking(move || entered_rx.recv())
            .await
            .expect("join setup-poll observer")
            .expect("observe setup poll");

        barrier.force();
        let quiescent = tokio::spawn({
            let barrier = Arc::clone(&barrier);
            async move { barrier.wait_quiescent().await }
        });
        tokio::task::yield_now().await;
        assert!(
            !quiescent.is_finished(),
            "forced completion must wait for the already executing TCP/TLS/Hello poll"
        );
        release_tx.send(()).expect("release setup poll");
        assert!(
            setup.await.expect("join setup poll").is_ok(),
            "the already executing setup poll completes before quiescence"
        );
        quiescent.await.expect("join quiescence waiter");
        assert!(barrier.is_forced());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persistent_shutdown_waits_for_the_actual_resolver_poll() {
        let control = SessionReauthenticationControl::new();
        let (mut stateless, _material) = stateless_test_client(control);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let polls = Arc::new(AtomicUsize::new(0));
        stateless.resolve = Arc::new({
            let polls = Arc::clone(&polls);
            let entered_tx = Arc::new(StdMutex::new(Some(entered_tx)));
            let release_rx = Arc::new(StdMutex::new(release_rx));
            move || {
                let polls = Arc::clone(&polls);
                let entered_tx = Arc::clone(&entered_tx);
                let release_rx = Arc::clone(&release_rx);
                Box::pin(std::future::poll_fn(move |_| {
                    polls.fetch_add(1, Ordering::SeqCst);
                    if let Some(entered_tx) = entered_tx
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                    {
                        entered_tx.send(()).expect("publish resolver poll entry");
                    }
                    release_rx
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .recv()
                        .expect("release actual resolver poll");
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "fixed resolver failure",
                    )))
                }))
            }
        });
        let config = PersistentSessionConsumerConfig::try_new(
            1,
            0,
            Duration::from_millis(250),
            1,
            Duration::from_millis(1_500),
            1,
            Duration::ZERO,
            Duration::from_millis(1),
        )
        .expect("short bounded shutdown configuration");
        let persistent = PersistentSessionConsumerClient::try_from_stateless(stateless, config)
            .expect("valid persistent client");
        let call = tokio::spawn({
            let persistent = persistent.clone();
            async move { persistent.capabilities().await }
        });
        tokio::task::spawn_blocking(move || entered_rx.recv())
            .await
            .expect("join resolver observer")
            .expect("observe actual resolver poll");

        let shutdown = tokio::spawn({
            let persistent = persistent.clone();
            async move { persistent.shutdown().await }
        });
        while !persistent.pool.shutdown_io.is_forced() {
            tokio::task::yield_now().await;
        }
        assert!(
            !shutdown.is_finished(),
            "shutdown completion waits for the resolver poll already executing under the barrier"
        );
        release_tx.send(()).expect("release resolver poll");
        let _ = call.await.expect("join resolver call");
        let _ = shutdown.await.expect("join bounded shutdown");
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn pre_request_expiry_never_starts_a_retry_after_the_fixed_deadline() {
        let control = SessionReauthenticationControl::new();
        let (mut stateless, _material) = stateless_test_client(control);
        let resolutions = Arc::new(AtomicUsize::new(0));
        let resolve_started = Arc::new(tokio::sync::Notify::new());
        stateless.resolve = Arc::new({
            let resolutions = Arc::clone(&resolutions);
            let resolve_started = Arc::clone(&resolve_started);
            move || {
                let resolutions = Arc::clone(&resolutions);
                let resolve_started = Arc::clone(&resolve_started);
                Box::pin(async move {
                    resolutions.fetch_add(1, Ordering::SeqCst);
                    resolve_started.notify_one();
                    std::future::pending::<io::Result<std::net::SocketAddr>>().await
                })
            }
        });
        stateless.pre_request_connection_timeout = Some(Duration::from_millis(25));
        stateless.operation_timeout = Duration::from_secs(1);
        let persistent = PersistentSessionConsumerClient::from_stateless(stateless)
            .expect("valid persistent configuration");
        let call = tokio::spawn({
            let persistent = persistent.clone();
            async move { persistent.capabilities().await }
        });

        resolve_started.notified().await;
        tokio::time::advance(Duration::from_millis(24)).await;
        assert!(!call.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(
            call.await.expect("join bounded setup call"),
            Err(SessionConsumerClientError::Unavailable)
        );
        assert_eq!(resolutions.load(Ordering::SeqCst), 1);
        let diagnostics = persistent.diagnostics().await;
        assert_eq!(diagnostics.setup_attempts, 1);
        assert_eq!(diagnostics.setup_failures, 1);
        assert_eq!(diagnostics.not_transmitted, 1);
        persistent.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn checked_out_prewrite_failure_never_retries_past_the_fixed_setup_deadline() {
        let control = SessionReauthenticationControl::new();
        let (mut stateless, _material) = stateless_test_client(control);
        let resolutions = Arc::new(AtomicUsize::new(0));
        stateless.resolve = Arc::new({
            let resolutions = Arc::clone(&resolutions);
            move || {
                let resolutions = Arc::clone(&resolutions);
                Box::pin(async move {
                    resolutions.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<io::Result<std::net::SocketAddr>>().await
                })
            }
        });
        stateless.pre_request_connection_timeout = Some(Duration::from_millis(25));
        stateless.operation_timeout = Duration::from_secs(1);
        let persistent = PersistentSessionConsumerClient::from_stateless(stateless)
            .expect("valid persistent configuration");
        let (connection, _) = synthetic_consumer_connection(
            &persistent.pool.client,
            tokio::time::Instant::now() + Duration::from_secs(1),
            Box::new(PhaseFailWriter {
                accepted: 0,
                fail_after: Some(0),
                fail_flush: false,
            }),
        );
        persistent
            .pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(connection);
        let call = tokio::spawn({
            let persistent = persistent.clone();
            async move { persistent.capabilities().await }
        });

        tokio::task::yield_now().await;
        assert!(!call.is_finished());
        tokio::time::advance(Duration::from_millis(24)).await;
        assert!(!call.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(
            call.await.expect("join checked-out call"),
            Err(SessionConsumerClientError::Unavailable)
        );
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            0,
            "the retry delay consumes the remaining setup budget before a resolver can run"
        );
        let diagnostics = persistent.diagnostics().await;
        assert_eq!(diagnostics.not_transmitted, 1);
        assert_eq!(diagnostics.outcome_unknown, 0);
        persistent.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn forced_shutdown_precedes_ready_request_and_response_io() {
        let control = SessionReauthenticationControl::new();
        let (client, _material) = stateless_test_client(control);
        let persistent = PersistentSessionConsumerClient::from_stateless(client)
            .expect("valid persistent configuration");

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
            response: Box::new(ConsumerSessionResponseWire::AcquireLease(Err(
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
    async fn unary_active_frame_idle_does_not_record_a_later_lifecycle_overrun() {
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
        let (mut pending_peer, pending_reader) = tokio::io::duplex(64);
        connection.reader = Box::new(pending_reader);
        pending_peer
            .write_all(&[0])
            .await
            .expect("start one authenticated response frame");
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

        let v2_call = ConsumerV2WireRequest::Call(ConsumerV2Call {
            correlation: NonZeroU32::MIN,
            attempt_nonce: [0; 16],
            request_commitment: super::v2_request_commitment(&v2_effectful_request(0x87))
                .expect("test commitment"),
            request: Box::new(v2_effectful_request(0x87)),
        });
        let payload = serde_json::to_vec(&v2_call).expect("V2 call encodes");
        let mut partial_frame = u32::try_from(payload.len())
            .expect("V2 call length fits u32")
            .to_be_bytes()
            .to_vec();
        partial_frame.push(payload[0]);
        let (mut v2_peer, mut v2_reader) = tokio::io::duplex(64 * 1024);
        v2_peer
            .write_all(&partial_frame)
            .await
            .expect("write V2 Call prefix and payload byte");
        let v2_partial = read_authenticated_consumer_frame_within::<_, ConsumerV2WireRequest>(
            &mut v2_reader,
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_millis(100),
        );
        tokio::pin!(v2_partial);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(v2_partial.as_mut(), context).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(matches!(
            v2_partial.await,
            Err(crate::ProtocolError::Io(error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        drop(v2_peer);

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
