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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use futures_util::stream::{self, BoxStream, StreamExt};
use opc_session_store::{
    session_consumer_batch_result_into_store, BackendCapabilities, CompareAndSet,
    CompareAndSetResult, LeaseError, LeaseGuard, OwnerId, RecordExpiryPreflight, RestoreScanPage,
    RestoreScanRequest, SessionConsumerAuthorizationManifest, SessionConsumerChange,
    SessionConsumerIdentity, SessionConsumerOperation, SessionConsumerOutcomeUnknown,
    SessionConsumerRejection, SessionConsumerRequest, SessionConsumerRequestId,
    SessionConsumerResponse, SessionConsumerScope, SessionConsumerStoreError, SessionOp,
    SessionOpResult, SessionQuorumConsumer, StatelessSessionConsumer, StoreError,
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
    read_authenticated_frame_payload_until, read_frame_payload, write_frame_bounded_until,
    write_frame_bounded_until_classified, FrameWriteError, MAX_NEGOTIATED_FRAME_SIZE,
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

struct QueuedConsumerWatchItem {
    item: Result<SessionConsumerChange, StoreError>,
    // Retained for precisely as long as this item occupies the bounded local
    // queue. Dropping it returns its byte budget to the producer.
    _byte_permit: OwnedSemaphorePermit,
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
            Self::NotTransmitted { .. } => None,
        }
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
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerHelloAck {
    transport_revision: u16,
    scope: SessionConsumerScope,
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
    response: Box<SessionConsumerResponse>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BorrowedConsumerCallResponse<'a> {
    correlation: NonZeroU32,
    response: &'a SessionConsumerResponse,
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
    Batch { contains_mutation: bool },
    ScanRestoreRecords,
    Watch,
    AcquireLease,
    RenewLease,
    ReleaseLease,
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
            // A newer operation reaching this revision is conservatively an
            // effectful mutation for timeout and response-family purposes.
            _ => Self::CompareAndSet,
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
                ConsumerOperationKind::AcquireLease
                    | ConsumerOperationKind::RenewLease
                    | ConsumerOperationKind::ReleaseLease,
                SessionConsumerResponse::OutcomeUnknown(SessionConsumerOutcomeUnknown::Lease),
            )
    )
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
    let Some(payload) =
        read_authenticated_frame_payload_until(reader, max_frame_size, deadline).await?
    else {
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

async fn read_consumer_frame_within<R, T>(
    reader: &mut R,
    max_frame_size: usize,
    timeout: Duration,
) -> Result<T, ProtocolError>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de> + Serialize,
{
    tokio::time::timeout(timeout, read_consumer_frame(reader, max_frame_size))
        .await
        .map_err(|_| {
            ProtocolError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out reading consumer frame from peer",
            ))
        })?
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

struct ConsumerConnection {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    lifecycle: ConnectionLifecycle,
    admitted_generation: u64,
    admitted_material_epoch: opc_tls::TlsMaterialEpoch,
    next_correlation: NonZeroU32,
    calls: usize,
    idle_deadline: tokio::time::Instant,
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
            self.admitted_generation,
            self.admitted_material_epoch,
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
) {
    lifecycle.observe_rotation(
        now,
        generation,
        Some(material_epoch),
        b"session-quorum-consumer",
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
    admitted_generation: u64,
    admitted_material_epoch: opc_tls::TlsMaterialEpoch,
) -> bool {
    let now = tokio::time::Instant::now();
    let current_generation = reauthentication.generation();
    let current_material_epoch = config.material_status().epoch();
    observe_consumer_rotation(lifecycle, now, current_generation, current_material_epoch);
    if lifecycle.retirement(now).is_some() {
        return false;
    }
    if let Some(reason) =
        lifecycle.evidence_mismatch_reason(current_generation, Some(current_material_epoch))
    {
        // A cached or not-yet-dispatched connection cannot keep serving old
        // authentication during rotation jitter. This records the actual
        // reason exactly once before the socket is physically discarded.
        lifecycle.record_forced_retirement(reason);
        return false;
    }
    admitted_generation == current_generation && admitted_material_epoch == current_material_epoch
}

fn record_consumer_hard_overrun(lifecycle: &ConnectionLifecycle) {
    let _ = lifecycle.retirement(tokio::time::Instant::now());
    lifecycle.record_hard_overrun();
}

fn server_connection_current(
    lifecycle: &mut ConnectionLifecycle,
    config: &opc_tls::AuthenticatedServerConfig,
    reauthentication: &SessionReauthenticationControl,
    admitted_generation: u64,
    admitted_material_epoch: opc_tls::TlsMaterialEpoch,
) -> bool {
    let now = tokio::time::Instant::now();
    let current_generation = reauthentication.generation();
    let current_material_epoch = config.material_status().epoch();
    observe_consumer_rotation(lifecycle, now, current_generation, current_material_epoch);
    if lifecycle.retirement(now).is_some() {
        return false;
    }
    if let Some(reason) =
        lifecycle.evidence_mismatch_reason(current_generation, Some(current_material_epoch))
    {
        lifecycle.record_forced_retirement(reason);
        return false;
    }
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
        }
    }

    /// Set the finite bootstrap and active-frame idle timeout.
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
        record_setup_phase_attempt(setup_counters, ConsumerSetupPhase::Resolve);
        let address = tokio::time::timeout_at(pre_request_deadline, (self.resolve)())
            .await
            .map_err(|_| {
                record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Resolve);
                SessionConsumerClientError::Unavailable
            })?
            .map_err(|_| {
                record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Resolve);
                SessionConsumerClientError::Unavailable
            })?;
        let generation = self.reauthentication.generation();
        record_setup_phase_attempt(setup_counters, ConsumerSetupPhase::Tcp);
        let tcp = tokio::time::timeout_at(pre_request_deadline, TcpStream::connect(address))
            .await
            .map_err(|_| {
                record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Tcp);
                pre_request_timeout_error(pre_request_budget_active)
            })?
            .map_err(|_| {
                record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Tcp);
                SessionConsumerClientError::Unavailable
            })?;
        tcp.set_nodelay(true).map_err(|_| {
            record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Tcp);
            SessionConsumerClientError::Unavailable
        })?;
        record_setup_phase_attempt(setup_counters, ConsumerSetupPhase::Tls);
        let handshake = self.tls_config.begin_handshake().map_err(|_| {
            record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Tls);
            SessionConsumerClientError::Authentication
        })?;
        let connector =
            tokio_rustls::TlsConnector::from(consumer_client_tls_config(handshake.rustls_config()));
        let tls = tokio::time::timeout_at(
            pre_request_deadline,
            connector.connect(self.server_name.clone(), tcp),
        )
        .await
        .map_err(|_| {
            record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Tls);
            pre_request_timeout_error(pre_request_budget_active)
        })?
        .map_err(|error| SessionConsumerClientError::from(classify_tls_io_error(error)))
        .map_err(|error| {
            record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Tls);
            pre_request_error(error, pre_request_budget_active)
        })?;
        let established_at = tokio::time::Instant::now();
        if tls.get_ref().1.alpn_protocol() != Some(SESSION_QUORUM_CONSUMER_ALPN) {
            record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Tls);
            return Err(SessionConsumerClientError::Protocol);
        }
        let peer =
            opc_tls::peer_tls_identity_from_client_connection(tls.get_ref().1).map_err(|_| {
                record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Tls);
                SessionConsumerClientError::Authentication
            })?;
        if peer.spiffe_id() != &self.expected_server_identity {
            record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Tls);
            return Err(SessionConsumerClientError::Authentication);
        }
        let (mut reader, mut writer) = tokio::io::split(tls);
        record_setup_phase_attempt(setup_counters, ConsumerSetupPhase::Hello);
        // The server starts its between-frame timeout after HelloAck. Stamp
        // from before our Hello write and never extend beyond the protocol's
        // fixed five-second idle ceiling, making this conservatively earlier.
        let idle_deadline = tokio::time::Instant::now()
            .checked_add(self.idle_timeout.min(DEFAULT_CONSUMER_IDLE_TIMEOUT))
            .ok_or(SessionConsumerClientError::Protocol)?;
        let hello = ConsumerWireRequest::Hello(ConsumerHello {
            transport_revision: SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
            scope: self.scope,
        });
        write_frame_bounded_until(
            &mut writer,
            &hello,
            MAX_NEGOTIATED_FRAME_SIZE,
            pre_request_deadline,
        )
        .await
        .map_err(SessionConsumerClientError::from)
        .map_err(|error| {
            record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Hello);
            pre_request_error(error, pre_request_budget_active)
        })?;
        let ack = tokio::time::timeout_at(
            pre_request_deadline,
            read_consumer_frame::<_, ConsumerWireResponse>(&mut reader, MAX_NEGOTIATED_FRAME_SIZE),
        )
        .await
        .map_err(|_| {
            record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Hello);
            pre_request_timeout_error(pre_request_budget_active)
        })?
        .map_err(SessionConsumerClientError::from)
        .map_err(|error| {
            record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Hello);
            pre_request_error(error, pre_request_budget_active)
        })?;
        match ack {
            ConsumerWireResponse::HelloAck(ack)
                if ack.transport_revision == SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION
                    && ack.scope == self.scope => {}
            ConsumerWireResponse::HelloRejected(SessionConsumerRejection::ScopeMismatch) => {
                record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Hello);
                return Err(SessionConsumerClientError::Scope);
            }
            ConsumerWireResponse::HelloRejected(SessionConsumerRejection::Unauthorized) => {
                record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Hello);
                return Err(SessionConsumerClientError::Authentication);
            }
            _ => {
                record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Hello);
                return Err(SessionConsumerClientError::Protocol);
            }
        }
        let admission = handshake.admit().map_err(|_| {
            record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Hello);
            SessionConsumerClientError::Authentication
        })?;
        if generation != self.reauthentication.generation()
            || admission.epoch() != self.tls_config.material_status().epoch()
        {
            record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Hello);
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
        .map_err(|_| {
            record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Hello);
            SessionConsumerClientError::Protocol
        })?;
        let mut connection = ConsumerConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            lifecycle,
            admitted_generation: generation,
            admitted_material_epoch: admission.epoch(),
            next_correlation: NonZeroU32::MIN,
            calls: 0,
            idle_deadline,
        };
        if !connection.current(&self.tls_config, &self.reauthentication) {
            record_setup_phase_failure(setup_counters, ConsumerSetupPhase::Hello);
            return Err(SessionConsumerClientError::Deadline);
        }
        Ok(connection)
    }

    async fn execute_on_connection(
        &self,
        connection: &mut ConsumerConnection,
        request: &SessionConsumerRequest,
        pre_request_deadline: tokio::time::Instant,
        pre_request_budget_active: bool,
        deadline: tokio::time::Instant,
        mut force_shutdown: Option<watch::Receiver<PersistentShutdownPhase>>,
    ) -> Result<SessionConsumerResponse, SessionConsumerCallError> {
        let mut reauthentication_changes = self.reauthentication.subscribe();
        let mut material_changes = Some(self.tls_config.subscribe_material_changes());
        if !connection.current(&self.tls_config, &self.reauthentication) {
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Unavailable,
            ));
        }
        let correlation = connection
            .take_correlation()
            .map_err(SessionConsumerCallError::BeforeCallWrite)?;
        let operation = ConsumerOperationKind::from_operation(request.operation());
        let outbound = BorrowedConsumerWireRequest::Call(BorrowedConsumerCall {
            correlation,
            request,
        });
        // The peer's next-frame idle retirement starts after its response
        // write. Stamping before our call write is conservatively earlier and
        // prevents an idle FIN race from ever being recycled as a new call.
        connection.idle_deadline = tokio::time::Instant::now()
            .checked_add(self.idle_timeout.min(DEFAULT_CONSUMER_IDLE_TIMEOUT))
            .ok_or(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Protocol,
            ))?;
        let write_result = {
            let lifecycle = &mut connection.lifecycle;
            let initial_hard_deadline = lifecycle.hard_deadline().map_err(|_| {
                SessionConsumerCallError::BeforeCallWrite(SessionConsumerClientError::Protocol)
            })?;
            let write_deadline = pre_request_deadline.min(initial_hard_deadline);
            let write = write_frame_bounded_until_classified(
                &mut connection.writer,
                &outbound,
                MAX_NEGOTIATED_FRAME_SIZE,
                write_deadline,
            );
            tokio::pin!(write);
            loop {
                let hard_deadline = lifecycle.hard_deadline().map_err(|_| {
                    SessionConsumerCallError::MayHaveSent(SessionConsumerClientError::Protocol)
                })?;
                tokio::select! {
                    biased;
                    result = &mut write => {
                        if hard_deadline <= write_deadline
                            && tokio::time::Instant::now() >= hard_deadline
                        {
                            record_consumer_hard_overrun(lifecycle);
                            if result.is_ok() {
                                return Err(SessionConsumerCallError::MayHaveSent(
                                    SessionConsumerClientError::Deadline,
                                ));
                            }
                        }
                        break result;
                    },
                    _ = wait_for_optional_forced_shutdown(&mut force_shutdown) => {
                        return Err(SessionConsumerCallError::MayHaveSent(
                            SessionConsumerClientError::ShuttingDown,
                        ));
                    }
                    _ = wait_for_shortened_deadline(hard_deadline, write_deadline) => {
                        record_consumer_hard_overrun(lifecycle);
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
                        );
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        observe_consumer_rotation(
                            lifecycle,
                            tokio::time::Instant::now(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status().epoch(),
                        );
                    }
                }
            }
        };
        write_result
            .map_err(|error| classify_call_write_error(error, pre_request_budget_active))?;
        let response = {
            let lifecycle = &mut connection.lifecycle;
            let read = read_consumer_frame::<_, ConsumerWireResponse>(
                &mut connection.reader,
                MAX_NEGOTIATED_FRAME_SIZE,
            );
            tokio::pin!(read);
            loop {
                let hard_deadline = lifecycle.hard_deadline().map_err(|_| {
                    SessionConsumerCallError::MayHaveSent(SessionConsumerClientError::Protocol)
                })?;
                let response_deadline = deadline.min(hard_deadline);
                let response = tokio::select! {
                    biased;
                    response = &mut read => {
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
                    _ = wait_for_optional_forced_shutdown(&mut force_shutdown) => {
                        return Err(SessionConsumerCallError::MayHaveSent(
                            SessionConsumerClientError::ShuttingDown,
                        ));
                    }
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
                            self.tls_config.material_status().epoch(),
                        );
                        None
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        observe_consumer_rotation(
                            lifecycle,
                            tokio::time::Instant::now(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status().epoch(),
                        );
                        None
                    }
                };
                if let Some(response) = response {
                    break response;
                }
            }
        };
        let response = response
            .map_err(SessionConsumerClientError::from)
            .map_err(SessionConsumerCallError::MayHaveSent)?;
        match response {
            ConsumerWireResponse::Response(ConsumerCallResponse {
                correlation: received,
                response,
            }) if exact_correlation(correlation, received).is_ok()
                && response_matches_operation(operation, response.as_ref()) =>
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
            .connect(pre_request_deadline, pre_request_budget_active, None)
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
            SessionConsumerResponse::Rejected(SessionConsumerRejection::ScopeMismatch) => {
                Err(SessionConsumerClientError::Scope)
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
        self.watch_with_counters(start_sequence, None, None).await
    }

    async fn write_watch_call_on_connection(
        &self,
        connection: &mut ConsumerConnection,
        request: &SessionConsumerRequest,
        pre_request_deadline: tokio::time::Instant,
        reauthentication_changes: &mut watch::Receiver<u64>,
        material_changes: &mut Option<opc_tls::TlsMaterialStatusReceiver>,
    ) -> Result<NonZeroU32, SessionConsumerClientError> {
        // The receivers are constructed before this check. A rotation between
        // connect's final check and subscription is visible in the synchronous
        // epoch snapshot; a later rotation is visible to the supervised write.
        if !connection.current(&self.tls_config, &self.reauthentication) {
            return Err(SessionConsumerClientError::Unavailable);
        }
        let correlation = connection.take_correlation()?;
        connection.idle_deadline = tokio::time::Instant::now()
            .checked_add(self.idle_timeout.min(DEFAULT_CONSUMER_IDLE_TIMEOUT))
            .ok_or(SessionConsumerClientError::Protocol)?;
        let outbound = BorrowedConsumerWireRequest::Call(BorrowedConsumerCall {
            correlation,
            request,
        });
        {
            let lifecycle = &mut connection.lifecycle;
            let initial_hard_deadline = lifecycle
                .hard_deadline()
                .map_err(|_| SessionConsumerClientError::Protocol)?;
            let write_deadline = pre_request_deadline.min(initial_hard_deadline);
            let write = write_frame_bounded_until(
                &mut connection.writer,
                &outbound,
                MAX_NEGOTIATED_FRAME_SIZE,
                write_deadline,
            );
            tokio::pin!(write);
            loop {
                let hard_deadline = lifecycle
                    .hard_deadline()
                    .map_err(|_| SessionConsumerClientError::Protocol)?;
                let result = tokio::select! {
                    biased;
                    result = &mut write => {
                        if hard_deadline <= write_deadline
                            && tokio::time::Instant::now() >= hard_deadline
                        {
                            record_consumer_hard_overrun(lifecycle);
                            return Err(SessionConsumerClientError::Deadline);
                        }
                        Some(result)
                    },
                    _ = wait_for_shortened_deadline(hard_deadline, write_deadline) => {
                        record_consumer_hard_overrun(lifecycle);
                        return Err(SessionConsumerClientError::Deadline);
                    }
                    _ = reauthentication_changes.changed() => {
                        observe_consumer_rotation(
                            lifecycle,
                            tokio::time::Instant::now(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status().epoch(),
                        );
                        None
                    }
                    _ = wait_consumer_material_change(material_changes) => {
                        observe_consumer_rotation(
                            lifecycle,
                            tokio::time::Instant::now(),
                            self.reauthentication.generation(),
                            self.tls_config.material_status().epoch(),
                        );
                        None
                    }
                };
                if let Some(result) = result {
                    result.map_err(SessionConsumerClientError::from)?;
                    break;
                }
            }
        }
        // A rotation notification may race a write that completes in the same
        // poll. Never publish a watch admitted on a connection that is no
        // longer current, even though Watch itself has no mutation effect.
        if !connection.current(&self.tls_config, &self.reauthentication) {
            return Err(SessionConsumerClientError::Unavailable);
        }
        Ok(correlation)
    }

    async fn watch_with_counters(
        &self,
        start_sequence: u64,
        setup_counters: Option<&PersistentConsumerCounters>,
        persistent_runtime: Option<PersistentWatchRuntime>,
    ) -> Result<BoxStream<'static, Result<SessionConsumerChange, StoreError>>, StoreError> {
        let started_at = tokio::time::Instant::now();
        let deadline = started_at
            .checked_add(self.operation_timeout)
            .ok_or_else(|| StoreError::BackendUnavailable("consumer watch unavailable".into()))?;
        let (pre_request_deadline, pre_request_budget_active) =
            self.pre_request_deadline(started_at, deadline);
        let mut connection = self
            .connect(
                pre_request_deadline,
                pre_request_budget_active,
                setup_counters,
            )
            .await
            .map_err(|_| StoreError::BackendUnavailable("consumer watch unavailable".into()))?;
        let mut reauthentication_changes = self.reauthentication.subscribe();
        let mut material_changes = Some(self.tls_config.subscribe_material_changes());
        ensure_pre_request_budget_remaining(pre_request_deadline, pre_request_budget_active)
            .map_err(|_| StoreError::BackendUnavailable("consumer watch unavailable".into()))?;
        let request = self.request(
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::Watch { start_sequence },
        );
        let correlation = self
            .write_watch_call_on_connection(
                &mut connection,
                &request,
                pre_request_deadline,
                &mut reauthentication_changes,
                &mut material_changes,
            )
            .await
            .map_err(|_| StoreError::BackendUnavailable("consumer watch unavailable".into()))?;
        let response = {
            let watch_response_deadline = deadline.min(connection.lifecycle.retire_at());
            let response_read = tokio::time::timeout_at(
                watch_response_deadline,
                read_consumer_frame::<_, ConsumerWireResponse>(
                    &mut connection.reader,
                    MAX_NEGOTIATED_FRAME_SIZE,
                ),
            );
            tokio::pin!(response_read);
            loop {
                let now = tokio::time::Instant::now();
                if now >= watch_response_deadline
                    || !consumer_connection_current(
                        &mut connection.lifecycle,
                        &self.tls_config,
                        &self.reauthentication,
                        connection.admitted_generation,
                        connection.admitted_material_epoch,
                    )
                {
                    let _ = connection.lifecycle.retirement(now);
                    return Err(StoreError::BackendUnavailable(
                        "consumer watch unavailable".into(),
                    ));
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
                                connection.admitted_generation,
                                connection.admitted_material_epoch,
                            )
                        {
                            let _ = connection.lifecycle.retirement(now);
                            return Err(StoreError::BackendUnavailable(
                                "consumer watch unavailable".into(),
                            ));
                        }
                        Some(response)
                    },
                    _ = tokio::time::sleep_until(connection.lifecycle.retire_at()) => {
                        let _ = connection
                            .lifecycle
                            .retirement(tokio::time::Instant::now());
                        return Err(StoreError::BackendUnavailable(
                            "consumer watch unavailable".into(),
                        ));
                    }
                    _ = reauthentication_changes.changed() => {
                        if !consumer_connection_current(
                            &mut connection.lifecycle,
                            &self.tls_config,
                            &self.reauthentication,
                            connection.admitted_generation,
                            connection.admitted_material_epoch,
                        ) {
                            return Err(StoreError::BackendUnavailable(
                                "consumer watch unavailable".into(),
                            ));
                        }
                        None
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        if !consumer_connection_current(
                            &mut connection.lifecycle,
                            &self.tls_config,
                            &self.reauthentication,
                            connection.admitted_generation,
                            connection.admitted_material_epoch,
                        ) {
                            return Err(StoreError::BackendUnavailable(
                                "consumer watch unavailable".into(),
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
        .map_err(|_| StoreError::BackendUnavailable("consumer watch unavailable".into()))?
        .map_err(|_| StoreError::BackendUnavailable("consumer watch unavailable".into()))?;
        if !matches!(
            response,
            ConsumerWireResponse::Response(ConsumerCallResponse {
                correlation: received,
                response,
            }) if exact_correlation(correlation, received).is_ok()
                && matches!(response.as_ref(), SessionConsumerResponse::WatchOpened)
        ) {
            return Err(StoreError::BackendUnavailable(
                "consumer watch unavailable".into(),
            ));
        }
        let (tx, rx) = mpsc::channel(CONSUMER_WATCH_CHANNEL_CAPACITY);
        let byte_budget = Arc::new(Semaphore::new(CONSUMER_WATCH_CHANNEL_MAX_BYTES));
        let tls_config = self.tls_config.clone();
        let reauthentication = self.reauthentication.clone();
        tokio::spawn(async move {
            let mut force_shutdown = persistent_runtime
                .as_ref()
                .map(|runtime| runtime.shutdown.clone());
            // The runtime owns the fixed watch permit. Keeping it in the
            // physical reader task releases capacity on peer close, rotation,
            // forced shutdown, or caller stream drop even if the caller never
            // polls its returned stream again.
            let _persistent_runtime = persistent_runtime;
            let mut reauthentication_changes = reauthentication.subscribe();
            let mut material_changes = Some(tls_config.subscribe_material_changes());
            let admitted_generation = connection.admitted_generation;
            let admitted_material_epoch = connection.admitted_material_epoch;
            loop {
                if !connection.current(&tls_config, &reauthentication) {
                    // Never wait behind already queued entries merely to
                    // report retirement. An unpolled receiver must not retain
                    // authenticated transport or fixed watch capacity.
                    let Ok(permit) = Arc::clone(&byte_budget).try_acquire_owned() else {
                        return;
                    };
                    let _ = tokio::select! {
                        _ = wait_for_optional_forced_shutdown(&mut force_shutdown) => return,
                        _ = tx.closed() => return,
                        result = tx.send(QueuedConsumerWatchItem {
                            item: Err(StoreError::BackendUnavailable(
                                "consumer watch authentication retired".into(),
                            )),
                            _byte_permit: permit,
                        })
                        => result,
                    };
                    return;
                }
                // A quiet, healthy watch is normal. Frame sizing still bounds
                // any received item, while reauthentication, material
                // rotation, lifecycle retirement, and stream drop can all
                // interrupt this otherwise unbounded wait.
                let response = {
                    let response_read = read_consumer_frame::<_, ConsumerWireResponse>(
                        &mut connection.reader,
                        MAX_NEGOTIATED_FRAME_SIZE,
                    );
                    tokio::pin!(response_read);
                    loop {
                        let response = tokio::select! {
                            biased;
                            _ = wait_for_optional_forced_shutdown(&mut force_shutdown) => return,
                            _ = tx.closed() => return,
                            response = &mut response_read => Some(response),
                            _ = tokio::time::sleep_until(connection.lifecycle.retire_at()) => {
                                let _ = connection
                                    .lifecycle
                                    .retirement(tokio::time::Instant::now());
                                return;
                            },
                            _ = reauthentication_changes.changed() => {
                                if !consumer_connection_current(
                                    &mut connection.lifecycle,
                                    &tls_config,
                                    &reauthentication,
                                    admitted_generation,
                                    admitted_material_epoch,
                                ) {
                                    return;
                                }
                                None
                            },
                            _ = wait_consumer_material_change(&mut material_changes) => {
                                if !consumer_connection_current(
                                    &mut connection.lifecycle,
                                    &tls_config,
                                    &reauthentication,
                                    admitted_generation,
                                    admitted_material_epoch,
                                ) {
                                    return;
                                }
                                None
                            },
                        };
                        if let Some(response) = response {
                            break response;
                        }
                    }
                };
                if !connection.current(&tls_config, &reauthentication) {
                    return;
                }
                let entry = match response {
                    Ok(ConsumerWireResponse::WatchEntry(ConsumerWatchEntry {
                        correlation: received,
                        entry,
                    })) if exact_correlation(correlation, received).is_ok() => {
                        (*entry).map_err(SessionConsumerStoreError::into_store_error)
                    }
                    Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
                        "consumer watch unavailable".into(),
                    )),
                };
                let (entry, byte_count) = match serde_json::to_vec(&entry) {
                    Ok(encoded) if encoded.len() <= CONSUMER_WATCH_CHANNEL_MAX_BYTES => {
                        let byte_count = u32::try_from(encoded.len().max(1));
                        match byte_count {
                            Ok(byte_count) => (entry, byte_count),
                            Err(_) => (
                                Err(StoreError::PayloadTooLarge {
                                    actual: encoded.len(),
                                    max: CONSUMER_WATCH_CHANNEL_MAX_BYTES,
                                }),
                                1,
                            ),
                        }
                    }
                    Ok(encoded) => (
                        Err(StoreError::PayloadTooLarge {
                            actual: encoded.len(),
                            max: CONSUMER_WATCH_CHANNEL_MAX_BYTES,
                        }),
                        1,
                    ),
                    Err(_) => (
                        Err(StoreError::BackendUnavailable(
                            "consumer watch unavailable".into(),
                        )),
                        1,
                    ),
                };
                let stop = entry.is_err();
                let acquire_permit = Arc::clone(&byte_budget).acquire_many_owned(byte_count);
                tokio::pin!(acquire_permit);
                let permit = loop {
                    let permit = tokio::select! {
                        biased;
                        _ = wait_for_optional_forced_shutdown(&mut force_shutdown) => return,
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
                            return;
                        },
                        _ = reauthentication_changes.changed() => {
                            if !consumer_connection_current(
                                &mut connection.lifecycle,
                                &tls_config,
                                &reauthentication,
                                admitted_generation,
                                admitted_material_epoch,
                            ) {
                                return;
                            }
                            None
                        },
                        _ = wait_consumer_material_change(&mut material_changes) => {
                            if !consumer_connection_current(
                                &mut connection.lifecycle,
                                &tls_config,
                                &reauthentication,
                                admitted_generation,
                                admitted_material_epoch,
                            ) {
                                return;
                                }
                                None
                            },
                    };
                    if let Some(permit) = permit {
                        break permit;
                    }
                };
                if !connection.current(&tls_config, &reauthentication) {
                    return;
                }
                let send = tx.send(QueuedConsumerWatchItem {
                    item: entry,
                    _byte_permit: permit,
                });
                tokio::pin!(send);
                let sent = loop {
                    let sent = tokio::select! {
                        biased;
                        _ = wait_for_optional_forced_shutdown(&mut force_shutdown) => return,
                        result = &mut send => Some(result),
                        _ = tokio::time::sleep_until(connection.lifecycle.retire_at()) => {
                            let _ = connection
                                .lifecycle
                                .retirement(tokio::time::Instant::now());
                            return;
                        },
                        _ = reauthentication_changes.changed() => {
                            if !consumer_connection_current(
                                &mut connection.lifecycle,
                                &tls_config,
                                &reauthentication,
                                admitted_generation,
                                admitted_material_epoch,
                            ) {
                                return;
                            }
                            None
                        },
                        _ = wait_consumer_material_change(&mut material_changes) => {
                            if !consumer_connection_current(
                                &mut connection.lifecycle,
                                &tls_config,
                                &reauthentication,
                                admitted_generation,
                                admitted_material_epoch,
                            ) {
                                return;
                                }
                                None
                            },
                    };
                    if let Some(sent) = sent {
                        break sent;
                    }
                };
                if sent.is_err() || stop || !connection.current(&tls_config, &reauthentication) {
                    return;
                }
            }
        });
        Ok(stream::unfold(rx, |mut receiver| async move {
            receiver.recv().await.map(|item| (item.item, receiver))
        })
        .boxed())
    }
}

impl StatelessSessionConsumer for StatelessSessionConsumerClient {}

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

#[derive(Clone, Copy, PartialEq, Eq)]
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

async fn wait_for_forced_shutdown(receiver: &mut watch::Receiver<PersistentShutdownPhase>) {
    loop {
        if *receiver.borrow_and_update() == PersistentShutdownPhase::Forced {
            return;
        }
        if receiver.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

async fn wait_for_optional_forced_shutdown(
    receiver: &mut Option<watch::Receiver<PersistentShutdownPhase>>,
) {
    match receiver {
        Some(receiver) => wait_for_forced_shutdown(receiver).await,
        None => std::future::pending::<()>().await,
    }
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

async fn wait_for_optional_deadline(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
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
    reconnect_sequence: AtomicU64,
    counters: PersistentConsumerCounters,
    active_calls: AtomicUsize,
    active_watches: AtomicUsize,
    drained_notify: Notify,
}

async fn reap_persistent_consumer_idle(
    pool: Weak<PersistentSessionConsumerPool>,
    changed: Arc<Notify>,
    mut shutdown: watch::Receiver<PersistentShutdownPhase>,
    mut reauthentication_changes: watch::Receiver<u64>,
    mut material_changes: Option<opc_tls::TlsMaterialStatusReceiver>,
) {
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
            _ = wait_consumer_material_change(&mut material_changes) => {}
            _ = &mut idle_changed => {}
            _ = wait_for_optional_deadline(next_deadline) => {}
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
        self.pool.counters.active.fetch_sub(1, Ordering::Relaxed);
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
        let active = self.active_calls.fetch_add(1, Ordering::Relaxed) + 1;
        let active_u64 = u64::try_from(active).unwrap_or(u64::MAX);
        counter_increment(&self.counters.active);
        counter_max(&self.counters.max_active, active_u64);
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

    fn record_error(&self, error: SessionConsumerClientError, may_have_sent: bool) {
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
        if may_have_sent {
            counter_increment(&self.counters.outcome_unknown);
        } else {
            counter_increment(&self.counters.not_transmitted);
        }
    }

    async fn admit_call(
        &self,
    ) -> Result<(OwnedSemaphorePermit, OwnedSemaphorePermit), SessionConsumerClientError> {
        if self.phase() != PersistentShutdownPhase::Running {
            return Err(SessionConsumerClientError::ShuttingDown);
        }
        let started = tokio::time::Instant::now();
        // This immediate total-admission acquisition structurally bounds
        // active plus queued caller futures. Tokio's lane semaphore supplies
        // the fair bounded wait only after admission succeeds.
        let pending = Arc::clone(&self.pending)
            .try_acquire_owned()
            .map_err(|_| SessionConsumerClientError::Overloaded)?;
        let lane = match Arc::clone(&self.lanes).try_acquire_owned() {
            Ok(lane) => lane,
            Err(_) => {
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
                let wait_deadline = started
                    .checked_add(self.config.pool_wait_timeout)
                    .ok_or(SessionConsumerClientError::Overloaded)?;
                let lane = tokio::select! {
                    biased;
                    _ = wait_for_shutdown(&mut shutdown) => {
                        Err(SessionConsumerClientError::ShuttingDown)
                    }
                    lane = tokio::time::timeout_at(
                        wait_deadline,
                        Arc::clone(&self.lanes).acquire_owned(),
                    ) => {
                        lane.ok().and_then(Result::ok)
                            .ok_or(SessionConsumerClientError::Overloaded)
                    }
                };
                drop(wait);
                let lane = lane?;
                // `timeout_at` polls the semaphore first. Do not admit a
                // permit that became ready only after the fixed wait cap.
                complete_before_deadline(
                    lane,
                    wait_deadline,
                    SessionConsumerClientError::Overloaded,
                )?
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

    fn return_idle(self: &Arc<Self>, mut connection: ConsumerConnection) {
        if self.phase() != PersistentShutdownPhase::Running {
            return;
        }
        if !connection.reusable()
            || !connection.current(&self.client.tls_config, &self.client.reauthentication)
        {
            counter_increment(&self.counters.reconnects);
            return;
        }
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.phase() != PersistentShutdownPhase::Running {
            return;
        }
        if !connection.reusable()
            || !connection.current(&self.client.tls_config, &self.client.reauthentication)
        {
            counter_increment(&self.counters.reconnects);
            return;
        }
        let inserted = if idle.len() < self.config.request_connections {
            idle.push_back(connection);
            true
        } else {
            false
        };
        drop(idle);
        if inserted {
            self.ensure_idle_reaper();
            self.idle_reaper.changed.notify_one();
        }
    }

    fn clear_idle(&self) {
        self.idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
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
        &self,
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
        counter_increment(&self.counters.setup_attempts);
        let result = self
            .client
            .connect(setup_deadline, true, Some(&self.counters))
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
            Ok(connection) => {
                counter_increment(&self.counters.setup_successes);
                Ok(connection)
            }
            Err(error) => {
                counter_increment(&self.counters.setup_failures);
                Err(error)
            }
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
                reconnect_sequence: AtomicU64::new(jitter_seed_high ^ jitter_seed_low),
                counters: PersistentConsumerCounters::default(),
                active_calls: AtomicUsize::new(0),
                active_watches: AtomicUsize::new(0),
                drained_notify: Notify::new(),
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
        let request_id = request.request_id();
        match self.execute_classified(request).await {
            Ok(response) => Ok(response),
            Err(SessionConsumerCallError::BeforeCallWrite(cause)) => {
                Err(PersistentSessionConsumerExecuteError::NotTransmitted { cause })
            }
            Err(SessionConsumerCallError::MayHaveSent(_)) => {
                Err(PersistentSessionConsumerExecuteError::OutcomeUnknown { request_id })
            }
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
        if request.scope() != self.pool.client.scope {
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Scope,
            ));
        }
        if matches!(request.operation(), SessionConsumerOperation::Watch { .. }) {
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Protocol,
            ));
        }
        if request.validate().is_err() {
            return Err(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Protocol,
            ));
        }
        let (_pending, _lane) = self.pool.admit_call().await.map_err(|error| {
            self.pool.record_error(error, false);
            SessionConsumerCallError::BeforeCallWrite(error)
        })?;
        let _activity = self.pool.register_call().map_err(|error| {
            self.pool.record_error(error, false);
            SessionConsumerCallError::BeforeCallWrite(error)
        })?;
        let result = self.execute_admitted(request).await;
        match result {
            Ok(response) => {
                counter_increment(&self.pool.counters.successes);
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
            SessionConsumerResponse::Rejected(SessionConsumerRejection::ScopeMismatch) => {
                Err(SessionConsumerClientError::Scope)
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
        op: CompareAndSet,
    ) -> Result<CompareAndSetResult, SessionConsumerMutationError> {
        mutation_response(
            request_id,
            self.execute_classified(&self.request(
                request_id,
                SessionConsumerOperation::CompareAndSet { op: Box::new(op) },
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
        lease: LeaseGuard,
    ) -> Result<(), SessionConsumerMutationError> {
        mutation_response(
            request_id,
            self.execute_classified(
                &self.request(request_id, SessionConsumerOperation::DeleteFenced { lease }),
            )
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
        lease: LeaseGuard,
        ttl: Duration,
    ) -> Result<(), SessionConsumerMutationError> {
        mutation_response(
            request_id,
            self.execute_classified(&self.request(
                request_id,
                SessionConsumerOperation::RefreshTtl { lease, ttl },
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
        ops: Vec<SessionOp>,
    ) -> Result<Vec<SessionOpResult>, SessionConsumerMutationError> {
        mutation_response(
            request_id,
            self.execute_classified(
                &self.request(request_id, SessionConsumerOperation::Batch { ops }),
            )
            .await,
            |response| match response {
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
        key: opc_session_store::SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, SessionConsumerLeaseMutationError> {
        lease_response(
            request_id,
            self.execute_classified(&self.request(
                request_id,
                SessionConsumerOperation::AcquireLease { key, owner, ttl },
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
        lease: LeaseGuard,
        ttl: Duration,
    ) -> Result<LeaseGuard, SessionConsumerLeaseMutationError> {
        lease_response(
            request_id,
            self.execute_classified(&self.request(
                request_id,
                SessionConsumerOperation::RenewLease { lease, ttl },
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
        lease: LeaseGuard,
    ) -> Result<(), SessionConsumerLeaseMutationError> {
        lease_response(
            request_id,
            self.execute_classified(
                &self.request(request_id, SessionConsumerOperation::ReleaseLease { lease }),
            )
            .await,
            |response| match response {
                SessionConsumerResponse::ReleaseLease(value) => Some(value),
                _ => None,
            },
        )
    }

    /// Open a watch using slots isolated from normal request lanes.
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
        counter_increment(&self.pool.counters.setup_attempts);
        let runtime = PersistentWatchRuntime {
            _lease: lease,
            shutdown: shutdown.clone(),
        };
        let upstream = tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => {
                self.pool.record_error(SessionConsumerClientError::ShuttingDown, false);
                counter_increment(&self.pool.counters.setup_failures);
                return Err(SessionConsumerClientError::ShuttingDown);
            }
            upstream = watch_client.watch_with_counters(
                start_sequence,
                Some(&self.pool.counters),
                Some(runtime),
            ) => upstream,
        }
        .map_err(|_| {
            counter_increment(&self.pool.counters.setup_failures);
            self.pool
                .record_error(SessionConsumerClientError::Unavailable, false);
            SessionConsumerClientError::Unavailable
        })?;
        counter_increment(&self.pool.counters.setup_successes);
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
    ) -> Result<SessionConsumerResponse, SessionConsumerCallError> {
        let started = tokio::time::Instant::now();
        let deadline = started
            .checked_add(self.pool.client.operation_timeout)
            .ok_or(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Deadline,
            ))?;
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
                    _ = wait_for_forced_shutdown(&mut shutdown) => {
                        Err(SessionConsumerClientError::ShuttingDown)
                    }
                    result = self.pool.connect(pre_request_deadline) => result,
                },
            };
            let mut connection = match connection {
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
                            _ = wait_for_forced_shutdown(&mut shutdown) => {
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
            ensure_pre_request_budget_remaining(pre_request_deadline, pre_request_budget_active)
                .map_err(SessionConsumerCallError::BeforeCallWrite)?;
            let result = self
                .pool
                .client
                .execute_on_connection(
                    &mut connection,
                    request,
                    pre_request_deadline,
                    pre_request_budget_active,
                    deadline,
                    Some(shutdown.clone()),
                )
                .await;
            match result {
                Ok(response) => {
                    self.pool.return_idle(connection);
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
                    counter_increment(&self.pool.counters.reconnects);
                    let delay = self.pool.reconnect_delay();
                    if !delay.is_zero() && tokio::time::Instant::now() < deadline {
                        tokio::select! {
                            biased;
                            _ = wait_for_forced_shutdown(&mut shutdown) => {
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
        let (initial_calls, initial_watches, published_phase) = {
            let mut activity = self
                .pool
                .activity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if activity.phase == PersistentShutdownPhase::Running {
                activity.phase = PersistentShutdownPhase::Draining;
                self.pool
                    .shutdown_phase
                    .store(PersistentShutdownPhase::Draining as u8, Ordering::Release);
            }
            (activity.calls, activity.watches, activity.phase)
        };
        self.pool.shutdown_tx.send_replace(published_phase);
        self.pool.pending.close();
        self.pool.lanes.close();
        self.pool.watches.close();
        self.pool.prewarm.close();
        self.pool.clear_idle();
        self.pool.idle_reaper.stop();
        let deadline = tokio::time::Instant::now() + self.pool.config.shutdown_drain;
        loop {
            let notified = self.pool.drained_notify.notified();
            let drained = {
                let activity = self
                    .pool
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
        let (forced_calls, forced_watches) = {
            let mut activity = self
                .pool
                .activity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            activity.phase = PersistentShutdownPhase::Forced;
            self.pool
                .shutdown_phase
                .store(PersistentShutdownPhase::Forced as u8, Ordering::Release);
            (activity.calls, activity.watches)
        };
        self.pool
            .shutdown_tx
            .send_replace(PersistentShutdownPhase::Forced);
        // This independently retires stateless watch reader tasks after the
        // grace period even if the returned stream is held without polling.
        let _ = self.pool.client.request_reauthentication();
        PersistentSessionConsumerShutdownReport {
            drained_calls: u64::try_from(initial_calls.saturating_sub(forced_calls))
                .unwrap_or(u64::MAX),
            forced_calls: u64::try_from(forced_calls).unwrap_or(u64::MAX),
            drained_watches: u64::try_from(initial_watches.saturating_sub(forced_watches))
                .unwrap_or(u64::MAX),
            forced_watches: u64::try_from(forced_watches).unwrap_or(u64::MAX),
        }
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
        Ok(SessionConsumerResponse::Rejected(SessionConsumerRejection::ScopeMismatch))
        | Ok(SessionConsumerResponse::Rejected(SessionConsumerRejection::Unauthorized)) => Err(
            SessionConsumerLeaseMutationError::Lease(LeaseError::StaleFence),
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
        }
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

    /// Set the bootstrap and active-frame idle deadline, capped at five
    /// seconds by listener validation.
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
                let service = Arc::clone(&service);
                let tls_config = tls_config.clone();
                let authorizer = authorizer.clone();
                let cancellation = Arc::clone(&accept_cancellation);
                let reauthentication = reauthentication.clone();
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
                        lifecycle_policy,
                        reauthentication,
                        cancellation,
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
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
    cancellation: Arc<AtomicBool>,
) -> Result<(), ProtocolError> {
    // Revision 2 reuses a socket for small request/response frames. Disable
    // Nagle on both peers so a warm exchange cannot inherit the platform's
    // delayed-ACK cadence and consume the bounded fair-pool wait budget.
    stream.set_nodelay(true).map_err(ProtocolError::Io)?;
    let generation = reauthentication.generation();
    let handshake = tls_config
        .begin_handshake()
        .map_err(|_| ProtocolError::Authentication)?;
    let acceptor =
        tokio_rustls::TlsAcceptor::from(consumer_server_tls_config(handshake.rustls_config()));
    let tls = tokio::time::timeout(idle_timeout, acceptor.accept(stream))
        .await
        .map_err(|_| {
            ProtocolError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "consumer TLS handshake timed out",
            ))
        })?
        .map_err(classify_tls_io_error)?;
    let established_at = tokio::time::Instant::now();
    if tls.get_ref().1.alpn_protocol() != Some(SESSION_QUORUM_CONSUMER_ALPN) {
        return Err(ProtocolError::UnexpectedResponse);
    }
    let peer = opc_tls::peer_tls_identity_from_server_connection(tls.get_ref().1)
        .map_err(|_| ProtocolError::Authentication)?;
    let identity = authorizer
        .authorize(peer.spiffe_id())
        .map_err(|_| ProtocolError::Authentication)?;
    let (mut reader, mut writer) = tokio::io::split(tls);
    let hello = read_consumer_frame_within::<_, ConsumerWireRequest>(
        &mut reader,
        max_frame_size,
        idle_timeout,
    )
    .await?;
    let ConsumerWireRequest::Hello(hello) = hello else {
        return Err(ProtocolError::UnexpectedResponse);
    };
    if hello.transport_revision != SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION {
        return Err(ProtocolError::UnexpectedResponse);
    }
    if hello.scope != authorizer.scope() {
        let _ = write_consumer_response(
            &mut writer,
            ConsumerWireResponse::HelloRejected(SessionConsumerRejection::ScopeMismatch),
            max_frame_size,
            idle_timeout,
        )
        .await;
        return Err(ProtocolError::UnexpectedResponse);
    }
    let admission = handshake
        .admit()
        .map_err(|_| ProtocolError::Authentication)?;
    if generation != reauthentication.generation()
        || admission.epoch() != tls_config.material_status().epoch()
    {
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
    lifecycle.observe_rotation(
        tokio::time::Instant::now(),
        reauthentication.generation(),
        Some(tls_config.material_status().epoch()),
        b"session-quorum-consumer",
    );
    if lifecycle.retirement(tokio::time::Instant::now()).is_some() {
        return Err(ProtocolError::Authentication);
    }
    let admitted_generation = generation;
    let admitted_material_epoch = admission.epoch();
    let mut reauthentication_changes = reauthentication.subscribe();
    let mut material_changes = Some(tls_config.subscribe_material_changes());
    if !server_connection_current(
        &mut lifecycle,
        &tls_config,
        &reauthentication,
        admitted_generation,
        admitted_material_epoch,
    ) {
        return Err(ProtocolError::Authentication);
    }
    write_consumer_response(
        &mut writer,
        ConsumerWireResponse::HelloAck(ConsumerHelloAck {
            transport_revision: SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
            scope: authorizer.scope(),
        }),
        max_frame_size,
        idle_timeout,
    )
    .await?;
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
                            admitted_generation,
                            admitted_material_epoch,
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
                            admitted_generation,
                            admitted_material_epoch,
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
            admitted_generation,
            admitted_material_epoch,
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
                max_frame_size,
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
                max_frame_size,
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
                    );
                    None
                }
                _ = wait_consumer_material_change(&mut material_changes) => {
                    observe_consumer_rotation(
                        &mut lifecycle,
                        tokio::time::Instant::now(),
                        reauthentication.generation(),
                        tls_config.material_status().epoch(),
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
                || !consumer_response_fits_for_correlation(correlation, &response, max_frame_size)
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
                            );
                            None
                        }
                        _ = wait_consumer_material_change(&mut material_changes) => {
                            observe_consumer_rotation(
                                &mut lifecycle,
                                tokio::time::Instant::now(),
                                reauthentication.generation(),
                                tls_config.material_status().epoch(),
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
        {
            let initial_hard_deadline = lifecycle
                .hard_deadline()
                .map_err(|_| ProtocolError::InvalidWireValue)?;
            let response_write_deadline = request_deadline.min(initial_hard_deadline);
            let response_write = write_consumer_response_until(
                &mut writer,
                ConsumerWireResponse::Response(ConsumerCallResponse {
                    correlation,
                    response: Box::new(response),
                }),
                max_frame_size,
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
                        );
                        None
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        observe_consumer_rotation(
                            &mut lifecycle,
                            tokio::time::Instant::now(),
                            reauthentication.generation(),
                            tls_config.material_status().epoch(),
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
                    admitted_generation,
                    admitted_material_epoch,
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
                        admitted_generation,
                        admitted_material_epoch,
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
                        admitted_generation,
                        admitted_material_epoch,
                    ) {
                        return Ok(());
                    }
                    continue;
                },
            };
            let Some(entry) = entry else {
                return Ok(());
            };
            if cancellation.load(Ordering::Acquire)
                || !server_connection_current(
                    &mut lifecycle,
                    &tls_config,
                    &reauthentication,
                    admitted_generation,
                    admitted_material_epoch,
                )
            {
                return Ok(());
            }
            let watch_write_deadline = tokio::time::Instant::now()
                .checked_add(operation_timeout)
                .ok_or(ProtocolError::InvalidWireValue)?
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
                max_frame_size,
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
                        admitted_generation,
                        admitted_material_epoch,
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
                        );
                        None
                    }
                    _ = wait_consumer_material_change(&mut material_changes) => {
                        observe_consumer_rotation(
                            &mut lifecycle,
                            tokio::time::Instant::now(),
                            reauthentication.generation(),
                            tls_config.material_status().epoch(),
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
                        admitted_generation,
                        admitted_material_epoch,
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
        | ConsumerOperationKind::RefreshTtl => Some(SessionConsumerOutcomeUnknown::Mutation),
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
            response,
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use super::{
        classify_call_write_error, complete_before_deadline, consumer_response_fits,
        decode_consumer_frame_payload, ensure_pre_request_budget_remaining, exact_correlation,
        lease_response, mutation_response, read_authenticated_consumer_frame_within,
        response_matches_operation, BorrowedConsumerCall, BorrowedConsumerCallResponse,
        BorrowedConsumerWireRequest, BorrowedConsumerWireResponse, ConsumerCall,
        ConsumerCallResponse, ConsumerConnection, ConsumerOperationKind, ConsumerWireRequest,
        ConsumerWireResponse, PersistentSessionConsumerClient, PersistentSessionConsumerConfig,
        PersistentSessionConsumerConfigError, SessionConsumerAuthorizationError,
        SessionConsumerAuthorizer, SessionConsumerCallError, SessionConsumerClientError,
        SessionConsumerLeaseMutationError, SessionConsumerMutationError,
        StatelessSessionConsumerClient, DEFAULT_PERSISTENT_SESSION_CONSUMER_CONNECT_ATTEMPTS,
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
    use opc_session_store::{
        BackendCapabilities, EncryptedSessionPayload, FenceToken, Generation, OwnerId,
        RestoreScanPage, SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId, SessionConsensusIdentity, SessionConsumerLeaseError,
        SessionConsumerOperation, SessionConsumerRequest, SessionConsumerRequestId,
        SessionConsumerResponse, SessionConsumerScope, SessionConsumerStoreError, SessionKey,
        SessionKeyType, StateClass, StateType, StoredSessionRecord,
    };
    use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
    use tokio::io::{AsyncWrite, AsyncWriteExt};

    use crate::lifecycle::{
        ConnectionLifecycle, ConnectionLifecyclePolicy, RetirementReason,
        SessionReauthenticationControl,
    };
    use crate::protocol::MAX_NEGOTIATED_FRAME_SIZE;
    use crate::test_support::RotatableClientMaterial;

    fn scope() -> SessionConsumerScope {
        SessionConsumerScope::new(SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([1; 32]),
            SessionConsensusConfigurationId::from_bytes([2; 32]),
            SessionConsensusConfigurationEpoch::new(1).expect("non-zero configuration epoch"),
        ))
    }

    fn spiffe(suffix: &str) -> SpiffeId {
        SpiffeId::new(format!(
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/{suffix}"
        ))
        .expect("test SPIFFE ID")
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
                admitted_generation: generation,
                admitted_material_epoch: material_epoch,
                next_correlation: NonZeroU32::MIN,
                calls: 0,
                idle_deadline,
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
                response: &response,
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
        let control = SessionReauthenticationControl::new();
        let (stateless, material) = stateless_test_client(control.clone());
        let persistent = PersistentSessionConsumerClient::from_stateless(stateless);

        let (connection, idle_lifecycle) = synthetic_consumer_connection(
            &persistent.pool.client,
            tokio::time::Instant::now() + Duration::from_millis(100),
            Box::new(tokio::io::sink()),
        );
        persistent.pool.return_idle(connection);
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

        let (connection, material_lifecycle) = synthetic_consumer_connection(
            &persistent.pool.client,
            tokio::time::Instant::now() + Duration::from_secs(60),
            Box::new(tokio::io::sink()),
        );
        persistent.pool.return_idle(connection);
        wait_for_raw_idle_count(&persistent, 1).await;
        material.publish_rejected_update();
        tokio::task::yield_now().await;
        wait_for_raw_idle_count(&persistent, 1).await;
        assert_eq!(
            material_lifecycle.recorded_retirement_count(),
            0,
            "a same-epoch rejected publication retains authenticated capacity"
        );
        material.rotate();
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
    async fn watch_call_rechecks_missed_rotation_before_any_write() {
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
                &mut reauthentication_changes,
                &mut material_changes,
            )
            .await;
        assert_eq!(result, Err(SessionConsumerClientError::Unavailable));
        assert_eq!(material_bytes.load(Ordering::SeqCst), 0);
        assert_eq!(material_connection.calls, 0);
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
