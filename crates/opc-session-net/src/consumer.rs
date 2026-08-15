//! Authenticated stateless application access to a fixed session quorum.
//!
//! The transport in this module is intentionally separate from both the
//! consensus-member ALPN and the quarantined compatibility ALPN. It exposes
//! only [`opc_session_store::SessionConsumerOperation`] and uses a fresh,
//! bounded mutual-TLS connection for each normal operation. A consumer never
//! receives a local member ID, Openraft peer, SQLite backend, snapshot path,
//! or raw replication append/rebuild operation.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use crate::consensus::RemoteAddrResolver;
use crate::error::{classify_tls_io_error, ProtocolError};
use crate::lifecycle::{
    CertificateExpiryEvidence, ConnectionLifecycle, ConnectionLifecyclePolicy,
    SessionReauthenticationControl,
};
use crate::protocol::{
    read_frame_payload, write_frame_bounded_until, write_frame_bounded_until_classified,
    FrameWriteError, MAX_NEGOTIATED_FRAME_SIZE,
};

/// Dedicated ALPN for authenticated stateless session-quorum consumers.
pub const SESSION_QUORUM_CONSUMER_ALPN: &[u8] = b"opc-session-consumer/1";

/// Fixed wire revision for [`SESSION_QUORUM_CONSUMER_ALPN`].
pub const SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION: u16 = 1;

/// Maximum application requests processed on one consumer connection.
///
/// Keeping this at one makes cancellation and ambiguous mutation handling
/// structural: a failed connection never causes this SDK to submit a second
/// application request automatically.
pub const MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION: usize = 1;

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

/// Redaction-safe construction or transport failure for a stateless consumer.
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

fn classify_call_write_error(error: FrameWriteError) -> SessionConsumerCallError {
    match error {
        FrameWriteError::BeforeWrite(error) => {
            SessionConsumerCallError::BeforeCallWrite(error.into())
        }
        FrameWriteError::MayHaveWritten(error) => {
            SessionConsumerCallError::MayHaveSent(error.into())
        }
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

/// Exact mTLS authorization policy for stateless application consumers.
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
            .field("scope", &self.scope)
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

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ConsumerWireRequest {
    Hello(ConsumerHello),
    Call(Box<SessionConsumerRequest>),
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
    Response(Box<SessionConsumerResponse>),
    WatchEntry(Box<Result<SessionConsumerChange, SessionConsumerStoreError>>),
}

/// Decode the fixed consumer revision without accepting a shared DTO's
/// forward-compatible unknown fields. The consumer transport owns an exact
/// wire contract, while its application DTOs are intentionally shared with
/// internal/legacy code and cannot globally enable `deny_unknown_fields`.
/// `serde_ignored` reports fields that shared DTO deserializers would ignore,
/// so this boundary rejects them without materializing, cloning, and
/// re-encoding a generic JSON tree.
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
    if ignored {
        return Err(ProtocolError::InvalidWireValue);
    }
    Ok(decoded)
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
}

impl ConsumerConnection {
    fn current(
        &mut self,
        config: &opc_tls::AuthenticatedClientConfig,
        reauthentication: &SessionReauthenticationControl,
    ) -> bool {
        let now = tokio::time::Instant::now();
        self.lifecycle.observe_rotation(
            now,
            reauthentication.generation(),
            Some(config.material_status().epoch()),
            b"session-quorum-consumer",
        );
        self.lifecycle.retirement(now).is_none()
            && self.admitted_generation == reauthentication.generation()
            && self.admitted_material_epoch == config.material_status().epoch()
    }
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
    lifecycle.observe_rotation(
        now,
        current_generation,
        Some(current_material_epoch),
        b"session-quorum-consumer",
    );
    lifecycle.retirement(now).is_none()
        && admitted_generation == current_generation
        && admitted_material_epoch == current_material_epoch
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

    async fn connect(
        &self,
        deadline: tokio::time::Instant,
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
        let address = tokio::time::timeout_at(deadline, (self.resolve)())
            .await
            .map_err(|_| SessionConsumerClientError::Unavailable)?
            .map_err(|_| SessionConsumerClientError::Unavailable)?;
        let generation = self.reauthentication.generation();
        let handshake = self
            .tls_config
            .begin_handshake()
            .map_err(|_| SessionConsumerClientError::Authentication)?;
        let tcp = tokio::time::timeout_at(deadline, TcpStream::connect(address))
            .await
            .map_err(|_| SessionConsumerClientError::Deadline)?
            .map_err(|_| SessionConsumerClientError::Unavailable)?;
        let connector =
            tokio_rustls::TlsConnector::from(consumer_client_tls_config(handshake.rustls_config()));
        let tls =
            tokio::time::timeout_at(deadline, connector.connect(self.server_name.clone(), tcp))
                .await
                .map_err(|_| SessionConsumerClientError::Deadline)?
                .map_err(|error| SessionConsumerClientError::from(classify_tls_io_error(error)))?;
        let established_at = tokio::time::Instant::now();
        if tls.get_ref().1.alpn_protocol() != Some(SESSION_QUORUM_CONSUMER_ALPN) {
            return Err(SessionConsumerClientError::Protocol);
        }
        let peer = opc_tls::peer_tls_identity_from_client_connection(tls.get_ref().1)
            .map_err(|_| SessionConsumerClientError::Authentication)?;
        if peer.spiffe_id() != &self.expected_server_identity {
            return Err(SessionConsumerClientError::Authentication);
        }
        let (mut reader, mut writer) = tokio::io::split(tls);
        let hello = ConsumerWireRequest::Hello(ConsumerHello {
            transport_revision: SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
            scope: self.scope,
        });
        write_frame_bounded_until(&mut writer, &hello, MAX_NEGOTIATED_FRAME_SIZE, deadline)
            .await
            .map_err(SessionConsumerClientError::from)?;
        let ack = tokio::time::timeout_at(
            deadline,
            read_consumer_frame::<_, ConsumerWireResponse>(&mut reader, MAX_NEGOTIATED_FRAME_SIZE),
        )
        .await
        .map_err(|_| SessionConsumerClientError::Deadline)?
        .map_err(SessionConsumerClientError::from)?;
        match ack {
            ConsumerWireResponse::HelloAck(ack)
                if ack.transport_revision == SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION
                    && ack.scope == self.scope => {}
            ConsumerWireResponse::Response(response)
                if matches!(
                    response.as_ref(),
                    SessionConsumerResponse::Rejected(SessionConsumerRejection::ScopeMismatch,)
                ) =>
            {
                return Err(SessionConsumerClientError::Scope)
            }
            ConsumerWireResponse::Response(response)
                if matches!(
                    response.as_ref(),
                    SessionConsumerResponse::Rejected(SessionConsumerRejection::Unauthorized,)
                ) =>
            {
                return Err(SessionConsumerClientError::Authentication)
            }
            _ => return Err(SessionConsumerClientError::Protocol),
        }
        let admission = handshake
            .admit()
            .map_err(|_| SessionConsumerClientError::Authentication)?;
        if generation != self.reauthentication.generation()
            || admission.epoch() != self.tls_config.material_status().epoch()
        {
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
        let mut connection = ConsumerConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            lifecycle,
            admitted_generation: generation,
            admitted_material_epoch: admission.epoch(),
        };
        if !connection.current(&self.tls_config, &self.reauthentication) {
            return Err(SessionConsumerClientError::Deadline);
        }
        Ok(connection)
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
        let deadline = tokio::time::Instant::now()
            .checked_add(self.operation_timeout)
            .ok_or(SessionConsumerCallError::BeforeCallWrite(
                SessionConsumerClientError::Deadline,
            ))?;
        let mut connection = self
            .connect(deadline)
            .await
            .map_err(SessionConsumerCallError::BeforeCallWrite)?;
        let outbound = ConsumerWireRequest::Call(Box::new(request));
        write_frame_bounded_until_classified(
            &mut connection.writer,
            &outbound,
            MAX_NEGOTIATED_FRAME_SIZE,
            deadline,
        )
        .await
        .map_err(classify_call_write_error)?;
        if !connection.current(&self.tls_config, &self.reauthentication) {
            return Err(SessionConsumerCallError::MayHaveSent(
                SessionConsumerClientError::Deadline,
            ));
        }
        let response = tokio::time::timeout_at(
            deadline,
            read_consumer_frame::<_, ConsumerWireResponse>(
                &mut connection.reader,
                MAX_NEGOTIATED_FRAME_SIZE,
            ),
        )
        .await
        .map_err(|_| SessionConsumerCallError::MayHaveSent(SessionConsumerClientError::Deadline))?
        .map_err(SessionConsumerClientError::from)
        .map_err(SessionConsumerCallError::MayHaveSent)?;
        if !connection.current(&self.tls_config, &self.reauthentication) {
            return Err(SessionConsumerCallError::MayHaveSent(
                SessionConsumerClientError::Deadline,
            ));
        }
        match response {
            ConsumerWireResponse::Response(response) => Ok(*response),
            _ => Err(SessionConsumerCallError::MayHaveSent(
                SessionConsumerClientError::Protocol,
            )),
        }
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
        let deadline = tokio::time::Instant::now()
            .checked_add(self.operation_timeout)
            .ok_or_else(|| StoreError::BackendUnavailable("consumer watch unavailable".into()))?;
        let mut connection = self
            .connect(deadline)
            .await
            .map_err(|_| StoreError::BackendUnavailable("consumer watch unavailable".into()))?;
        let request = self.request(
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::Watch { start_sequence },
        );
        write_frame_bounded_until(
            &mut connection.writer,
            &ConsumerWireRequest::Call(Box::new(request)),
            MAX_NEGOTIATED_FRAME_SIZE,
            deadline,
        )
        .await
        .map_err(|_| StoreError::BackendUnavailable("consumer watch unavailable".into()))?;
        let response = tokio::time::timeout_at(
            deadline,
            read_consumer_frame::<_, ConsumerWireResponse>(
                &mut connection.reader,
                MAX_NEGOTIATED_FRAME_SIZE,
            ),
        )
        .await
        .map_err(|_| StoreError::BackendUnavailable("consumer watch unavailable".into()))?
        .map_err(|_| StoreError::BackendUnavailable("consumer watch unavailable".into()))?;
        if !matches!(
            response,
            ConsumerWireResponse::Response(response)
                if matches!(response.as_ref(), SessionConsumerResponse::WatchOpened)
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
            let mut reauthentication_changes = reauthentication.subscribe();
            let mut material_changes = Some(tls_config.subscribe_material_changes());
            loop {
                if !connection.current(&tls_config, &reauthentication) {
                    let permit = tokio::select! {
                        _ = tx.closed() => return,
                        permit = Arc::clone(&byte_budget).acquire_owned() => {
                            match permit {
                                Ok(permit) => permit,
                                Err(_) => return,
                            }
                        }
                    };
                    let _ = tx
                        .send(QueuedConsumerWatchItem {
                            item: Err(StoreError::BackendUnavailable(
                                "consumer watch authentication retired".into(),
                            )),
                            _byte_permit: permit,
                        })
                        .await;
                    return;
                }
                // A quiet, healthy watch is normal. Frame sizing still bounds
                // any received item, while reauthentication, material
                // rotation, lifecycle retirement, and stream drop can all
                // interrupt this otherwise unbounded wait.
                let response = tokio::select! {
                    biased;
                    _ = tx.closed() => return,
                    _ = reauthentication_changes.changed() => return,
                    _ = wait_consumer_material_change(&mut material_changes) => return,
                    _ = tokio::time::sleep_until(connection.lifecycle.retire_at()) => return,
                    response = read_consumer_frame::<_, ConsumerWireResponse>(
                        &mut connection.reader,
                        MAX_NEGOTIATED_FRAME_SIZE,
                    ) => response,
                };
                if !connection.current(&tls_config, &reauthentication) {
                    return;
                }
                let entry = match response {
                    Ok(ConsumerWireResponse::WatchEntry(entry)) => {
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
                let permit = tokio::select! {
                    _ = tx.closed() => return,
                    permit = Arc::clone(&byte_budget).acquire_many_owned(byte_count) => {
                        match permit {
                            Ok(permit) => permit,
                            Err(_) => return,
                        }
                    }
                };
                if tx
                    .send(QueuedConsumerWatchItem {
                        item: entry,
                        _byte_permit: permit,
                    })
                    .await
                    .is_err()
                    || stop
                {
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

/// Dedicated server for stateless session-quorum consumers.
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

    /// Set the maximum simultaneous authenticated consumer connections.
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

    /// Set the bootstrap and active-frame idle deadline.
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
                "invalid stateless consumer listener configuration",
            ));
        }
        Ok(())
    }
}

/// Handle for a running stateless consumer listener.
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
    if hello.transport_revision != SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION
        || hello.scope != authorizer.scope()
    {
        let _ = write_consumer_response(
            &mut writer,
            ConsumerWireResponse::Response(Box::new(SessionConsumerResponse::Rejected(
                SessionConsumerRejection::ScopeMismatch,
            ))),
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
    if cancellation.load(Ordering::Acquire) {
        return Ok(());
    }
    let request = tokio::select! {
        biased;
        _ = reauthentication_changes.changed() => return Ok(()),
        _ = wait_consumer_material_change(&mut material_changes) => return Ok(()),
        request = read_consumer_frame_within::<_, ConsumerWireRequest>(&mut reader, max_frame_size, idle_timeout) => request?,
    };
    let ConsumerWireRequest::Call(request) = request else {
        return Err(ProtocolError::UnexpectedResponse);
    };
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
        return write_consumer_response(
            &mut writer,
            ConsumerWireResponse::Response(Box::new(SessionConsumerResponse::Rejected(
                SessionConsumerRejection::ScopeMismatch,
            ))),
            max_frame_size,
            idle_timeout,
        )
        .await;
    }
    if let Err(rejection) = request.validate() {
        return write_consumer_response(
            &mut writer,
            ConsumerWireResponse::Response(Box::new(SessionConsumerResponse::Rejected(rejection))),
            max_frame_size,
            idle_timeout,
        )
        .await;
    }
    let watch_start = match request.operation() {
        SessionConsumerOperation::Watch { start_sequence } => Some(*start_sequence),
        _ => None,
    };
    let restore_request = match request.operation() {
        SessionConsumerOperation::ScanRestoreRecords { request } => Some(request.clone()),
        _ => None,
    };
    let timeout_response = consumer_timeout_response(request.operation());
    let scope = request.scope();
    let request_deadline = tokio::time::Instant::now()
        .checked_add(operation_timeout)
        .ok_or(ProtocolError::InvalidWireValue)?;
    let mut response = tokio::select! {
        biased;
        _ = reauthentication_changes.changed() => return Ok(()),
        _ = wait_consumer_material_change(&mut material_changes) => return Ok(()),
        response = tokio::time::timeout_at(request_deadline, service.execute(&identity, *request)) => {
            response.unwrap_or(timeout_response)
        }
    };
    if !server_connection_current(
        &mut lifecycle,
        &tls_config,
        &reauthentication,
        admitted_generation,
        admitted_material_epoch,
    ) {
        return Ok(());
    }
    if let (Some(request), SessionConsumerResponse::ScanRestoreRecords(Ok(page))) =
        (&restore_request, &response)
    {
        // A restore page carries record byte arrays and can be valid for the
        // store while exceeding the consumer frame after JSON expansion.
        // Replace it before the response write with a small typed error; do
        // not let a cursor become permanently unframeable after dispatch.
        if page.validate_for_request(request).is_err()
            || !consumer_response_fits(&response, max_frame_size)
        {
            response = SessionConsumerResponse::ScanRestoreRecords(Err(
                SessionConsumerStoreError::RestoreBudgetExceeded,
            ));
        }
    }
    write_consumer_response_until(
        &mut writer,
        ConsumerWireResponse::Response(Box::new(response.clone())),
        max_frame_size,
        request_deadline,
    )
    .await?;
    let Some(start_sequence) = watch_start else {
        return Ok(());
    };
    if !matches!(response, SessionConsumerResponse::WatchOpened) {
        return Ok(());
    }
    let mut watch = match tokio::time::timeout_at(
        request_deadline,
        service.watch(&identity, scope, start_sequence),
    )
    .await
    {
        Ok(Ok(watch)) => watch,
        Ok(Err(rejection)) => {
            return write_consumer_response(
                &mut writer,
                ConsumerWireResponse::Response(Box::new(SessionConsumerResponse::Rejected(
                    rejection,
                ))),
                max_frame_size,
                operation_timeout,
            )
            .await;
        }
        Err(_) => return Ok(()),
    };
    let mut peer_probe = [0_u8; 1];
    loop {
        if !server_connection_current(
            &mut lifecycle,
            &tls_config,
            &reauthentication,
            admitted_generation,
            admitted_material_epoch,
        ) {
            return Ok(());
        }
        let entry = tokio::select! {
            biased;
            _ = reauthentication_changes.changed() => return Ok(()),
            _ = wait_consumer_material_change(&mut material_changes) => return Ok(()),
            _ = tokio::time::sleep_until(lifecycle.retire_at()) => return Ok(()),
            _ = tokio::time::sleep(CONSUMER_WATCH_CANCELLATION_RECHECK_INTERVAL) => {
                if cancellation.load(Ordering::Acquire) {
                    return Ok(());
                }
                continue;
            }
            // The client sends exactly one request per connection. Continue
            // polling its read half after watch admission so an otherwise idle
            // stream terminates when the peer goes away instead of retaining
            // its backend watch until a future change arrives.
            _ = reader.read(&mut peer_probe) => return Ok(()),
            entry = watch.next() => entry,
        };
        let Some(entry) = entry else {
            return Ok(());
        };
        if cancellation.load(Ordering::Acquire) {
            return Ok(());
        }
        write_consumer_response(
            &mut writer,
            ConsumerWireResponse::WatchEntry(Box::new(entry)),
            max_frame_size,
            operation_timeout,
        )
        .await?;
    }
}

fn consumer_timeout_response(operation: &SessionConsumerOperation) -> SessionConsumerResponse {
    let mutation_may_have_been_accepted = match operation {
        SessionConsumerOperation::CompareAndSet { .. }
        | SessionConsumerOperation::DeleteFenced { .. }
        | SessionConsumerOperation::RefreshTtl { .. } => {
            Some(SessionConsumerOutcomeUnknown::Mutation)
        }
        SessionConsumerOperation::AcquireLease { .. }
        | SessionConsumerOperation::RenewLease { .. }
        | SessionConsumerOperation::ReleaseLease { .. } => {
            Some(SessionConsumerOutcomeUnknown::Lease)
        }
        SessionConsumerOperation::Batch { ops }
            if ops.iter().any(|op| !matches!(op, SessionOp::Get { .. })) =>
        {
            Some(SessionConsumerOutcomeUnknown::Mutation)
        }
        SessionConsumerOperation::Capabilities
        | SessionConsumerOperation::Get { .. }
        | SessionConsumerOperation::PreflightRecordExpiry { .. }
        | SessionConsumerOperation::Batch { .. }
        | SessionConsumerOperation::ScanRestoreRecords { .. }
        | SessionConsumerOperation::Watch { .. } => None,
        // A newer operation may have an effect unknown to this transport
        // revision. Preserve mutation safety across that version skew.
        _ => Some(SessionConsumerOutcomeUnknown::Mutation),
    };
    mutation_may_have_been_accepted.map_or(
        SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable),
        SessionConsumerResponse::OutcomeUnknown,
    )
}

fn consumer_response_fits(response: &SessionConsumerResponse, max_frame_size: usize) -> bool {
    serde_json::to_vec(&ConsumerWireResponse::Response(Box::new(response.clone())))
        .is_ok_and(|encoded| encoded.len() <= max_frame_size)
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
    use super::{
        classify_call_write_error, consumer_response_fits, decode_consumer_frame_payload,
        lease_response, mutation_response, ConsumerWireResponse, SessionConsumerAuthorizationError,
        SessionConsumerAuthorizer, SessionConsumerCallError, SessionConsumerClientError,
        SessionConsumerLeaseMutationError, SessionConsumerMutationError,
    };
    use bytes::Bytes;
    use opc_session_store::{
        BackendCapabilities, EncryptedSessionPayload, FenceToken, Generation, OwnerId,
        RestoreScanPage, SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId, SessionConsensusIdentity, SessionConsumerLeaseError,
        SessionConsumerRequestId, SessionConsumerResponse, SessionConsumerScope,
        SessionConsumerStoreError, SessionKey, SessionKeyType, StateClass, StateType,
        StoredSessionRecord,
    };
    use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};

    use crate::protocol::MAX_NEGOTIATED_FRAME_SIZE;

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
        let response = ConsumerWireResponse::Response(Box::new(
            SessionConsumerResponse::Capabilities(BackendCapabilities::all_enabled()),
        ));
        let mut encoded = serde_json::to_value(response).expect("consumer response encodes");
        encoded["body"]["Capabilities"]["unexpected"] = serde_json::Value::Bool(true);
        let payload = serde_json::to_vec(&encoded).expect("JSON payload");
        assert!(decode_consumer_frame_payload::<ConsumerWireResponse>(&payload).is_err());
    }

    #[test]
    fn consumer_decoder_rejects_trailing_json_values() {
        let response = ConsumerWireResponse::Response(Box::new(
            SessionConsumerResponse::Capabilities(BackendCapabilities::all_enabled()),
        ));
        let mut payload = serde_json::to_vec(&response).expect("consumer response encodes");
        payload.extend_from_slice(br#"{}"#);
        assert!(decode_consumer_frame_payload::<ConsumerWireResponse>(&payload).is_err());
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
            classify_call_write_error(crate::protocol::FrameWriteError::BeforeWrite(
                crate::ProtocolError::FrameTooLarge(1),
            )),
            SessionConsumerCallError::BeforeCallWrite(SessionConsumerClientError::Protocol)
        ));
        assert!(matches!(
            classify_call_write_error(crate::protocol::FrameWriteError::MayHaveWritten(
                crate::ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "redacted test failure",
                )),
            )),
            SessionConsumerCallError::MayHaveSent(SessionConsumerClientError::Deadline)
        ));
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
