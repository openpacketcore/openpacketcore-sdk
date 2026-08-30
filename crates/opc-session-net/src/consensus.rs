//! Authenticated, least-authority transport for session consensus RPCs.
//!
//! This module deliberately does not expose [`opc_session_store::SessionBackend`]
//! or any raw replication-log/rebuild operation. A listener constructed here
//! owns only a [`SessionConsensusRpcHandler`], and its dedicated ALPN decodes
//! only the bounded consensus DTOs.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::future::BoxFuture;
use opc_consensus::{
    ConsensusIdentity, ConsensusRpcFamily, DURABLE_CONSENSUS_REMOTE_RETIREMENT_PROBE_INTERVAL,
    DURABLE_CONSENSUS_TIMING_PROFILE,
};
use opc_redaction::metrics::METRICS;
use opc_session_store::{
    ReplicaId, SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
};
use opc_types::SpiffeId;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, MutexGuard, Notify, Semaphore, SemaphorePermit};

use crate::error::{classify_tls_io_error, ProtocolError};
use crate::identity::{LocalReplicaBinding, RemoteReplicaBinding};
use crate::lifecycle::{
    directed_connection_key, material_status_matches_admission, CertificateExpiryEvidence,
    ConnectionAttemptMetricGuard, ConnectionLifecycle, ConnectionLifecyclePolicy,
    ReconnectAdmission, ReconnectGate, RetirementReason, SessionReauthenticationControl,
};
use crate::membership::SessionMembershipAdmission;
use crate::protocol::{
    checked_frame_size, checked_wire_frame_size, negotiate_response_frame_size,
    read_authenticated_frame_within, read_frame, write_frame_bounded_until,
    write_frame_bounded_until_cancellable, SessionConsensusBootstrapAck,
    SessionConsensusBootstrapHello, SessionConsensusBootstrapRequest,
    SessionConsensusBootstrapResponse, SessionConsensusTransportRequest,
    SessionConsensusTransportResponse, CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
    MAX_HANDSHAKE_FRAME_SIZE, MAX_NEGOTIATED_FRAME_SIZE, MIN_SESSION_CONSENSUS_FRAME_SIZE,
    SESSION_CONSENSUS_ALPN, SESSION_CONSENSUS_TRANSPORT_REVISION,
};

const DEFAULT_CONSENSUS_IDLE_TIMEOUT: Duration =
    DURABLE_CONSENSUS_TIMING_PROFILE.server_idle_timeout();
const DEFAULT_CONSENSUS_RPC_TIMEOUT: Duration =
    DURABLE_CONSENSUS_TIMING_PROFILE.server_handler_timeout();

// Cold establishment is contained inside the caller's existing logical
// deadline. Limiting it to two thirds of the remaining budget guarantees that
// a successful DNS/TCP/TLS/bootstrap phase leaves a non-zero bounded interval
// for the first negotiated RPC. This is especially important for Openraft
// AppendEntries: its 1,500 ms soft TTL is equal to the profile's absolute cold
// cap, so applying only that cap could leave no time to send the heartbeat that
// makes the new connection useful.
const CONSENSUS_COLD_CONNECT_BUDGET_NUMERATOR: u32 = 2;
const CONSENSUS_COLD_CONNECT_BUDGET_DENOMINATOR: u32 = 3;

fn contained_cold_connect_deadline(
    now: tokio::time::Instant,
    call_deadline: tokio::time::Instant,
) -> tokio::time::Instant {
    let remaining = call_deadline.saturating_duration_since(now);
    let proportional_budget = remaining.saturating_mul(CONSENSUS_COLD_CONNECT_BUDGET_NUMERATOR)
        / CONSENSUS_COLD_CONNECT_BUDGET_DENOMINATOR;
    let cold_budget =
        proportional_budget.min(DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout());
    now.checked_add(cold_budget)
        .unwrap_or(call_deadline)
        .min(call_deadline)
}

#[derive(Clone, Copy, Debug)]
enum ConsensusDeadlinePolicy {
    Profiled,
    Fixed(Duration),
}

impl ConsensusDeadlinePolicy {
    const fn from_override(deadline: Option<Duration>) -> Self {
        match deadline {
            Some(deadline) => Self::Fixed(deadline),
            None => Self::Profiled,
        }
    }

    const fn for_family(self, family: ConsensusRpcFamily) -> Duration {
        match self {
            Self::Profiled => DURABLE_CONSENSUS_TIMING_PROFILE.rpc_timeout(family),
            Self::Fixed(deadline) => deadline,
        }
    }
}

/// Resolver callback used by [`RemoteSessionConsensusPeer::new_with_resolver`],
/// [`crate::StatelessSessionConsumerClient::new_with_resolver`], and, when
/// explicitly enabled, the legacy remote-backend compatibility client.
pub type RemoteAddrResolver =
    Arc<dyn Fn() -> BoxFuture<'static, io::Result<SocketAddr>> + Send + Sync>;

#[derive(Clone)]
enum ConsensusTarget {
    #[cfg(feature = "insecure-test")]
    Pinned(SocketAddr),
    Resolved {
        server_name: Option<Arc<str>>,
        resolve: RemoteAddrResolver,
    },
}

impl ConsensusTarget {
    fn configured(binding: &RemoteReplicaBinding) -> Self {
        let endpoint = binding.remote_endpoint();
        let server_name = endpoint.host().to_owned();
        let host = Arc::<str>::from(endpoint.host());
        let port = endpoint.port();
        let resolve: RemoteAddrResolver = Arc::new(move || {
            let host = host.clone();
            Box::pin(async move {
                let mut addresses = tokio::net::lookup_host((host.as_ref(), port)).await?;
                addresses.next().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "consensus endpoint did not resolve",
                    )
                })
            })
        });
        Self::Resolved {
            server_name: Some(Arc::from(server_name)),
            resolve,
        }
    }

    fn resolved(binding: &RemoteReplicaBinding, resolve: RemoteAddrResolver) -> Self {
        Self::Resolved {
            server_name: Some(Arc::from(binding.remote_endpoint().host())),
            resolve,
        }
    }

    #[cfg(feature = "insecure-test")]
    const fn pinned(addr: SocketAddr) -> Self {
        Self::Pinned(addr)
    }

    async fn resolve(&self) -> io::Result<SocketAddr> {
        match self {
            #[cfg(feature = "insecure-test")]
            Self::Pinned(addr) => Ok(*addr),
            Self::Resolved { resolve, .. } => resolve().await,
        }
    }

    fn tls_server_name(
        &self,
        resolved_addr: SocketAddr,
    ) -> Result<rustls_pki_types::ServerName<'static>, SessionConsensusPeerError> {
        match self {
            #[cfg(feature = "insecure-test")]
            Self::Pinned(_) => Ok(rustls_pki_types::ServerName::IpAddress(
                resolved_addr.ip().into(),
            )),
            Self::Resolved {
                server_name: Some(server_name),
                ..
            } => rustls_pki_types::ServerName::try_from(server_name.to_string())
                .map_err(|_| SessionConsensusPeerError::Authentication),
            Self::Resolved {
                server_name: None, ..
            } => Ok(rustls_pki_types::ServerName::IpAddress(
                resolved_addr.ip().into(),
            )),
        }
    }
}

impl fmt::Debug for ConsensusTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsensusTarget(<redacted>)")
    }
}

fn consensus_client_tls_config(config: Arc<opc_tls::ClientConfig>) -> Arc<opc_tls::ClientConfig> {
    let mut config = config.as_ref().clone();
    config.alpn_protocols = vec![SESSION_CONSENSUS_ALPN.to_vec()];
    config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Arc::new(config)
}

fn consensus_server_tls_config(config: Arc<opc_tls::ServerConfig>) -> Arc<opc_tls::ServerConfig> {
    let mut config = config.as_ref().clone();
    config.alpn_protocols = vec![SESSION_CONSENSUS_ALPN.to_vec()];
    config.session_storage = Arc::new(tokio_rustls::rustls::server::NoServerSessionStorage {});
    config.ticketer = Arc::new(DisabledSessionTickets);
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    Arc::new(config)
}

// Consensus reuses connections for small request/response frames. Disable
// Nagle before TLS or the plaintext Hello so either transport cannot inherit a
// delayed-ACK cadence that consumes the bounded consensus call budget.
fn configure_consensus_tcp_socket(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)
}

#[derive(Debug)]
struct DisabledSessionTickets;

impl tokio_rustls::rustls::server::ProducesTickets for DisabledSessionTickets {
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

fn map_protocol_error(error: &ProtocolError) -> SessionConsensusPeerError {
    match error {
        ProtocolError::Io(error) if error.kind() == io::ErrorKind::TimedOut => {
            SessionConsensusPeerError::Timeout
        }
        ProtocolError::Io(_) | ProtocolError::BackendUnavailable(_) => {
            SessionConsensusPeerError::Unavailable
        }
        ProtocolError::Authentication => SessionConsensusPeerError::Authentication,
        ProtocolError::FrameTooLarge(_)
        | ProtocolError::VersionMismatch { .. }
        | ProtocolError::ContractMismatch
        | ProtocolError::InvalidWireValue
        | ProtocolError::UnexpectedResponse
        | ProtocolError::Serialization(_) => SessionConsensusPeerError::Protocol,
    }
}

/// Classify TLS alerts that surface only while the peer consumes the
/// consensus bootstrap frames.
///
/// Rustls may defer a remote credential rejection until the Hello write or
/// HelloAck read. Keep that interpretation at this bootstrap boundary: an
/// ordinary EOF/reset remains unavailable, while a credential alert is an
/// authentication failure rather than a generic transport failure.
fn bootstrap_protocol_error_to_peer_error(error: ProtocolError) -> SessionConsensusPeerError {
    match error {
        ProtocolError::Io(error) => map_protocol_error(&classify_tls_io_error(error)),
        error => map_protocol_error(&error),
    }
}

fn record_consensus_server_connection_failure(error: &ProtocolError) {
    #[cfg(test)]
    if matches!(
        error,
        ProtocolError::Io(error) if error.kind() == io::ErrorKind::TimedOut
    ) {
        crate::test_support::record_connection_timeout_failure();
    }
    match error {
        ProtocolError::Io(error) if error.kind() == io::ErrorKind::TimedOut => {
            &METRICS.session_net_connection_failure_timeout
        }
        ProtocolError::Io(_) => &METRICS.session_net_connection_failure_transport,
        ProtocolError::Authentication => &METRICS.session_net_connection_failure_authentication,
        ProtocolError::BackendUnavailable(_) => &METRICS.session_net_connection_failure_backend,
        _ => &METRICS.session_net_connection_failure_protocol,
    }
    .fetch_add(1, Ordering::Relaxed);
}

fn record_consensus_client_connection_failure(error: SessionConsensusPeerError) {
    match error {
        SessionConsensusPeerError::Unavailable => &METRICS.session_net_connection_failure_transport,
        SessionConsensusPeerError::Timeout => &METRICS.session_net_connection_failure_timeout,
        SessionConsensusPeerError::Authentication => {
            &METRICS.session_net_connection_failure_authentication
        }
        SessionConsensusPeerError::Rejected => &METRICS.session_net_connection_failure_backend,
        _ => &METRICS.session_net_connection_failure_protocol,
    }
    .fetch_add(1, Ordering::Relaxed);
}

fn record_consensus_server_connection_outcome(result: &Result<(), ProtocolError>) {
    match result {
        Ok(()) => {
            METRICS
                .session_net_connection_successes
                .fetch_add(1, Ordering::Relaxed);
            #[cfg(test)]
            crate::test_support::record_connection_success();
        }
        Err(error) => record_consensus_server_connection_failure(error),
    }
}

fn map_tls_connect_error(error: io::Error) -> SessionConsensusPeerError {
    match classify_tls_io_error(error) {
        ProtocolError::Authentication => SessionConsensusPeerError::Authentication,
        ProtocolError::Io(_) => SessionConsensusPeerError::Unavailable,
        _ => SessionConsensusPeerError::Protocol,
    }
}

async fn wait_consensus_material_change(receiver: &mut Option<opc_tls::TlsMaterialStatusReceiver>) {
    loop {
        match receiver.as_mut() {
            Some(status) => {
                if status.changed().await.is_ok() {
                    return;
                }
                *receiver = None;
            }
            None => {
                std::future::pending::<()>().await;
            }
        }
    }
}

async fn wait_consensus_material_epoch_change(
    receiver: &mut Option<opc_tls::TlsMaterialStatusReceiver>,
    admitted_epoch: Option<opc_tls::TlsMaterialEpoch>,
) -> Option<opc_tls::TlsMaterialEpoch> {
    loop {
        let Some(status) = receiver.as_ref() else {
            std::future::pending::<()>().await;
            continue;
        };
        let current_epoch = Some(status.status().epoch());
        if current_epoch != admitted_epoch {
            return current_epoch;
        }
        wait_consensus_material_change(receiver).await;
    }
}

struct ConsensusConnection {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    response_frame_size: usize,
    request_frame_size: usize,
    // Installed only when the cold coordinator publishes this exact
    // authenticated bootstrap. Cached-lane retirement carries the token back
    // to the coordinator so a delayed predecessor cannot reopen a probe gate
    // after a same-epoch successor was already accepted.
    admission_attempt_id: Option<uuid::Uuid>,
    lifecycle: ConnectionLifecycle,
    // This is set only after a complete response has passed call-ID
    // correlation and payload validation. TCP/TLS establishment and attempted
    // writes do not prove that the peer observed a request.
    last_successful_correlated_use: Option<tokio::time::Instant>,
    // A staged cold connection has not yet completed a correlated call. Its
    // establishment/bootstrapping age is therefore the conservative fallback
    // used to prevent `None` from granting unbounded reuse.
    idle_deadline_origin: tokio::time::Instant,
}

fn consensus_connection_idle_deadline(connection: &ConsensusConnection) -> tokio::time::Instant {
    connection
        .last_successful_correlated_use
        .unwrap_or(connection.idle_deadline_origin)
        .checked_add(DURABLE_CONSENSUS_TIMING_PROFILE.client_connection_reuse_limit())
        .unwrap_or(connection.idle_deadline_origin)
}

fn consensus_connection_idle_expired(
    connection: &ConsensusConnection,
    now: tokio::time::Instant,
) -> bool {
    now >= consensus_connection_idle_deadline(connection)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConsensusColdConnectionEpoch {
    consensus_identity: ConsensusIdentity,
    remote_node_id: SessionConsensusNodeId,
    reauthentication_generation: u64,
    material_epoch: Option<opc_tls::TlsMaterialEpoch>,
}

impl ConsensusColdConnectionEpoch {
    /// Return whether this is a causally later connector epoch for the same
    /// coordinator. Reauthentication generations fence every preceding
    /// connector; within one generation TLS material publication epochs are
    /// monotonically ordered. A material-tracking mode change is deliberately
    /// not ordered, so it cannot displace a still-relevant negative gate.
    fn is_strictly_newer_than(self, other: Self) -> bool {
        if self.consensus_identity != other.consensus_identity
            || self.remote_node_id != other.remote_node_id
        {
            return false;
        }
        if self.reauthentication_generation != other.reauthentication_generation {
            return self.reauthentication_generation > other.reauthentication_generation;
        }
        match (self.material_epoch, other.material_epoch) {
            (Some(current), Some(previous)) => current > previous,
            (None, None) | (Some(_), None) | (None, Some(_)) => false,
        }
    }
}

#[derive(Default)]
struct ConsensusColdAttemptReceipt {
    terminal: std::sync::Mutex<Option<SessionConsensusPeerError>>,
}

/// Per-exact-peer negative admission state for an authenticated remote
/// bootstrap retirement. This stays beside the shared cold coordinator, so it
/// gates physical setup rather than individual Openraft calls.
#[derive(Clone, Copy)]
struct ConsensusRemoteRetirementProbeGate {
    epoch: ConsensusColdConnectionEpoch,
    next_probe_at: Option<tokio::time::Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConsensusAcceptedConnection {
    epoch: ConsensusColdConnectionEpoch,
    attempt_id: uuid::Uuid,
    peer_certificate_effective_expiry: Option<opc_types::Timestamp>,
}

impl ConsensusRemoteRetirementProbeGate {
    fn blocks(self, epoch: ConsensusColdConnectionEpoch, now: tokio::time::Instant) -> bool {
        self.epoch == epoch
            && self
                .next_probe_at
                .is_none_or(|next_probe_at| now < next_probe_at)
    }

    fn probe_is_due(self, epoch: ConsensusColdConnectionEpoch, now: tokio::time::Instant) -> bool {
        self.epoch == epoch
            && self
                .next_probe_at
                .is_some_and(|next_probe_at| now >= next_probe_at)
    }

    fn waitable_probe_at(
        self,
        epoch: ConsensusColdConnectionEpoch,
        call_deadline: tokio::time::Instant,
    ) -> Option<tokio::time::Instant> {
        if self.epoch != epoch {
            return None;
        }
        let probe_at = self.next_probe_at?;
        probe_at
            .checked_add(DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout())
            .filter(|complete_probe_deadline| *complete_probe_deadline <= call_deadline)
            .map(|_| probe_at)
    }
}

const fn is_credential_lifecycle_retirement(reason: RetirementReason) -> bool {
    matches!(
        reason,
        RetirementReason::LocalLeafExpiry
            | RetirementReason::PeerLeafExpiry
            | RetirementReason::LocalCertificateChainExpiry
            | RetirementReason::PeerCertificateChainExpiry
    )
}

impl ConsensusColdAttemptReceipt {
    fn publish(&self, error: SessionConsensusPeerError) {
        let mut terminal = self
            .terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if terminal.is_none() {
            *terminal = Some(error);
        }
    }

    fn terminal(&self) -> Option<SessionConsensusPeerError> {
        *self
            .terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

enum ConsensusColdConnectionPhase {
    Idle,
    Connecting {
        attempt_id: uuid::Uuid,
        epoch: ConsensusColdConnectionEpoch,
        attempt_deadline: tokio::time::Instant,
        receipt: Arc<ConsensusColdAttemptReceipt>,
        remote_retirement_probe: bool,
    },
    Ready {
        attempt_id: uuid::Uuid,
        epoch: ConsensusColdConnectionEpoch,
        connection: Box<ConsensusConnection>,
    },
    Failed {
        attempt_id: uuid::Uuid,
        epoch: ConsensusColdConnectionEpoch,
        error: SessionConsensusPeerError,
    },
}

struct ConsensusColdConnectionState {
    phase: ConsensusColdConnectionPhase,
    no_admission_marker: uuid::Uuid,
    remote_retirement_probe_gate: Option<ConsensusRemoteRetirementProbeGate>,
    latest_accepted_connection: Option<ConsensusAcceptedConnection>,
}

struct ConsensusColdConnectionCoordinator {
    state: Mutex<ConsensusColdConnectionState>,
    changed: Notify,
    #[cfg(test)]
    pre_claim_state_lock_hook: std::sync::Mutex<Option<Arc<ConsensusColdClaimLockHook>>>,
}

#[cfg(test)]
struct ConsensusColdClaimLockHook {
    entered: Notify,
    release: Notify,
    armed: AtomicBool,
}

#[cfg(test)]
impl ConsensusColdClaimLockHook {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Notify::new(),
            release: Notify::new(),
            armed: AtomicBool::new(true),
        })
    }
}

// This test-only task-local seam pauses an outbound setup only after its
// complete bootstrap has been accepted and validated. It lets the regression
// test advance time between physical establishment and cold-pool admission
// without exposing a production control surface.
#[cfg(test)]
struct ConsensusPostAcceptedBootstrapHook {
    entered: Notify,
    release: Notify,
    arrived: AtomicBool,
}

#[cfg(test)]
impl ConsensusPostAcceptedBootstrapHook {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Notify::new(),
            release: Notify::new(),
            arrived: AtomicBool::new(false),
        })
    }
}

#[cfg(test)]
tokio::task_local! {
    static CONSENSUS_POST_ACCEPTED_BOOTSTRAP_HOOK: Arc<ConsensusPostAcceptedBootstrapHook>;
    static CONSENSUS_PRE_READY_PUBLICATION_HOOK: Arc<ConsensusPostAcceptedBootstrapHook>;
}

#[cfg(test)]
async fn pause_after_accepted_consensus_bootstrap() {
    let Ok(hook) = CONSENSUS_POST_ACCEPTED_BOOTSTRAP_HOOK.try_with(Arc::clone) else {
        return;
    };
    hook.arrived.store(true, Ordering::Release);
    hook.entered.notify_one();
    hook.release.notified().await;
}

// This second test-only seam is deliberately after the detached attempt's
// outer deadline fence and before the coordinator lock. It makes the lock-wait
// deadline crossing deterministic without changing production scheduling.
#[cfg(test)]
async fn pause_before_consensus_ready_publication() {
    let Ok(hook) = CONSENSUS_PRE_READY_PUBLICATION_HOOK.try_with(Arc::clone) else {
        return;
    };
    hook.arrived.store(true, Ordering::Release);
    hook.entered.notify_one();
    hook.release.notified().await;
}

#[derive(Clone, Copy)]
enum ConsensusStagedConnectionInvalidation {
    Shutdown,
    Forced(RetirementReason),
    Lifecycle,
    IdleTimeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConsensusPublishReadyOutcome {
    Published,
    TimedOut,
    Retired(RetirementReason),
    Superseded,
}

impl ConsensusColdConnectionCoordinator {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ConsensusColdConnectionState {
                phase: ConsensusColdConnectionPhase::Idle,
                no_admission_marker: uuid::Uuid::nil(),
                remote_retirement_probe_gate: None,
                latest_accepted_connection: None,
            }),
            changed: Notify::new(),
            #[cfg(test)]
            pre_claim_state_lock_hook: std::sync::Mutex::new(None),
        })
    }

    async fn publish_ready(
        &self,
        attempt_id: uuid::Uuid,
        epoch: ConsensusColdConnectionEpoch,
        mut connection: Box<ConsensusConnection>,
    ) -> ConsensusPublishReadyOutcome {
        let mut state = self.state.lock().await;
        let Some((receipt, attempt_deadline)) = (match &state.phase {
            ConsensusColdConnectionPhase::Connecting {
                attempt_id: current_attempt_id,
                epoch: current_epoch,
                receipt,
                attempt_deadline,
                ..
            } if *current_attempt_id == attempt_id && *current_epoch == epoch => {
                Some((Arc::clone(receipt), *attempt_deadline))
            }
            _ => None,
        }) else {
            return ConsensusPublishReadyOutcome::Superseded;
        };
        let now = tokio::time::Instant::now();
        let no_admission = if now >= attempt_deadline {
            Some((
                SessionConsensusPeerError::Timeout,
                ConsensusPublishReadyOutcome::TimedOut,
            ))
        } else {
            connection.lifecycle.retirement(now).map(|reason| {
                (
                    SessionConsensusPeerError::Unavailable,
                    ConsensusPublishReadyOutcome::Retired(reason),
                )
            })
        };
        if let Some((error, outcome)) = no_admission {
            // Accepted bootstrap bytes are not Call admission. Every caller
            // joined to this exact setup must observe one no-admission edge;
            // only a genuinely later logical call may start another setup.
            state.phase = ConsensusColdConnectionPhase::Failed {
                attempt_id,
                epoch,
                error,
            };
            receipt.publish(error);
            state.no_admission_marker = attempt_id;
            // Only credential lifecycle retirement justifies the durable
            // probe gate. A local deadline or maximum-age overrun retains any
            // existing gate but must not create one; the ordinary reconnect
            // gate already bounds a later setup attempt.
            if matches!(
                outcome,
                ConsensusPublishReadyOutcome::Retired(reason)
                    if is_credential_lifecycle_retirement(reason)
            ) {
                Self::arm_remote_retirement_probe_gate(&mut state, epoch);
            }
            drop(state);
            self.changed.notify_waiters();
            return outcome;
        }
        connection.admission_attempt_id = Some(attempt_id);
        state.latest_accepted_connection = Some(ConsensusAcceptedConnection {
            epoch,
            attempt_id,
            peer_certificate_effective_expiry: connection
                .lifecycle
                .peer_certificate_effective_expiry(),
        });
        state.phase = ConsensusColdConnectionPhase::Ready {
            attempt_id,
            epoch,
            connection,
        };
        // A usable authenticated Accepted bootstrap proves that this exact
        // peer/epoch is no longer remotely retired. A delayed older attempt
        // cannot, however, erase a causally newer or incomparable gate that
        // arrived while its physical setup was in flight.
        let clear_remote_retirement_probe_gate = state
            .remote_retirement_probe_gate
            .is_none_or(|gate| gate.epoch == epoch || epoch.is_strictly_newer_than(gate.epoch));
        if clear_remote_retirement_probe_gate {
            state.remote_retirement_probe_gate = None;
        }
        drop(state);
        self.changed.notify_waiters();
        ConsensusPublishReadyOutcome::Published
    }

    async fn publish_failure(
        &self,
        attempt_id: uuid::Uuid,
        epoch: ConsensusColdConnectionEpoch,
        error: SessionConsensusPeerError,
    ) {
        let mut state = self.state.lock().await;
        let receipt = match &state.phase {
            ConsensusColdConnectionPhase::Connecting {
                attempt_id: current_attempt_id,
                epoch: current_epoch,
                receipt,
                remote_retirement_probe,
                ..
            } if *current_attempt_id == attempt_id && *current_epoch == epoch => {
                Some((Arc::clone(receipt), *remote_retirement_probe))
            }
            _ => None,
        };
        if let Some((receipt, remote_retirement_probe)) = receipt {
            // A failed pre-Call attempt is a shared terminal receipt, not a
            // consumable retry hint. Advancing the marker while installing the
            // receipt keeps every claimant joined to this attempt out of a
            // replacement attempt; only a later logical call may replace it.
            let remote_retirement = error == SessionConsensusPeerError::Rejected;
            let error = if remote_retirement {
                SessionConsensusPeerError::Unavailable
            } else {
                error
            };
            receipt.publish(error);
            state.phase = ConsensusColdConnectionPhase::Failed {
                attempt_id,
                epoch,
                // Bootstrap retirement is deliberately represented as the
                // no-admission result, never surfaced as a Call result.
                error,
            };
            state.no_admission_marker = attempt_id;
            if remote_retirement || remote_retirement_probe {
                Self::arm_remote_retirement_probe_gate(&mut state, epoch);
            }
            drop(state);
            self.changed.notify_waiters();
        }
    }

    async fn publish_no_admission(
        &self,
        attempt_id: uuid::Uuid,
        epoch: ConsensusColdConnectionEpoch,
        error: SessionConsensusPeerError,
    ) {
        let mut state = self.state.lock().await;
        let receipt = match &state.phase {
            ConsensusColdConnectionPhase::Connecting {
                attempt_id: current_attempt_id,
                epoch: current_epoch,
                receipt,
                remote_retirement_probe,
                ..
            } if *current_attempt_id == attempt_id && *current_epoch == epoch => {
                Some((Arc::clone(receipt), *remote_retirement_probe))
            }
            _ => None,
        };
        if let Some((receipt, remote_retirement_probe)) = receipt {
            receipt.publish(error);
            state.phase = ConsensusColdConnectionPhase::Failed {
                attempt_id,
                epoch,
                error,
            };
            state.no_admission_marker = attempt_id;
            if remote_retirement_probe {
                Self::arm_remote_retirement_probe_gate(&mut state, epoch);
            }
            drop(state);
            self.changed.notify_waiters();
        }
    }

    fn arm_remote_retirement_probe_gate(
        state: &mut ConsensusColdConnectionState,
        epoch: ConsensusColdConnectionEpoch,
    ) {
        if state
            .remote_retirement_probe_gate
            .is_some_and(|gate| gate.epoch != epoch && !epoch.is_strictly_newer_than(gate.epoch))
        {
            // An authenticated result is authoritative only for the epoch
            // that produced it. A delayed old attempt cannot replace a gate
            // for newer reauthentication or TLS material.
            return;
        }
        let now = tokio::time::Instant::now();
        state.remote_retirement_probe_gate = Some(ConsensusRemoteRetirementProbeGate {
            epoch,
            // The unrepresentable-instant edge is fail-closed: no call may
            // turn it into an operation-rate-dependent setup storm.
            next_probe_at: now.checked_add(DURABLE_CONSENSUS_REMOTE_RETIREMENT_PROBE_INTERVAL),
        });
    }

    fn seed_credential_retirement_probe_gate(
        state: &mut ConsensusColdConnectionState,
        epoch: ConsensusColdConnectionEpoch,
        admission_attempt_id: Option<uuid::Uuid>,
        peer_certificate_effective_expiry: Option<opc_types::Timestamp>,
        reason: RetirementReason,
    ) {
        let retirement_is_superseded = state.latest_accepted_connection.is_some_and(|accepted| {
            if epoch != accepted.epoch {
                return accepted.epoch.is_strictly_newer_than(epoch);
            }
            matches!(
                reason,
                RetirementReason::PeerLeafExpiry | RetirementReason::PeerCertificateChainExpiry
            ) && admission_attempt_id.is_some_and(|attempt_id| attempt_id != accepted.attempt_id)
                && peer_certificate_effective_expiry
                    .zip(accepted.peer_certificate_effective_expiry)
                    .is_some_and(|(retired, current)| current > retired)
        });
        if retirement_is_superseded {
            // Primary and overflow lanes can hold different authenticated
            // connections under one local epoch because remote certificate
            // replacement is not part of that epoch. Once a later bootstrap
            // is accepted, retirement of an older cached lane is stale
            // evidence and must not reopen the just-cleared probe gate. A
            // missing/equal credential evidence stays conservative, local
            // credential expiry under the same material epoch always remains
            // applicable, and retirement of the latest accepted connection
            // still seeds normally.
            return;
        }
        if state
            .remote_retirement_probe_gate
            .is_some_and(|gate| gate.epoch == epoch || !epoch.is_strictly_newer_than(gate.epoch))
        {
            // A credential reaper reports the epoch its cached connection
            // was admitted under, which can lag a newer connector epoch.
            // Preserve an equal gate without shortening, resetting, or
            // extending its failed-probe window; preserve a causally newer
            // gate against a delayed stale reaper. A later connector epoch,
            // however, must replace an older exact-epoch gate so its own
            // cached credential retirement has one immediate probe.
            return;
        }
        state.remote_retirement_probe_gate = Some(ConsensusRemoteRetirementProbeGate {
            epoch,
            // No replacement has been tested yet, so one later caller may
            // own the immediate probe under the coordinator lock.
            next_probe_at: Some(tokio::time::Instant::now()),
        });
    }

    async fn seed_credential_retirement_probe(
        &self,
        epoch: ConsensusColdConnectionEpoch,
        admission_attempt_id: Option<uuid::Uuid>,
        peer_certificate_effective_expiry: Option<opc_types::Timestamp>,
        reason: RetirementReason,
    ) {
        if !is_credential_lifecycle_retirement(reason) {
            return;
        }
        let mut state = self.state.lock().await;
        Self::seed_credential_retirement_probe_gate(
            &mut state,
            epoch,
            admission_attempt_id,
            peer_certificate_effective_expiry,
            reason,
        );
        drop(state);
        self.changed.notify_waiters();
    }

    async fn invalidate_ready(
        &self,
        attempt_id: uuid::Uuid,
        invalidation: ConsensusStagedConnectionInvalidation,
    ) -> bool {
        let mut state = self.state.lock().await;
        let current = std::mem::replace(&mut state.phase, ConsensusColdConnectionPhase::Idle);
        if let ConsensusColdConnectionPhase::Ready {
            attempt_id: current_attempt_id,
            epoch,
            connection,
        } = current
        {
            if current_attempt_id != attempt_id {
                state.phase = ConsensusColdConnectionPhase::Ready {
                    attempt_id: current_attempt_id,
                    epoch,
                    connection,
                };
                return false;
            }
            let credential_retirement = match invalidation {
                ConsensusStagedConnectionInvalidation::Shutdown => None,
                ConsensusStagedConnectionInvalidation::Forced(reason) => {
                    connection.lifecycle.record_forced_retirement(reason);
                    None
                }
                ConsensusStagedConnectionInvalidation::Lifecycle => {
                    connection.lifecycle.retirement(tokio::time::Instant::now())
                }
                ConsensusStagedConnectionInvalidation::IdleTimeout => {
                    connection
                        .lifecycle
                        .record_forced_retirement(RetirementReason::IdleTimeout);
                    None
                }
            };
            if matches!(
                invalidation,
                ConsensusStagedConnectionInvalidation::Shutdown
                    | ConsensusStagedConnectionInvalidation::Lifecycle
                    | ConsensusStagedConnectionInvalidation::IdleTimeout
            ) {
                state.no_admission_marker = current_attempt_id;
            }
            if credential_retirement.is_some_and(is_credential_lifecycle_retirement) {
                Self::seed_credential_retirement_probe_gate(
                    &mut state,
                    epoch,
                    connection.admission_attempt_id,
                    connection.lifecycle.peer_certificate_effective_expiry(),
                    credential_retirement.expect("credential retirement reason"),
                );
            }
            let seeded = credential_retirement.is_some_and(is_credential_lifecycle_retirement);
            drop(state);
            self.changed.notify_waiters();
            return seeded;
        } else {
            state.phase = current;
        }
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsensusConnectionLane {
    Primary,
    Overflow,
}

struct ConsensusConnectionLaneState {
    connection: Mutex<Option<ConsensusConnection>>,
    changed: Arc<Notify>,
    reaper_started: AtomicBool,
    in_flight: Semaphore,
}

impl ConsensusConnectionLaneState {
    fn new() -> Self {
        Self {
            connection: Mutex::new(None),
            changed: Arc::new(Notify::new()),
            reaper_started: AtomicBool::new(false),
            in_flight: Semaphore::new(1),
        }
    }
}

struct ConsensusConnectionPool {
    primary: ConsensusConnectionLaneState,
    overflow: ConsensusConnectionLaneState,
    cold_connection: Arc<ConsensusColdConnectionCoordinator>,
    reconnect_gate: Arc<ReconnectGate>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl ConsensusConnectionPool {
    fn new(lifecycle_policy: ConnectionLifecyclePolicy) -> Self {
        let (shutdown, _) = tokio::sync::watch::channel(false);
        Self {
            primary: ConsensusConnectionLaneState::new(),
            overflow: ConsensusConnectionLaneState::new(),
            cold_connection: ConsensusColdConnectionCoordinator::new(),
            reconnect_gate: ReconnectGate::new(lifecycle_policy),
            shutdown,
        }
    }

    async fn acquire(&self) -> ConsensusConnectionSlot<'_> {
        if let Ok(permit) = self.primary.in_flight.try_acquire() {
            let connection = self.primary.connection.lock().await;
            return self.slot(ConsensusConnectionLane::Primary, connection, permit);
        }
        if let Ok(permit) = self.overflow.in_flight.try_acquire() {
            let connection = self.overflow.connection.lock().await;
            return self.slot(ConsensusConnectionLane::Overflow, connection, permit);
        }

        let (lane, permit) = tokio::select! {
            biased;
            permit = self.primary.in_flight.acquire() => {
                (
                    ConsensusConnectionLane::Primary,
                    permit.expect("fixed primary lane remains open"),
                )
            },
            permit = self.overflow.in_flight.acquire() => {
                (
                    ConsensusConnectionLane::Overflow,
                    permit.expect("fixed overflow lane remains open"),
                )
            },
        };
        let connection = self.lane(lane).connection.lock().await;
        self.slot(lane, connection, permit)
    }

    fn slot<'a>(
        &'a self,
        lane: ConsensusConnectionLane,
        connection: MutexGuard<'a, Option<ConsensusConnection>>,
        permit: SemaphorePermit<'a>,
    ) -> ConsensusConnectionSlot<'a> {
        ConsensusConnectionSlot {
            lane,
            connection,
            _permit: permit,
        }
    }

    fn lane(&self, lane: ConsensusConnectionLane) -> &ConsensusConnectionLaneState {
        match lane {
            ConsensusConnectionLane::Primary => &self.primary,
            ConsensusConnectionLane::Overflow => &self.overflow,
        }
    }

    fn ensure_cached_connection_reaper(
        self: &Arc<Self>,
        lane: ConsensusConnectionLane,
        tls_config: Option<opc_tls::AuthenticatedClientConfig>,
        reauthentication: SessionReauthenticationControl,
        edge_key: [u8; 32],
        epoch: ConsensusColdConnectionEpoch,
    ) {
        let lane_state = self.lane(lane);
        if lane_state
            .reaper_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        tokio::spawn(reap_cached_consensus_connection(
            Arc::downgrade(self),
            lane,
            Arc::clone(&lane_state.changed),
            self.shutdown.subscribe(),
            tls_config,
            reauthentication,
            edge_key,
            epoch,
            Arc::clone(&self.reconnect_gate),
        ));
    }
}

impl Drop for ConsensusConnectionPool {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
    }
}

struct ConsensusConnectionSlot<'a> {
    lane: ConsensusConnectionLane,
    connection: MutexGuard<'a, Option<ConsensusConnection>>,
    _permit: SemaphorePermit<'a>,
}

impl ConsensusConnectionSlot<'_> {
    fn connection(&mut self) -> &mut Option<ConsensusConnection> {
        &mut self.connection
    }
}

#[allow(clippy::too_many_arguments)]
async fn reap_cached_consensus_connection(
    pool: std::sync::Weak<ConsensusConnectionPool>,
    lane: ConsensusConnectionLane,
    changed: Arc<Notify>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Option<opc_tls::AuthenticatedClientConfig>,
    reauthentication: SessionReauthenticationControl,
    edge_key: [u8; 32],
    peer_epoch: ConsensusColdConnectionEpoch,
    reconnect_gate: Arc<ReconnectGate>,
) {
    let mut reauthentication_rx = reauthentication.subscribe();
    let mut material_rx = tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedClientConfig::subscribe_material_changes);
    loop {
        if *shutdown.borrow() {
            return;
        }
        reconnect_gate.observe_epoch(
            reauthentication.generation(),
            tls_config
                .as_ref()
                .map(|config| config.material_status().epoch()),
        );
        // Register before inspecting the lane so an insertion between the
        // inspection and the select cannot lose its wake-up.
        let lane_changed = changed.notified();
        tokio::pin!(lane_changed);
        let retire_at = {
            let Some(pool) = pool.upgrade() else {
                return;
            };
            let lane_state = pool.lane(lane);
            let mut cached = lane_state.connection.lock().await;
            if let Some(connection) = cached.as_mut() {
                let now = tokio::time::Instant::now();
                connection.lifecycle.observe_rotation(
                    now,
                    reauthentication.generation(),
                    tls_config
                        .as_ref()
                        .map(|config| config.material_status().epoch()),
                    &edge_key,
                );
                if let Some(reason) = connection.lifecycle.retirement(now) {
                    let credential_retirement =
                        is_credential_lifecycle_retirement(reason).then(|| {
                            (
                                ConsensusColdConnectionEpoch {
                                    // The reaper is fixed to one lane and its peer
                                    // identity never changes. Its cached connection
                                    // may, however, be replaced by a later admitted
                                    // successor before this retirement is observed.
                                    consensus_identity: peer_epoch.consensus_identity,
                                    remote_node_id: peer_epoch.remote_node_id,
                                    reauthentication_generation: connection
                                        .lifecycle
                                        .admitted_generation(),
                                    material_epoch: connection.lifecycle.admitted_material_epoch(),
                                },
                                connection.admission_attempt_id,
                                connection.lifecycle.peer_certificate_effective_expiry(),
                            )
                        });
                    let retired = cached.take();
                    drop(cached);
                    drop(retired);
                    if let Some((epoch, admission_attempt_id, peer_certificate_effective_expiry)) =
                        credential_retirement
                    {
                        pool.cold_connection
                            .seed_credential_retirement_probe(
                                epoch,
                                admission_attempt_id,
                                peer_certificate_effective_expiry,
                                reason,
                            )
                            .await;
                    }
                    continue;
                }
                if consensus_connection_idle_expired(connection, now) {
                    connection
                        .lifecycle
                        .record_forced_retirement(RetirementReason::IdleTimeout);
                    let retired = cached.take();
                    drop(cached);
                    drop(retired);
                    continue;
                }
                Some(
                    connection
                        .lifecycle
                        .retire_at()
                        .min(consensus_connection_idle_deadline(connection)),
                )
            } else {
                None
            }
        };

        match retire_at {
            Some(retire_at) => {
                tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return;
                        }
                    }
                    _ = &mut lane_changed => {}
                    _ = reauthentication_rx.changed() => {}
                    _ = wait_consensus_material_change(&mut material_rx) => {}
                    _ = tokio::time::sleep_until(retire_at) => {}
                }
            }
            None => {
                tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return;
                        }
                    }
                    _ = &mut lane_changed => {}
                    _ = reauthentication_rx.changed() => {}
                    _ = wait_consensus_material_change(&mut material_rx) => {}
                }
            }
        }
    }
}

#[derive(Clone)]
struct ConsensusColdConnector {
    target: ConsensusTarget,
    tls_config: Option<opc_tls::AuthenticatedClientConfig>,
    binding: RemoteReplicaBinding,
    max_frame_size: usize,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
}

impl ConsensusColdConnector {
    fn epoch(&self) -> ConsensusColdConnectionEpoch {
        ConsensusColdConnectionEpoch {
            consensus_identity: self.binding.consensus_identity(),
            remote_node_id: self.binding.remote_consensus_node_id(),
            reauthentication_generation: self.reauthentication.generation(),
            material_epoch: self
                .tls_config
                .as_ref()
                .map(|config| config.material_status().epoch()),
        }
    }

    async fn establish(
        &self,
        epoch: ConsensusColdConnectionEpoch,
        deadline: tokio::time::Instant,
    ) -> Result<ConsensusConnection, SessionConsensusPeerError> {
        if let Some(tls_config) = &self.tls_config {
            let outcome = tls_config
                .run_handshake(|attempt| {
                    let connector = self.clone();
                    async move {
                        let addr = connector
                            .target
                            .resolve()
                            .await
                            .map_err(|_| SessionConsensusPeerError::Unavailable)?;
                        let tcp = TcpStream::connect(addr)
                            .await
                            .map_err(|_| SessionConsensusPeerError::Unavailable)?;
                        configure_consensus_tcp_socket(&tcp)
                            .map_err(|_| SessionConsensusPeerError::Unavailable)?;
                        let tls_connector = tokio_rustls::TlsConnector::from(
                            consensus_client_tls_config(attempt.rustls_config()),
                        );
                        let server_name = connector.target.tls_server_name(addr)?;
                        let tls_stream = tls_connector
                            .connect(server_name, tcp)
                            .await
                            .map_err(map_tls_connect_error)?;
                        if tls_stream.get_ref().1.alpn_protocol() != Some(SESSION_CONSENSUS_ALPN) {
                            return Err(SessionConsensusPeerError::Protocol);
                        }
                        let peer = opc_tls::peer_tls_identity_from_client_connection(
                            tls_stream.get_ref().1,
                        )
                        .map_err(|_| SessionConsensusPeerError::Authentication)?;
                        if peer.spiffe_id().as_str()
                            != connector.binding.remote_spiffe_id().as_str()
                        {
                            return Err(SessionConsensusPeerError::Authentication);
                        }
                        let tls_completed_at = tokio::time::Instant::now();
                        let local_expiry = CertificateExpiryEvidence::capture(
                            attempt.leaf_expires_at(),
                            attempt.certificate_chain_expires_at(),
                            tls_completed_at,
                        );
                        let peer_expiry = CertificateExpiryEvidence::capture(
                            peer.leaf_expires_at(),
                            peer.certificate_chain_expires_at(),
                            tls_completed_at,
                        );
                        let lifecycle = ConnectionLifecycle::new(
                            connector.lifecycle_policy,
                            tls_completed_at,
                            Some(local_expiry),
                            Some(peer_expiry),
                            epoch.reauthentication_generation,
                            Some(attempt.epoch()),
                        )
                        .map_err(|_| SessionConsensusPeerError::Protocol)?;
                        let (mut reader, mut writer) = tokio::io::split(tls_stream);
                        let (response_frame_size, request_frame_size) = connector
                            .bootstrap(&mut reader, &mut writer, deadline)
                            .await?;
                        Ok::<_, SessionConsensusPeerError>((
                            Box::new(reader) as Box<dyn AsyncRead + Unpin + Send>,
                            Box::new(writer) as Box<dyn AsyncWrite + Unpin + Send>,
                            response_frame_size,
                            request_frame_size,
                            tls_completed_at,
                            lifecycle,
                        ))
                    }
                })
                .await
                .map_err(|error| match error {
                    opc_tls::TlsHandshakeRunError::Material(_) => {
                        SessionConsensusPeerError::Authentication
                    }
                    opc_tls::TlsHandshakeRunError::Operation(error) => error,
                })?;
            let admission = outcome.admission();
            if Some(admission.epoch()) != epoch.material_epoch {
                return Err(SessionConsensusPeerError::Unavailable);
            }
            let (parts, _) = outcome.into_parts();
            let (
                reader,
                writer,
                response_frame_size,
                request_frame_size,
                tls_completed_at,
                lifecycle,
            ) = parts;
            return Ok(ConsensusConnection {
                reader,
                writer,
                response_frame_size,
                request_frame_size,
                admission_attempt_id: None,
                lifecycle,
                last_successful_correlated_use: None,
                idle_deadline_origin: tls_completed_at,
            });
        }

        let addr = self
            .target
            .resolve()
            .await
            .map_err(|_| SessionConsensusPeerError::Unavailable)?;
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|_| SessionConsensusPeerError::Unavailable)?;
        configure_consensus_tcp_socket(&tcp).map_err(|_| SessionConsensusPeerError::Unavailable)?;
        let (mut reader, mut writer) = tokio::io::split(tcp);
        let established_at = tokio::time::Instant::now();
        let (response_frame_size, request_frame_size) =
            self.bootstrap(&mut reader, &mut writer, deadline).await?;
        Ok(ConsensusConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            response_frame_size,
            request_frame_size,
            admission_attempt_id: None,
            lifecycle: ConnectionLifecycle::new(
                self.lifecycle_policy,
                established_at,
                None,
                None,
                epoch.reauthentication_generation,
                None,
            )
            .map_err(|_| SessionConsensusPeerError::Protocol)?,
            last_successful_correlated_use: None,
            idle_deadline_origin: established_at,
        })
    }

    async fn bootstrap<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        deadline: tokio::time::Instant,
    ) -> Result<(usize, usize), SessionConsensusPeerError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let nonce = uuid::Uuid::new_v4();
        let requested_frame_size = checked_wire_frame_size(self.max_frame_size)
            .map_err(|_| SessionConsensusPeerError::Protocol)?;
        let hello = SessionConsensusBootstrapRequest::Hello(SessionConsensusBootstrapHello {
            transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
            contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
            sender_replica_id: self.binding.local_replica_id().as_str().to_owned(),
            expected_server_replica_id: self.binding.remote_replica_id().as_str().to_owned(),
            identity: self.binding.consensus_identity(),
            sender_node_id: self.binding.local_consensus_node_id(),
            expected_server_node_id: self.binding.remote_consensus_node_id(),
            handshake_nonce: nonce,
            requested_response_frame_size: requested_frame_size,
        });
        write_frame_bounded_until(writer, &hello, MAX_HANDSHAKE_FRAME_SIZE, deadline)
            .await
            .map_err(bootstrap_protocol_error_to_peer_error)?;
        let ack: SessionConsensusBootstrapResponse = read_frame(reader, MAX_HANDSHAKE_FRAME_SIZE)
            .await
            .map_err(bootstrap_protocol_error_to_peer_error)?;
        let ack = match ack {
            SessionConsensusBootstrapResponse::Accepted(ack) => ack,
            SessionConsensusBootstrapResponse::Rejected(error) => return Err(error),
        };
        if ack.transport_revision != SESSION_CONSENSUS_TRANSPORT_REVISION
            || !ack.contract_profile.is_current()
            || ack.identity != self.binding.consensus_identity()
            || ack.server_node_id != self.binding.remote_consensus_node_id()
            || ack.accepted_sender_node_id != self.binding.local_consensus_node_id()
            || ack.handshake_nonce != nonce
        {
            return Err(SessionConsensusPeerError::ScopeMismatch);
        }
        let response_frame_size = checked_frame_size(ack.accepted_response_frame_size)
            .map_err(|_| SessionConsensusPeerError::Protocol)?;
        let request_frame_size = checked_frame_size(ack.server_request_frame_size)
            .map_err(|_| SessionConsensusPeerError::Protocol)?;
        if response_frame_size < MIN_SESSION_CONSENSUS_FRAME_SIZE
            || request_frame_size < MIN_SESSION_CONSENSUS_FRAME_SIZE
            || response_frame_size > self.max_frame_size
            || request_frame_size > self.max_frame_size
        {
            return Err(SessionConsensusPeerError::Protocol);
        }
        Ok((response_frame_size, request_frame_size))
    }
}

enum DetachedConsensusConnectionOutcome {
    Established(Result<Box<ConsensusConnection>, SessionConsensusPeerError>),
    Superseded,
    Shutdown,
}

enum ConsensusColdConnectionAction {
    Ready(Box<ConsensusConnection>),
    Failed(SessionConsensusPeerError),
    NoAdmission(SessionConsensusPeerError),
    Retry,
    WaitForRemoteRetirementProbe {
        probe_at: tokio::time::Instant,
    },
    Wait {
        attempt_id: uuid::Uuid,
        epoch: ConsensusColdConnectionEpoch,
        no_admission_marker: uuid::Uuid,
        receipt: Arc<ConsensusColdAttemptReceipt>,
    },
    Spawn {
        attempt_id: uuid::Uuid,
        epoch: ConsensusColdConnectionEpoch,
        attempt_deadline: tokio::time::Instant,
        no_admission_marker: uuid::Uuid,
        receipt: Arc<ConsensusColdAttemptReceipt>,
    },
}

#[allow(clippy::too_many_arguments)]
async fn run_detached_consensus_connection_attempt(
    connector: ConsensusColdConnector,
    coordinator: Arc<ConsensusColdConnectionCoordinator>,
    reconnect_gate: Arc<ReconnectGate>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    attempt_id: uuid::Uuid,
    epoch: ConsensusColdConnectionEpoch,
    attempt_deadline: tokio::time::Instant,
) {
    if tokio::time::Instant::now() >= attempt_deadline {
        coordinator
            .publish_no_admission(attempt_id, epoch, SessionConsensusPeerError::Timeout)
            .await;
        return;
    }
    let mut reauthentication_rx = connector.reauthentication.subscribe();
    let mut material_rx = connector
        .tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedClientConfig::subscribe_material_changes);
    if *shutdown.borrow() || connector.epoch() != epoch {
        let current_epoch = connector.epoch();
        reconnect_gate.observe_epoch(
            current_epoch.reauthentication_generation,
            current_epoch.material_epoch,
        );
        coordinator
            .publish_failure(attempt_id, epoch, SessionConsensusPeerError::Unavailable)
            .await;
        return;
    }
    let acquire = reconnect_gate.acquire_classified(
        attempt_deadline,
        epoch.reauthentication_generation,
        epoch.material_epoch,
    );
    tokio::pin!(acquire);
    let reconnect_admission = tokio::select! {
        biased;
        changed = shutdown.changed() => {
            let _ = changed;
            None
        }
        changed = reauthentication_rx.changed() => {
            if changed.is_ok() {
                reconnect_gate.observe_epoch(
                    connector.reauthentication.generation(),
                    connector
                        .tls_config
                        .as_ref()
                        .map(|config| config.material_status().epoch()),
                );
            }
            None
        }
        material_epoch = wait_consensus_material_epoch_change(
            &mut material_rx,
            epoch.material_epoch,
        ) => {
            reconnect_gate.observe_epoch(
                connector.reauthentication.generation(),
                material_epoch,
            );
            None
        }
        admission = &mut acquire => Some(admission),
    };
    let reconnect_attempt = match reconnect_admission {
        Some(ReconnectAdmission::Admitted(attempt)) => attempt,
        Some(ReconnectAdmission::Cooldown) => {
            coordinator
                .publish_no_admission(attempt_id, epoch, SessionConsensusPeerError::Unavailable)
                .await;
            return;
        }
        Some(ReconnectAdmission::Deadline) => {
            coordinator
                .publish_no_admission(attempt_id, epoch, SessionConsensusPeerError::Timeout)
                .await;
            return;
        }
        Some(ReconnectAdmission::Superseded) | None => {
            let error = if tokio::time::Instant::now() >= attempt_deadline {
                SessionConsensusPeerError::Timeout
            } else {
                SessionConsensusPeerError::Unavailable
            };
            coordinator.publish_failure(attempt_id, epoch, error).await;
            return;
        }
    };

    let mut attempt_metrics = ConnectionAttemptMetricGuard::started();
    let establish = tokio::time::timeout_at(
        attempt_deadline,
        connector.establish(epoch, attempt_deadline),
    );
    tokio::pin!(establish);
    let outcome = {
        let superseded = reconnect_attempt.superseded();
        tokio::pin!(superseded);
        tokio::select! {
            biased;
            () = &mut superseded => DetachedConsensusConnectionOutcome::Superseded,
            changed = shutdown.changed() => {
                let _ = changed;
                DetachedConsensusConnectionOutcome::Shutdown
            }
            changed = reauthentication_rx.changed() => {
                if changed.is_ok() {
                    reconnect_gate.observe_epoch(
                        connector.reauthentication.generation(),
                        connector
                            .tls_config
                            .as_ref()
                            .map(|config| config.material_status().epoch()),
                    );
                }
                DetachedConsensusConnectionOutcome::Superseded
            }
            material_epoch = wait_consensus_material_epoch_change(
                &mut material_rx,
                epoch.material_epoch,
            ) => {
                reconnect_gate.observe_epoch(
                    connector.reauthentication.generation(),
                    material_epoch,
                );
                DetachedConsensusConnectionOutcome::Superseded
            }
            result = &mut establish => DetachedConsensusConnectionOutcome::Established(
                result
                    .unwrap_or(Err(SessionConsensusPeerError::Timeout))
                    .map(Box::new),
            ),
        }
    };
    #[cfg(test)]
    if matches!(
        &outcome,
        DetachedConsensusConnectionOutcome::Established(Ok(_))
    ) {
        pause_after_accepted_consensus_bootstrap().await;
    }

    let connection = match outcome {
        DetachedConsensusConnectionOutcome::Established(Ok(connection))
            if connector.epoch() == epoch =>
        {
            connection
        }
        DetachedConsensusConnectionOutcome::Established(Ok(_))
        | DetachedConsensusConnectionOutcome::Superseded => {
            METRICS
                .session_net_reconnect_attempts
                .fetch_add(1, Ordering::Relaxed);
            attempt_metrics.finish_superseded();
            reconnect_attempt.failed();
            coordinator
                .publish_failure(attempt_id, epoch, SessionConsensusPeerError::Unavailable)
                .await;
            return;
        }
        DetachedConsensusConnectionOutcome::Shutdown => {
            reconnect_attempt.failed();
            coordinator
                .publish_failure(attempt_id, epoch, SessionConsensusPeerError::Unavailable)
                .await;
            // Pool teardown has no wire/deadline outcome. Let the metric
            // guard classify this bounded task cancellation as abandoned.
            return;
        }
        DetachedConsensusConnectionOutcome::Established(Err(error)) => {
            if error == SessionConsensusPeerError::Rejected {
                METRICS
                    .session_net_connection_successes
                    .fetch_add(1, Ordering::Relaxed);
                METRICS
                    .session_net_reconnect_attempts
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                record_consensus_client_connection_failure(error);
                if matches!(
                    error,
                    SessionConsensusPeerError::Unavailable | SessionConsensusPeerError::Timeout
                ) {
                    METRICS
                        .session_net_reconnect_attempts
                        .fetch_add(1, Ordering::Relaxed);
                    METRICS
                        .session_net_reconnect_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            attempt_metrics.finish();
            reconnect_attempt.failed();
            coordinator.publish_failure(attempt_id, epoch, error).await;
            return;
        }
    };

    // `timeout_at` and scheduling races are not sufficient at the exact
    // boundary: publish itself is the admission point.  Fence it again here.
    if tokio::time::Instant::now() >= attempt_deadline {
        coordinator
            .publish_no_admission(attempt_id, epoch, SessionConsensusPeerError::Timeout)
            .await;
        record_consensus_client_connection_failure(SessionConsensusPeerError::Timeout);
        METRICS
            .session_net_reconnect_attempts
            .fetch_add(1, Ordering::Relaxed);
        METRICS
            .session_net_reconnect_failures
            .fetch_add(1, Ordering::Relaxed);
        reconnect_attempt.failed();
        attempt_metrics.finish();
        return;
    }

    #[cfg(test)]
    pause_before_consensus_ready_publication().await;

    match coordinator
        .publish_ready(attempt_id, epoch, connection)
        .await
    {
        ConsensusPublishReadyOutcome::Published => {
            METRICS
                .session_net_connection_successes
                .fetch_add(1, Ordering::Relaxed);
            attempt_metrics.finish();
            reconnect_attempt.succeeded();
        }
        ConsensusPublishReadyOutcome::TimedOut => {
            record_consensus_client_connection_failure(SessionConsensusPeerError::Timeout);
            METRICS
                .session_net_reconnect_attempts
                .fetch_add(1, Ordering::Relaxed);
            METRICS
                .session_net_reconnect_failures
                .fetch_add(1, Ordering::Relaxed);
            attempt_metrics.finish();
            reconnect_attempt.failed();
            return;
        }
        ConsensusPublishReadyOutcome::Retired(_) => {
            // The authenticated setup completed, but its own immutable
            // lifecycle evidence forbade a Call before the lock-held publish
            // transition. Keep the reconnect cooldown failed and give every
            // joined claimant one shared no-admission edge.
            METRICS
                .session_net_connection_successes
                .fetch_add(1, Ordering::Relaxed);
            METRICS
                .session_net_reconnect_attempts
                .fetch_add(1, Ordering::Relaxed);
            attempt_metrics.finish();
            reconnect_attempt.failed();
            return;
        }
        ConsensusPublishReadyOutcome::Superseded => {
            METRICS
                .session_net_reconnect_attempts
                .fetch_add(1, Ordering::Relaxed);
            attempt_metrics.finish_superseded();
            reconnect_attempt.failed();
            return;
        }
    }
    monitor_staged_consensus_connection(
        &connector,
        &coordinator,
        &reconnect_gate,
        &mut shutdown,
        attempt_id,
        epoch,
    )
    .await;
}

async fn monitor_staged_consensus_connection(
    connector: &ConsensusColdConnector,
    coordinator: &ConsensusColdConnectionCoordinator,
    reconnect_gate: &ReconnectGate,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    attempt_id: uuid::Uuid,
    epoch: ConsensusColdConnectionEpoch,
) {
    let mut reauthentication_rx = connector.reauthentication.subscribe();
    let mut material_rx = connector
        .tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedClientConfig::subscribe_material_changes);
    loop {
        if *shutdown.borrow() {
            coordinator
                .invalidate_ready(attempt_id, ConsensusStagedConnectionInvalidation::Shutdown)
                .await;
            return;
        }
        let current_epoch = connector.epoch();
        if current_epoch != epoch {
            reconnect_gate.observe_epoch(
                current_epoch.reauthentication_generation,
                current_epoch.material_epoch,
            );
            let reason =
                if current_epoch.reauthentication_generation != epoch.reauthentication_generation {
                    RetirementReason::Explicit
                } else {
                    RetirementReason::MaterialEpoch
                };
            coordinator
                .invalidate_ready(
                    attempt_id,
                    ConsensusStagedConnectionInvalidation::Forced(reason),
                )
                .await;
            return;
        }
        let changed = coordinator.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let (retire_at, idle_deadline) = {
            let state = coordinator.state.lock().await;
            match &state.phase {
                ConsensusColdConnectionPhase::Ready {
                    attempt_id: current_attempt_id,
                    epoch: current_epoch,
                    connection,
                } if *current_attempt_id == attempt_id && *current_epoch == epoch => (
                    connection.lifecycle.retire_at(),
                    consensus_connection_idle_deadline(connection),
                ),
                _ => return,
            }
        };
        let invalidation = tokio::select! {
            biased;
            _ = &mut changed => continue,
            changed = shutdown.changed() => {
                let _ = changed;
                ConsensusStagedConnectionInvalidation::Shutdown
            }
            changed = reauthentication_rx.changed() => {
                if changed.is_ok() {
                    reconnect_gate.observe_epoch(
                        connector.reauthentication.generation(),
                        connector
                            .tls_config
                            .as_ref()
                            .map(|config| config.material_status().epoch()),
                    );
                    ConsensusStagedConnectionInvalidation::Forced(RetirementReason::Explicit)
                } else {
                    ConsensusStagedConnectionInvalidation::Shutdown
                }
            }
            material_epoch = wait_consensus_material_epoch_change(
                &mut material_rx,
                epoch.material_epoch,
            ) => {
                reconnect_gate.observe_epoch(
                    connector.reauthentication.generation(),
                    material_epoch,
                );
                ConsensusStagedConnectionInvalidation::Forced(RetirementReason::MaterialEpoch)
            }
            _ = tokio::time::sleep_until(retire_at.min(idle_deadline)) => {
                if idle_deadline <= retire_at {
                    ConsensusStagedConnectionInvalidation::IdleTimeout
                } else {
                    ConsensusStagedConnectionInvalidation::Lifecycle
                }
            }
        };
        let seeded_credential_retirement =
            coordinator.invalidate_ready(attempt_id, invalidation).await;
        if matches!(
            invalidation,
            ConsensusStagedConnectionInvalidation::Lifecycle
                | ConsensusStagedConnectionInvalidation::IdleTimeout
        ) && !seeded_credential_retirement
        {
            reconnect_gate.publish_failure_cooldown(
                epoch.reauthentication_generation,
                epoch.material_epoch,
                Duration::ZERO,
            );
        }
        return;
    }
}

/// Authenticated outbound peer implementing only the session consensus port.
#[derive(Clone)]
pub struct RemoteSessionConsensusPeer {
    target: ConsensusTarget,
    tls_config: Option<opc_tls::AuthenticatedClientConfig>,
    binding: RemoteReplicaBinding,
    deadline_policy: ConsensusDeadlinePolicy,
    max_frame_size: usize,
    connection_pool: Arc<ConsensusConnectionPool>,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
}

impl fmt::Debug for RemoteSessionConsensusPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteSessionConsensusPeer")
            .field("target", &self.target)
            .field("authenticated", &self.tls_config.is_some())
            .field("deadline_policy", &self.deadline_policy)
            .field("max_frame_size", &self.max_frame_size)
            .finish_non_exhaustive()
    }
}

impl RemoteSessionConsensusPeer {
    /// Current redaction-safe health of the credentials this peer authenticates
    /// with, or `None` when the peer is running without TLS.
    ///
    /// This is the signal a CNF readiness probe should consume during a
    /// credential or trust-bundle rotation. It reports only epoch,
    /// availability and a closed reason enum -- never certificate bytes or
    /// identity text -- so it is safe to surface in health output.
    ///
    /// `RetainingLastGood` means a candidate was rejected and the previous
    /// material is still serving: connections continue, but the rotation did
    /// not take effect and the reason says why. `Unavailable` means there is
    /// no usable material and new handshakes will fail.
    #[must_use]
    pub fn credential_health(&self) -> Option<opc_tls::TlsMaterialStatus> {
        self.tls_config
            .as_ref()
            .map(opc_tls::AuthenticatedClientConfig::material_status)
    }

    /// Exact authenticated cluster/configuration/epoch scope carried by this
    /// peer. Dynamic peer directories must compare this evidence with the
    /// staged manifest instead of trusting a node ID alone.
    pub fn consensus_identity(&self) -> ConsensusIdentity {
        self.binding.consensus_identity()
    }

    /// Canonical local sender ordinal bound into this peer's authenticated
    /// requests.
    pub fn local_consensus_node_id(&self) -> SessionConsensusNodeId {
        self.binding.local_consensus_node_id()
    }

    /// Construct a mutually authenticated consensus-only peer.
    ///
    /// `None` selects the fixed family-specific durable timing profile.
    /// `Some` retains the source-compatible uniform complete-call override for
    /// tests and controlled compatibility only; it cannot enlarge the shared
    /// cold-connection sub-bound and is not the production profile.
    pub fn new(
        binding: RemoteReplicaBinding,
        tls_config: opc_tls::AuthenticatedClientConfig,
        deadline: Option<Duration>,
    ) -> Self {
        let target = ConsensusTarget::configured(&binding);
        Self::from_transport(target, Some(tls_config), binding, deadline)
    }

    /// Construct a production-profiled mutually authenticated peer.
    pub fn new_profiled(
        binding: RemoteReplicaBinding,
        tls_config: opc_tls::AuthenticatedClientConfig,
    ) -> Self {
        Self::new(binding, tls_config, None)
    }

    /// Construct a mutually authenticated peer with a reconnect-time resolver.
    ///
    /// `None` selects the fixed family-specific durable timing profile.
    /// `Some` is a non-qualifying uniform complete-call test/compatibility
    /// override and cannot enlarge the shared cold-connection sub-bound.
    pub fn new_with_resolver(
        binding: RemoteReplicaBinding,
        resolve: RemoteAddrResolver,
        tls_config: opc_tls::AuthenticatedClientConfig,
        deadline: Option<Duration>,
    ) -> Self {
        let target = ConsensusTarget::resolved(&binding, resolve);
        Self::from_transport(target, Some(tls_config), binding, deadline)
    }

    /// Construct a production-profiled peer with reconnect-time resolution.
    pub fn new_profiled_with_resolver(
        binding: RemoteReplicaBinding,
        resolve: RemoteAddrResolver,
        tls_config: opc_tls::AuthenticatedClientConfig,
    ) -> Self {
        Self::new_with_resolver(binding, resolve, tls_config, None)
    }

    /// Construct a plaintext consensus peer for transport tests.
    #[cfg(feature = "insecure-test")]
    pub fn new_insecure(
        binding: RemoteReplicaBinding,
        addr: SocketAddr,
        deadline: Option<Duration>,
    ) -> Self {
        Self::from_transport(ConsensusTarget::pinned(addr), None, binding, deadline)
    }

    fn from_transport(
        target: ConsensusTarget,
        tls_config: Option<opc_tls::AuthenticatedClientConfig>,
        binding: RemoteReplicaBinding,
        deadline: Option<Duration>,
    ) -> Self {
        let lifecycle_policy = ConnectionLifecyclePolicy::default();
        Self {
            target,
            tls_config,
            binding,
            deadline_policy: ConsensusDeadlinePolicy::from_override(deadline),
            // The bounded inner consensus payload needs the maximum profile
            // frame in its worst-case JSON byte-array expansion.
            max_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            connection_pool: Arc::new(ConsensusConnectionPool::new(lifecycle_policy)),
            lifecycle_policy,
            reauthentication: SessionReauthenticationControl::new(),
        }
    }

    /// Set the negotiated encoded request/response frame budget.
    #[must_use]
    pub fn with_max_frame_size(mut self, max_frame_size: usize) -> Self {
        self.max_frame_size = max_frame_size;
        // A clone-local wire budget cannot reuse a connection negotiated by a
        // differently configured clone.
        self.connection_pool = Arc::new(ConsensusConnectionPool::new(self.lifecycle_policy));
        self
    }

    /// Set the finite authentication and drain policy for consensus calls.
    #[must_use]
    pub fn with_connection_lifecycle(mut self, policy: ConnectionLifecyclePolicy) -> Self {
        self.lifecycle_policy = policy;
        self.connection_pool = Arc::new(ConsensusConnectionPool::new(policy));
        self
    }

    /// Share the graceful reauthentication trigger used by this peer.
    #[must_use]
    pub fn with_reauthentication_control(
        mut self,
        control: SessionReauthenticationControl,
    ) -> Self {
        self.reauthentication = control;
        self.connection_pool = Arc::new(ConsensusConnectionPool::new(self.lifecycle_policy));
        self
    }

    /// Control used by this peer for explicit graceful reauthentication.
    pub fn reauthentication_control(&self) -> SessionReauthenticationControl {
        self.reauthentication.clone()
    }

    fn cold_connector(&self) -> ConsensusColdConnector {
        ConsensusColdConnector {
            target: self.target.clone(),
            tls_config: self.tls_config.clone(),
            binding: self.binding.clone(),
            max_frame_size: self.max_frame_size,
            lifecycle_policy: self.lifecycle_policy,
            reauthentication: self.reauthentication.clone(),
        }
    }

    async fn claim_or_start_cold_connection(
        &self,
        call_deadline: tokio::time::Instant,
    ) -> Result<ConsensusConnection, SessionConsensusPeerError> {
        let connector = self.cold_connector();
        let coordinator = &self.connection_pool.cold_connection;
        let mut reauthentication_rx = self.reauthentication.subscribe();
        let mut material_rx = self
            .tls_config
            .as_ref()
            .map(opc_tls::AuthenticatedClientConfig::subscribe_material_changes);
        let mut joined_no_admission_marker = None;
        let mut joined_attempt_id = None;
        let mut joined_attempt_epoch = None;
        let mut joined_receipt = None;
        // The remote-retirement gate is pre-Call admission state, so it may
        // consume the whole logical deadline. Once this caller has actually
        // admitted or joined a setup, fix its cold budget once; notification
        // wakeups and successor epochs must not replenish it.
        let mut cold_connect_deadline = None;
        loop {
            let epoch = connector.epoch();
            if joined_attempt_epoch == Some(epoch) {
                let terminal = joined_receipt
                    .as_ref()
                    .and_then(|receipt: &Arc<ConsensusColdAttemptReceipt>| receipt.terminal());
                if let Some(error) = terminal {
                    return Err(error);
                }
            }
            if tokio::time::Instant::now() >= call_deadline {
                return Err(SessionConsensusPeerError::Timeout);
            }
            self.connection_pool
                .reconnect_gate
                .observe_epoch(epoch.reauthentication_generation, epoch.material_epoch);
            let changed = coordinator.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            #[cfg(test)]
            let pre_claim_state_lock_hook = {
                coordinator
                    .pre_claim_state_lock_hook
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            };
            #[cfg(test)]
            if let Some(hook) = pre_claim_state_lock_hook {
                if hook.armed.swap(false, Ordering::AcqRel) {
                    hook.entered.notify_one();
                    hook.release.notified().await;
                }
            }
            let action = {
                let mut state = coordinator.state.lock().await;
                if joined_attempt_epoch == Some(epoch) {
                    let terminal = joined_receipt
                        .as_ref()
                        .and_then(|receipt: &Arc<ConsensusColdAttemptReceipt>| receipt.terminal());
                    if let Some(error) = terminal {
                        return Err(error);
                    }
                }
                let terminal_receipt_is_superseded = matches!(
                    &state.phase,
                    ConsensusColdConnectionPhase::Failed {
                        epoch: receipt_epoch,
                        ..
                    } if *receipt_epoch != epoch
                );
                if terminal_receipt_is_superseded {
                    // Reauthentication or new material starts a newer shared
                    // epoch. Claimants still alive in that epoch may join its
                    // one replacement setup; they remain fenced from the old
                    // receipt rather than consuming it.
                    joined_no_admission_marker = Some(state.no_admission_marker);
                    joined_attempt_id = None;
                    joined_attempt_epoch = None;
                    joined_receipt = None;
                }
                let now = tokio::time::Instant::now();
                if now >= call_deadline {
                    // The caller may have reached its exact logical boundary
                    // while awaiting the coordinator lock. Do not let that
                    // scheduler delay launch a detached physical probe beyond
                    // the deadline that admitted the wait.
                    return Err(SessionConsensusPeerError::Timeout);
                }
                if state
                    .remote_retirement_probe_gate
                    .is_some_and(|gate| gate.blocks(epoch, now))
                {
                    match state
                        .remote_retirement_probe_gate
                        .and_then(|gate| gate.waitable_probe_at(epoch, call_deadline))
                    {
                        Some(probe_at) => {
                            // Do not hold the coordinator lock while this
                            // logical caller awaits the one fixed probe
                            // boundary. Admission reserves the full fixed cold
                            // setup budget after that boundary, so short
                            // Openraft RPCs can never be parked in the tail of
                            // a retirement window. A newer local epoch or
                            // coordinator publication wakes it to re-evaluate
                            // early.
                            ConsensusColdConnectionAction::WaitForRemoteRetirementProbe { probe_at }
                        }
                        None => {
                            // This caller's original logical budget cannot
                            // contain both the shared probe boundary and a
                            // complete cold setup. Preserve a prompt pre-Call
                            // no-admission result instead of occupying a short
                            // Openraft RPC until Timeout; doing so keeps the
                            // healthy-quorum path live while still admitting
                            // zero physical setups.
                            ConsensusColdConnectionAction::NoAdmission(
                                SessionConsensusPeerError::Unavailable,
                            )
                        }
                    }
                } else if joined_no_admission_marker
                    .is_some_and(|marker| marker != state.no_admission_marker)
                    && !terminal_receipt_is_superseded
                {
                    match &state.phase {
                        ConsensusColdConnectionPhase::Failed {
                            attempt_id,
                            epoch: receipt_epoch,
                            error,
                        } if joined_attempt_id == Some(*attempt_id)
                            && *attempt_id == state.no_admission_marker
                            && *receipt_epoch == epoch =>
                        {
                            ConsensusColdConnectionAction::Failed(*error)
                        }
                        _ => ConsensusColdConnectionAction::NoAdmission(
                            SessionConsensusPeerError::Unavailable,
                        ),
                    }
                } else {
                    let remote_retirement_probe = state
                        .remote_retirement_probe_gate
                        .is_some_and(|gate| gate.probe_is_due(epoch, now));
                    let no_admission_marker = state.no_admission_marker;
                    let current =
                        std::mem::replace(&mut state.phase, ConsensusColdConnectionPhase::Idle);
                    match current {
                        ConsensusColdConnectionPhase::Idle => {
                            let attempt_id = uuid::Uuid::new_v4();
                            let receipt = Arc::new(ConsensusColdAttemptReceipt::default());
                            let Some(attempt_deadline) = tokio::time::Instant::now().checked_add(
                                DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout(),
                            ) else {
                                return Err(SessionConsensusPeerError::Protocol);
                            };
                            state.phase = ConsensusColdConnectionPhase::Connecting {
                                attempt_id,
                                epoch,
                                attempt_deadline,
                                receipt: Arc::clone(&receipt),
                                remote_retirement_probe,
                            };
                            ConsensusColdConnectionAction::Spawn {
                                attempt_id,
                                epoch,
                                attempt_deadline,
                                no_admission_marker,
                                receipt,
                            }
                        }
                        ConsensusColdConnectionPhase::Connecting {
                            attempt_id,
                            epoch: current_epoch,
                            attempt_deadline,
                            receipt,
                            remote_retirement_probe,
                        } => {
                            state.phase = ConsensusColdConnectionPhase::Connecting {
                                attempt_id,
                                epoch: current_epoch,
                                attempt_deadline,
                                receipt: Arc::clone(&receipt),
                                remote_retirement_probe,
                            };
                            ConsensusColdConnectionAction::Wait {
                                attempt_id,
                                epoch: current_epoch,
                                no_admission_marker,
                                receipt,
                            }
                        }
                        ConsensusColdConnectionPhase::Ready {
                            attempt_id,
                            epoch: current_epoch,
                            connection,
                        } if current_epoch == epoch => {
                            let now = tokio::time::Instant::now();
                            if let Some(reason) = connection.lifecycle.retirement(now) {
                                let admission_attempt_id = connection.admission_attempt_id;
                                let peer_certificate_effective_expiry =
                                    connection.lifecycle.peer_certificate_effective_expiry();
                                drop(connection);
                                if is_credential_lifecycle_retirement(reason) {
                                    ConsensusColdConnectionCoordinator::seed_credential_retirement_probe_gate(
                                        &mut state,
                                        epoch,
                                        admission_attempt_id,
                                        peer_certificate_effective_expiry,
                                        reason,
                                    );
                                } else {
                                    self.connection_pool
                                        .reconnect_gate
                                        .publish_failure_cooldown(
                                            epoch.reauthentication_generation,
                                            epoch.material_epoch,
                                            Duration::ZERO,
                                        );
                                }
                                state.no_admission_marker = attempt_id;
                                ConsensusColdConnectionAction::NoAdmission(
                                    SessionConsensusPeerError::Unavailable,
                                )
                            } else if consensus_connection_idle_expired(&connection, now) {
                                connection
                                    .lifecycle
                                    .record_forced_retirement(RetirementReason::IdleTimeout);
                                drop(connection);
                                self.connection_pool
                                    .reconnect_gate
                                    .publish_failure_cooldown(
                                        epoch.reauthentication_generation,
                                        epoch.material_epoch,
                                        Duration::ZERO,
                                    );
                                state.no_admission_marker = attempt_id;
                                ConsensusColdConnectionAction::NoAdmission(
                                    SessionConsensusPeerError::Unavailable,
                                )
                            } else {
                                ConsensusColdConnectionAction::Ready(connection)
                            }
                        }
                        ConsensusColdConnectionPhase::Ready {
                            epoch: staged_epoch,
                            connection,
                            ..
                        } => {
                            let reason = if staged_epoch.reauthentication_generation
                                != epoch.reauthentication_generation
                            {
                                RetirementReason::Explicit
                            } else {
                                RetirementReason::MaterialEpoch
                            };
                            connection.lifecycle.record_forced_retirement(reason);
                            drop(connection);
                            ConsensusColdConnectionAction::Retry
                        }
                        ConsensusColdConnectionPhase::Failed {
                            attempt_id,
                            epoch: current_epoch,
                            error,
                            ..
                        } if current_epoch == epoch => {
                            if joined_attempt_id == Some(attempt_id) {
                                state.phase = ConsensusColdConnectionPhase::Failed {
                                    attempt_id,
                                    epoch: current_epoch,
                                    error,
                                };
                                ConsensusColdConnectionAction::Failed(error)
                            } else {
                                // This distinct later caller owns the only
                                // next setup. When the fixed remote-
                                // retirement window has expired it is the
                                // sole probe owner under the same lock.
                                let receipt = Arc::new(ConsensusColdAttemptReceipt::default());
                                let Some(attempt_deadline) = now.checked_add(
                                    DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout(),
                                ) else {
                                    return Err(SessionConsensusPeerError::Protocol);
                                };
                                let attempt_id = uuid::Uuid::new_v4();
                                state.phase = ConsensusColdConnectionPhase::Connecting {
                                    attempt_id,
                                    epoch,
                                    attempt_deadline,
                                    receipt: Arc::clone(&receipt),
                                    remote_retirement_probe,
                                };
                                ConsensusColdConnectionAction::Spawn {
                                    attempt_id,
                                    epoch,
                                    attempt_deadline,
                                    no_admission_marker,
                                    receipt,
                                }
                            }
                        }
                        ConsensusColdConnectionPhase::Failed { .. } => {
                            ConsensusColdConnectionAction::Retry
                        }
                    }
                }
            };

            let mut probe_wait = None;
            match action {
                ConsensusColdConnectionAction::Ready(connection) => {
                    coordinator.changed.notify_waiters();
                    return Ok(*connection);
                }
                ConsensusColdConnectionAction::Failed(error) => {
                    // The receipt belongs to the pre-Call attempt this
                    // logical caller joined. It is terminal for this caller,
                    // including transient setup errors, so it cannot consume
                    // the receipt and spawn a second physical setup.
                    return Err(error);
                }
                ConsensusColdConnectionAction::NoAdmission(error) => {
                    return Err(error);
                }
                ConsensusColdConnectionAction::Retry => continue,
                ConsensusColdConnectionAction::WaitForRemoteRetirementProbe { probe_at } => {
                    probe_wait = Some(probe_at);
                }
                ConsensusColdConnectionAction::Spawn {
                    attempt_id,
                    epoch,
                    attempt_deadline,
                    no_admission_marker,
                    receipt,
                } => {
                    joined_no_admission_marker = Some(no_admission_marker);
                    joined_attempt_id = Some(attempt_id);
                    joined_attempt_epoch = Some(epoch);
                    joined_receipt = Some(receipt);
                    cold_connect_deadline.get_or_insert_with(|| {
                        contained_cold_connect_deadline(tokio::time::Instant::now(), call_deadline)
                    });
                    let attempt = run_detached_consensus_connection_attempt(
                        connector.clone(),
                        Arc::clone(coordinator),
                        Arc::clone(&self.connection_pool.reconnect_gate),
                        self.connection_pool.shutdown.subscribe(),
                        attempt_id,
                        epoch,
                        attempt_deadline,
                    );
                    #[cfg(test)]
                    {
                        let accounting = crate::lifecycle::CONNECTION_ATTEMPT_TEST_ACCOUNTING
                            .try_with(Arc::clone)
                            .ok();
                        tokio::spawn(async move {
                            if let Some(accounting) = accounting {
                                crate::lifecycle::CONNECTION_ATTEMPT_TEST_ACCOUNTING
                                    .scope(accounting, attempt)
                                    .await;
                            } else {
                                attempt.await;
                            }
                        });
                    }
                    #[cfg(not(test))]
                    tokio::spawn(attempt);
                }
                ConsensusColdConnectionAction::Wait {
                    attempt_id,
                    epoch,
                    no_admission_marker,
                    receipt,
                } => {
                    joined_no_admission_marker = Some(no_admission_marker);
                    joined_attempt_id = Some(attempt_id);
                    joined_attempt_epoch = Some(epoch);
                    joined_receipt = Some(receipt);
                    cold_connect_deadline.get_or_insert_with(|| {
                        contained_cold_connect_deadline(tokio::time::Instant::now(), call_deadline)
                    });
                }
            }

            let (wait_deadline, probe_boundary_wins) = match probe_wait {
                Some(probe_at) => (probe_at.min(call_deadline), probe_at <= call_deadline),
                None => (
                    cold_connect_deadline.expect("cold setup actions install a bounded deadline"),
                    false,
                ),
            };

            tokio::select! {
                biased;
                _ = &mut changed => {}
                changed = reauthentication_rx.changed() => {
                    if changed.is_err() {
                        return Err(SessionConsensusPeerError::Unavailable);
                    }
                }
                material_epoch = wait_consensus_material_epoch_change(
                    &mut material_rx,
                    epoch.material_epoch,
                ) => {
                    self.connection_pool.reconnect_gate.observe_epoch(
                        self.reauthentication.generation(),
                        material_epoch,
                    );
                }
                _ = tokio::time::sleep_until(wait_deadline) => {
                    if !probe_boundary_wins {
                        return Err(SessionConsensusPeerError::Timeout);
                    }
                }
            }
        }
    }

    async fn call_once(
        &self,
        connection_slot: &mut Option<ConsensusConnection>,
        request: SessionConsensusWireRequest,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        checked_wire_frame_size(self.max_frame_size)
            .map_err(|_| SessionConsensusPeerError::Protocol)?;
        if self.max_frame_size < MIN_SESSION_CONSENSUS_FRAME_SIZE {
            return Err(SessionConsensusPeerError::Protocol);
        }
        request.validate()?;
        if request.identity != self.binding.consensus_identity()
            || request.sender != self.binding.local_consensus_node_id()
        {
            return Err(SessionConsensusPeerError::ScopeMismatch);
        }

        // The selected connection lane is owned by this call until a complete response
        // has passed every correlation and payload validation check. If this
        // future is cancelled after any request bytes may have been written,
        // the taken socket is dropped rather than exposing a late response to
        // the next Openraft RPC.
        if let Some(mut connection) = connection_slot.take() {
            let now = tokio::time::Instant::now();
            if self.connection_is_current(&mut connection, now)
                && !self.connection_idle_reuse_expired(&connection, now)
            {
                // Sample no later than request dispatch, then commit only
                // after a complete correlated and payload-validated response.
                // A failed/cancelled write never refreshes this idle epoch.
                let dispatched_at = tokio::time::Instant::now();
                let result = self
                    .call_negotiated(&mut connection, request, deadline)
                    .await;
                if result.is_ok() {
                    connection.last_successful_correlated_use = Some(dispatched_at);
                }
                if result
                    .as_ref()
                    .is_ok_and(consensus_response_allows_connection_reuse)
                {
                    let now = tokio::time::Instant::now();
                    if self.connection_is_current(&mut connection, now) {
                        self.mark_connection_usable(&connection);
                        *connection_slot = Some(connection);
                    } else if let Some(reason) = connection.lifecycle.retirement(now) {
                        let epoch = self.connection_epoch(&connection);
                        self.seed_connection_credential_retirement_probe(
                            epoch,
                            connection.admission_attempt_id,
                            connection.lifecycle.peer_certificate_effective_expiry(),
                            reason,
                        )
                        .await;
                    }
                }
                return result;
            }
            if let Some(reason) = connection.lifecycle.retirement(now) {
                let epoch = self.connection_epoch(&connection);
                self.seed_connection_credential_retirement_probe(
                    epoch,
                    connection.admission_attempt_id,
                    connection.lifecycle.peer_certificate_effective_expiry(),
                    reason,
                )
                .await;
            }
            METRICS
                .session_net_reconnect_attempts
                .fetch_add(1, Ordering::Relaxed);
        }

        let mut connection = self.claim_or_start_cold_connection(deadline).await?;
        let now = tokio::time::Instant::now();
        let current_generation = self.reauthentication.generation();
        let current_material_epoch = self
            .tls_config
            .as_ref()
            .map(|config| config.material_status().epoch());
        connection.lifecycle.observe_rotation(
            now,
            current_generation,
            current_material_epoch,
            &directed_connection_key(
                b"consensus",
                self.binding.local_replica_id().as_str(),
                self.binding.remote_replica_id().as_str(),
            ),
        );
        let mismatch = connection
            .lifecycle
            .evidence_mismatch_reason(current_generation, current_material_epoch);
        let retirement = connection.lifecycle.retirement(now);
        if mismatch.is_some() || retirement.is_some() {
            if let Some(reason) = mismatch {
                connection.lifecycle.record_forced_retirement(reason);
            } else if let Some(reason) = retirement {
                if is_credential_lifecycle_retirement(reason) {
                    let epoch = self.connection_epoch(&connection);
                    self.seed_connection_credential_retirement_probe(
                        epoch,
                        connection.admission_attempt_id,
                        connection.lifecycle.peer_certificate_effective_expiry(),
                        reason,
                    )
                    .await;
                } else {
                    self.connection_pool
                        .reconnect_gate
                        .publish_failure_cooldown(
                            current_generation,
                            current_material_epoch,
                            Duration::ZERO,
                        );
                }
            } else {
                self.connection_pool
                    .reconnect_gate
                    .publish_failure_cooldown(
                        current_generation,
                        current_material_epoch,
                        Duration::ZERO,
                    );
            }
            METRICS
                .session_net_reconnect_attempts
                .fetch_add(1, Ordering::Relaxed);
            return Err(SessionConsensusPeerError::Unavailable);
        }
        let dispatched_at = tokio::time::Instant::now();
        let result = self
            .call_negotiated(&mut connection, request, deadline)
            .await;
        if result.is_ok() {
            connection.last_successful_correlated_use = Some(dispatched_at);
        }
        if result
            .as_ref()
            .is_ok_and(consensus_response_allows_connection_reuse)
        {
            let now = tokio::time::Instant::now();
            if self.connection_is_current(&mut connection, now) {
                self.mark_connection_usable(&connection);
                *connection_slot = Some(connection);
            } else if let Some(reason) = connection.lifecycle.retirement(now) {
                let epoch = self.connection_epoch(&connection);
                self.seed_connection_credential_retirement_probe(
                    epoch,
                    connection.admission_attempt_id,
                    connection.lifecycle.peer_certificate_effective_expiry(),
                    reason,
                )
                .await;
            }
        }
        result
    }

    async fn call_with_timeout_inner(
        &self,
        request: SessionConsensusWireRequest,
        call_timeout: Duration,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(call_timeout)
            .ok_or(SessionConsensusPeerError::Protocol)?;
        // Waiting for one of the two fixed per-peer lanes must consume the
        // caller's logical budget, but it does not start a transport attempt.
        // Once a lane is owned, `call_once` bounds this caller's wait and its
        // negotiated RPC. A pre-request cold task has a separate absolute
        // deadline fixed when the coordinator admits it; no outer timeout may
        // cancel that supervised guard and misreport it as abandoned.
        let mut slot = tokio::time::timeout_at(deadline, self.connection_pool.acquire())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        let result = self.call_once(slot.connection(), request, deadline).await;
        if slot.connection.is_some() {
            self.connection_pool.ensure_cached_connection_reaper(
                slot.lane,
                self.tls_config.clone(),
                self.reauthentication.clone(),
                directed_connection_key(
                    b"consensus",
                    self.binding.local_replica_id().as_str(),
                    self.binding.remote_replica_id().as_str(),
                ),
                self.cold_connector().epoch(),
            );
        }
        self.connection_pool.lane(slot.lane).changed.notify_one();
        result
    }

    fn connection_is_current(
        &self,
        connection: &mut ConsensusConnection,
        now: tokio::time::Instant,
    ) -> bool {
        let current_generation = self.reauthentication.generation();
        let current_material_epoch = self
            .tls_config
            .as_ref()
            .map(|config| config.material_status().epoch());
        connection.lifecycle.observe_rotation(
            now,
            current_generation,
            current_material_epoch,
            &directed_connection_key(
                b"consensus",
                self.binding.local_replica_id().as_str(),
                self.binding.remote_replica_id().as_str(),
            ),
        );
        // This path checks an already authenticated cached lane. Rotation is
        // intentionally cooperative and remains usable until its stable
        // per-peer jitter deadline. Fresh handshakes take the strict mismatch
        // path in `call_once` and are never admitted with stale evidence.
        connection.lifecycle.retirement(now).is_none()
    }

    fn connection_epoch(&self, connection: &ConsensusConnection) -> ConsensusColdConnectionEpoch {
        ConsensusColdConnectionEpoch {
            consensus_identity: self.binding.consensus_identity(),
            remote_node_id: self.binding.remote_consensus_node_id(),
            reauthentication_generation: connection.lifecycle.admitted_generation(),
            material_epoch: connection.lifecycle.admitted_material_epoch(),
        }
    }

    async fn seed_connection_credential_retirement_probe(
        &self,
        epoch: ConsensusColdConnectionEpoch,
        admission_attempt_id: Option<uuid::Uuid>,
        peer_certificate_effective_expiry: Option<opc_types::Timestamp>,
        reason: RetirementReason,
    ) {
        self.connection_pool
            .cold_connection
            .seed_credential_retirement_probe(
                epoch,
                admission_attempt_id,
                peer_certificate_effective_expiry,
                reason,
            )
            .await;
    }

    fn connection_idle_reuse_expired(
        &self,
        connection: &ConsensusConnection,
        now: tokio::time::Instant,
    ) -> bool {
        if !consensus_connection_idle_expired(connection, now) {
            return false;
        }
        connection
            .lifecycle
            .record_forced_retirement(RetirementReason::IdleTimeout);
        true
    }

    fn mark_connection_usable(&self, connection: &ConsensusConnection) {
        let current_generation = self.reauthentication.generation();
        let current_material_epoch = self
            .tls_config
            .as_ref()
            .map(|config| config.material_status().epoch());
        if connection
            .lifecycle
            .evidence_mismatch_reason(current_generation, current_material_epoch)
            .is_none()
        {
            self.connection_pool
                .reconnect_gate
                .mark_usable(current_generation, current_material_epoch);
        }
    }

    async fn call_negotiated(
        &self,
        connection: &mut ConsensusConnection,
        request: SessionConsensusWireRequest,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let call_id = uuid::Uuid::new_v4();
        let request = SessionConsensusTransportRequest::from_wire_call(call_id, request)?;
        let call = async {
            write_frame_bounded_until(
                &mut connection.writer,
                &request,
                connection.request_frame_size,
                deadline,
            )
            .await
            .map_err(|error| map_protocol_error(&error))?;
            let response: SessionConsensusTransportResponse =
                read_frame(&mut connection.reader, connection.response_frame_size)
                    .await
                    .map_err(|error| map_protocol_error(&error))?;
            let SessionConsensusTransportResponse::Call {
                call_id: response_call_id,
                response,
            } = response;
            if response_call_id != call_id {
                return Err(SessionConsensusPeerError::Protocol);
            }
            response.validate()?;
            Ok(response)
        };
        tokio::pin!(call);
        let mut lifecycle = connection.lifecycle.clone();
        let mut reauthentication_rx = self.reauthentication.subscribe();
        let mut material_rx = self
            .tls_config
            .as_ref()
            .map(opc_tls::AuthenticatedClientConfig::subscribe_material_changes);
        let response = loop {
            let now = tokio::time::Instant::now();
            lifecycle.observe_rotation(
                now,
                self.reauthentication.generation(),
                self.tls_config
                    .as_ref()
                    .map(|config| config.material_status().epoch()),
                &directed_connection_key(
                    b"consensus",
                    self.binding.local_replica_id().as_str(),
                    self.binding.remote_replica_id().as_str(),
                ),
            );
            let lifecycle_hard_deadline = lifecycle
                .hard_deadline()
                .map_err(|_| SessionConsensusPeerError::Protocol)?;
            let hard_deadline = lifecycle_hard_deadline.min(deadline);
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(hard_deadline) => {
                    let now = tokio::time::Instant::now();
                    if now >= lifecycle_hard_deadline {
                        let _ = lifecycle.retirement(now);
                        lifecycle.record_hard_overrun();
                    }
                    break Err(SessionConsensusPeerError::Timeout);
                }
                response = &mut call => break response,
                _ = reauthentication_rx.changed() => {}
                _ = wait_consensus_material_change(&mut material_rx) => {}
            }
        };
        connection.lifecycle = lifecycle;
        response
    }
}

fn consensus_response_allows_connection_reuse(response: &SessionConsensusWireResponse) -> bool {
    matches!(
        &response.result,
        Ok(_) | Err(SessionConsensusPeerError::Unavailable)
    )
}

#[async_trait]
impl SessionConsensusPeer for RemoteSessionConsensusPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.binding.remote_consensus_node_id()
    }

    fn scope_identity(&self) -> Option<ConsensusIdentity> {
        Some(self.binding.consensus_identity())
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let call_timeout = self.deadline_policy.for_family(request.family);
        self.call_with_timeout_inner(request, call_timeout).await
    }

    async fn call_with_timeout(
        &self,
        request: SessionConsensusWireRequest,
        timeout: Duration,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let call_timeout = timeout.min(self.deadline_policy.for_family(request.family));
        self.call_with_timeout_inner(request, call_timeout).await
    }
}

/// Dedicated consensus-only listener.
pub struct SessionConsensusServer {
    handler: Arc<dyn SessionConsensusRpcHandler>,
    tls_config: Option<opc_tls::AuthenticatedServerConfig>,
    membership: SessionMembershipAdmission,
    max_connections: usize,
    max_frame_size: usize,
    idle_timeout: Duration,
    rpc_timeout: Duration,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
    #[cfg(test)]
    post_accept_setup_hook: Option<Arc<ConsensusAcceptedSetupHook>>,
}

impl fmt::Debug for SessionConsensusServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionConsensusServer")
            .field("authenticated", &self.tls_config.is_some())
            .field("max_connections", &self.max_connections)
            .field("max_frame_size", &self.max_frame_size)
            .field("idle_timeout", &self.idle_timeout)
            .field("rpc_timeout", &self.rpc_timeout)
            .finish_non_exhaustive()
    }
}

impl SessionConsensusServer {
    /// Current redaction-safe health of the credentials this listener presents,
    /// or `None` when running without TLS.
    ///
    /// The server twin of
    /// [`RemoteSessionConsensusPeer::credential_health`]. A rotating fleet
    /// should gate readiness on both: a node whose inbound material is
    /// `RetainingLastGood` is still serving the previous certificate, which
    /// matters when the rotation's purpose was to stop presenting it.
    #[must_use]
    pub fn credential_health(&self) -> Option<opc_tls::TlsMaterialStatus> {
        self.tls_config
            .as_ref()
            .map(opc_tls::AuthenticatedServerConfig::material_status)
    }

    /// Construct a mutually authenticated consensus-only listener.
    pub fn new(
        handler: Arc<dyn SessionConsensusRpcHandler>,
        tls_config: opc_tls::AuthenticatedServerConfig,
        binding: LocalReplicaBinding,
    ) -> Self {
        Self::from_transport(
            handler,
            Some(tls_config),
            SessionMembershipAdmission::from_current_binding(binding),
        )
    }

    /// Construct a mutually authenticated listener with bounded current and
    /// staged-successor membership admission.
    pub fn new_with_membership_admission(
        handler: Arc<dyn SessionConsensusRpcHandler>,
        tls_config: opc_tls::AuthenticatedServerConfig,
        membership: SessionMembershipAdmission,
    ) -> Self {
        Self::from_transport(handler, Some(tls_config), membership)
    }

    /// Construct a plaintext consensus-only listener for transport tests.
    #[cfg(feature = "insecure-test")]
    pub fn new_insecure(
        handler: Arc<dyn SessionConsensusRpcHandler>,
        binding: LocalReplicaBinding,
    ) -> Self {
        Self::from_transport(
            handler,
            None,
            SessionMembershipAdmission::from_current_binding(binding),
        )
    }

    /// Construct a plaintext dynamic-membership listener for transport tests.
    #[cfg(feature = "insecure-test")]
    pub fn new_insecure_with_membership_admission(
        handler: Arc<dyn SessionConsensusRpcHandler>,
        membership: SessionMembershipAdmission,
    ) -> Self {
        Self::from_transport(handler, None, membership)
    }

    fn from_transport(
        handler: Arc<dyn SessionConsensusRpcHandler>,
        tls_config: Option<opc_tls::AuthenticatedServerConfig>,
        membership: SessionMembershipAdmission,
    ) -> Self {
        Self {
            handler,
            tls_config,
            membership,
            max_connections: 128,
            max_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            idle_timeout: DEFAULT_CONSENSUS_IDLE_TIMEOUT,
            rpc_timeout: DEFAULT_CONSENSUS_RPC_TIMEOUT,
            lifecycle_policy: ConnectionLifecyclePolicy::default(),
            reauthentication: SessionReauthenticationControl::new(),
            #[cfg(test)]
            post_accept_setup_hook: None,
        }
    }

    /// Set the per-frame and handshake idle timeout.
    #[must_use]
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the maximum duration of one inbound handler call.
    #[must_use]
    pub fn with_rpc_timeout(mut self, timeout: Duration) -> Self {
        self.rpc_timeout = timeout;
        self
    }

    /// Set the maximum number of concurrently accepted connections and handler
    /// executions retained after a transport timeout.
    #[must_use]
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Set the encoded request/response frame budget.
    #[must_use]
    pub fn with_max_frame_size(mut self, max_frame_size: usize) -> Self {
        self.max_frame_size = max_frame_size;
        self
    }

    /// Set the finite authentication and drain policy for accepted peers.
    #[must_use]
    pub fn with_connection_lifecycle(mut self, policy: ConnectionLifecyclePolicy) -> Self {
        self.lifecycle_policy = policy;
        self
    }

    /// Share the graceful reauthentication trigger used by this listener.
    #[must_use]
    pub fn with_reauthentication_control(
        mut self,
        control: SessionReauthenticationControl,
    ) -> Self {
        self.reauthentication = control;
        self
    }

    /// Control used by this listener for explicit graceful reauthentication.
    pub fn reauthentication_control(&self) -> SessionReauthenticationControl {
        self.reauthentication.clone()
    }

    /// Bind the dedicated listener and start accepting consensus connections.
    pub async fn listen(
        self,
        bind_addr: SocketAddr,
    ) -> io::Result<(SessionConsensusServerHandle, SocketAddr)> {
        self.validate_listener_configuration()?;
        let listener = TcpListener::bind(bind_addr).await?;
        self.serve_listener(listener).await
    }

    /// Start accepting consensus connections from an already-bound listener.
    ///
    /// This preserves listener ownership across multi-process discovery and
    /// configuration, avoiding a release-and-rebind race in orchestrators.
    pub async fn listen_on(
        self,
        listener: TcpListener,
    ) -> io::Result<(SessionConsensusServerHandle, SocketAddr)> {
        self.validate_listener_configuration()?;
        self.serve_listener(listener).await
    }

    fn validate_listener_configuration(&self) -> io::Result<()> {
        if self.max_connections == 0 || self.max_connections > Semaphore::MAX_PERMITS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "consensus connection limit is outside the supported range",
            ));
        }
        if !(MIN_SESSION_CONSENSUS_FRAME_SIZE..=MAX_NEGOTIATED_FRAME_SIZE)
            .contains(&self.max_frame_size)
            || checked_wire_frame_size(self.max_frame_size).is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "consensus frame size is outside the supported range",
            ));
        }
        let now = tokio::time::Instant::now();
        if now.checked_add(self.idle_timeout).is_none()
            || now.checked_add(self.rpc_timeout).is_none()
            || self.lifecycle_policy.validate_at(now).is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "consensus timeout is not representable",
            ));
        }
        Ok(())
    }

    async fn serve_listener(
        self,
        listener: TcpListener,
    ) -> io::Result<(SessionConsensusServerHandle, SocketAddr)> {
        let bound_addr = listener.local_addr()?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let connection_tasks = Arc::new(std::sync::Mutex::new(ConnectionTaskRegistry {
            stopping: false,
            handles: Vec::new(),
        }));
        let sem = Arc::new(Semaphore::new(self.max_connections));
        let handler_executions = Arc::new(Semaphore::new(self.max_connections));
        #[cfg(feature = "test-control")]
        let drain_handler_executions = Arc::clone(&handler_executions);
        #[cfg(feature = "test-control")]
        let handler_execution_limit = self.max_connections;
        let handler = self.handler;
        let tls_config = self.tls_config;
        let membership = self.membership;
        let max_frame_size = self.max_frame_size;
        let idle_timeout = self.idle_timeout;
        let rpc_timeout = self.rpc_timeout;
        let lifecycle_policy = self.lifecycle_policy;
        let reauthentication = self.reauthentication;
        #[cfg(test)]
        let post_accept_setup_hook = self.post_accept_setup_hook;
        let accept_cancellation = cancellation.clone();
        let task_registry = connection_tasks.clone();

        let accept_handle = tokio::spawn(async move {
            loop {
                let permit = match sem.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };
                let accepted = listener.accept().await;
                let Ok((stream, _peer_addr)) = accepted else {
                    continue;
                };
                // One accepted socket gets one non-renewable setup interval.
                // Capture it before registry contention or child scheduling so
                // TLS, Hello, authority admission, and Accepted cannot each
                // replenish the listener's setup budget.
                let Some(setup_deadline) = tokio::time::Instant::now().checked_add(idle_timeout)
                else {
                    // A later unrepresentable instant must fail closed.
                    continue;
                };
                let mut registry = task_registry
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                registry.handles.retain(|handle| !handle.is_finished());
                if registry.stopping {
                    break;
                }
                let handler = handler.clone();
                let tls_config = tls_config.clone();
                let membership = membership.clone();
                let handler_executions = Arc::clone(&handler_executions);
                let cancellation = accept_cancellation.clone();
                let shutdown_rx = shutdown_rx.clone();
                let reauthentication = reauthentication.clone();
                #[cfg(test)]
                let post_accept_setup_hook = post_accept_setup_hook.clone();
                let handle = tokio::spawn(async move {
                    let _permit = permit;
                    #[cfg(test)]
                    if let Some(hook) = post_accept_setup_hook {
                        hook.entered.notify_one();
                        hook.release.notified().await;
                    }
                    let mut attempt_metrics = ConnectionAttemptMetricGuard::started();
                    let result = handle_consensus_connection(
                        stream,
                        tls_config,
                        membership,
                        handler,
                        handler_executions,
                        max_frame_size,
                        idle_timeout,
                        setup_deadline,
                        rpc_timeout,
                        cancellation,
                        shutdown_rx,
                        lifecycle_policy,
                        reauthentication,
                    )
                    .await;
                    record_consensus_server_connection_outcome(&result);
                    attempt_metrics.finish();
                });
                registry.handles.push(handle);
            }
        });

        Ok((
            SessionConsensusServerHandle {
                accept_handle,
                connection_tasks,
                cancellation,
                shutdown_tx,
                #[cfg(feature = "test-control")]
                handler_executions: drain_handler_executions,
                #[cfg(feature = "test-control")]
                handler_execution_limit,
            },
            bound_addr,
        ))
    }
}

#[cfg(test)]
struct ConsensusAcceptedSetupHook {
    entered: Notify,
    release: Notify,
}

#[cfg(test)]
impl ConsensusAcceptedSetupHook {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Notify::new(),
            release: Notify::new(),
        })
    }
}

#[derive(Debug)]
struct ConnectionTaskRegistry {
    stopping: bool,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

/// Lifecycle handle for a running [`SessionConsensusServer`].
#[derive(Debug)]
pub struct SessionConsensusServerHandle {
    accept_handle: tokio::task::JoinHandle<()>,
    connection_tasks: Arc<std::sync::Mutex<ConnectionTaskRegistry>>,
    cancellation: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    #[cfg(feature = "test-control")]
    handler_executions: Arc<Semaphore>,
    #[cfg(feature = "test-control")]
    handler_execution_limit: usize,
}

impl SessionConsensusServerHandle {
    /// Return whether the consensus listener accept task has terminated.
    ///
    /// This observes only the listener lifecycle. It does not claim quorum
    /// health or consensus progress; callers must probe those separately.
    pub fn is_finished(&self) -> bool {
        self.accept_handle.is_finished()
    }

    /// Schedule immediate cancellation of the listener and all connections.
    ///
    /// A handler that already queued cancellation-unsafe consensus work is not
    /// cancelled: it remains bounded by the server execution budget and keeps
    /// its membership lease until the underlying operation completes.
    pub fn abort(&self) {
        self.cancellation.store(true, Ordering::Release);
        self.shutdown_tx.send_replace(true);
        self.accept_handle.abort();
        let mut registry = self
            .connection_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.stopping = true;
        for handle in &registry.handles {
            handle.abort();
        }
    }

    /// Cancel and await the listener and every registered connection.
    ///
    /// This does not manufacture cancellation of already-queued consensus-core
    /// work. Such work may complete after this connection barrier while holding
    /// its bounded execution permit and membership lease.
    pub async fn abort_and_wait(mut self) {
        self.abort_and_join_connections().await;
    }

    async fn abort_and_join_connections(&mut self) {
        self.abort();
        let _ = (&mut self.accept_handle).await;
        let handles = {
            let mut registry = self
                .connection_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut registry.handles)
        };
        for handle in &handles {
            handle.abort();
        }
        for handle in handles {
            let _ = handle.await;
        }
    }

    /// Test-only hard transport/core barrier for deterministic election
    /// qualification. It first prevents any new authenticated request from
    /// reaching the handler, then waits for every cancellation-unsafe handler
    /// already admitted to reach its actual terminal result.
    #[cfg(feature = "test-control")]
    #[doc(hidden)]
    pub async fn abort_and_drain_handlers_for_test(mut self) {
        self.abort_and_join_connections().await;
        let mut permits = Vec::with_capacity(self.handler_execution_limit);
        for _ in 0..self.handler_execution_limit {
            permits.push(
                Arc::clone(&self.handler_executions)
                    .acquire_owned()
                    .await
                    .expect("consensus handler semaphore remains open"),
            );
        }
    }
}

enum ConnectionPeerIdentity {
    Authenticated(SpiffeId),
    InsecureTest,
}

struct PendingConsensusLifecycle {
    handshake: Option<opc_tls::TlsServerHandshake>,
    tls_config: Option<opc_tls::AuthenticatedServerConfig>,
    local_certificate_expiry: Option<CertificateExpiryEvidence>,
    peer_certificate_expiry: Option<CertificateExpiryEvidence>,
    established_at: tokio::time::Instant,
    generation: u64,
    #[cfg(test)]
    expire_at_final_ack_boundary: bool,
}

enum PendingConsensusAdmissionError {
    Retired(RetirementReason),
    Protocol(ProtocolError),
}

impl PendingConsensusLifecycle {
    fn insecure(generation: u64) -> Self {
        Self {
            handshake: None,
            tls_config: None,
            local_certificate_expiry: None,
            peer_certificate_expiry: None,
            established_at: tokio::time::Instant::now(),
            generation,
            #[cfg(test)]
            expire_at_final_ack_boundary: false,
        }
    }

    fn admit(
        self,
        policy: ConnectionLifecyclePolicy,
        current_generation: u64,
    ) -> Result<
        (
            ConnectionLifecycle,
            Option<opc_tls::AuthenticatedServerConfig>,
        ),
        PendingConsensusAdmissionError,
    > {
        if current_generation != self.generation {
            return Err(PendingConsensusAdmissionError::Retired(
                RetirementReason::Explicit,
            ));
        }
        let epoch = match self.handshake {
            Some(handshake) => {
                let admission = handshake.admit().map_err(|_| {
                    PendingConsensusAdmissionError::Retired(RetirementReason::MaterialEpoch)
                })?;
                Some(admission.epoch())
            }
            None => None,
        };
        let lifecycle = ConnectionLifecycle::new(
            policy,
            self.established_at,
            self.local_certificate_expiry,
            self.peer_certificate_expiry,
            self.generation,
            epoch,
        )
        .map_err(|_| PendingConsensusAdmissionError::Protocol(ProtocolError::InvalidWireValue))?;
        Ok((lifecycle, self.tls_config))
    }

    fn provisional_lifecycle(
        &self,
        policy: ConnectionLifecyclePolicy,
    ) -> Result<ConnectionLifecycle, ProtocolError> {
        ConnectionLifecycle::new(
            policy,
            self.established_at,
            self.local_certificate_expiry,
            self.peer_certificate_expiry,
            self.generation,
            self.handshake
                .as_ref()
                .map(opc_tls::TlsServerHandshake::epoch),
        )
        .map_err(|_| ProtocolError::InvalidWireValue)
    }
}

struct ConsensusLifecycleTask(tokio::task::JoinHandle<()>);

impl Drop for ConsensusLifecycleTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn spawn_consensus_lifecycle(
    mut lifecycle: ConnectionLifecycle,
    edge_key: [u8; 32],
    tls_config: Option<opc_tls::AuthenticatedServerConfig>,
    reauthentication: SessionReauthenticationControl,
    mut server_shutdown: tokio::sync::watch::Receiver<bool>,
    connection_cancellation: Arc<AtomicBool>,
) -> (
    ConsensusLifecycleTask,
    tokio::sync::watch::Receiver<bool>,
    tokio::sync::watch::Receiver<bool>,
) {
    let (retirement_tx, retirement_rx) = tokio::sync::watch::channel(false);
    let (hard_tx, hard_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        let mut reauthentication_rx = reauthentication.subscribe();
        let mut material_rx = tls_config
            .as_ref()
            .map(opc_tls::AuthenticatedServerConfig::subscribe_material_changes);
        loop {
            let now = tokio::time::Instant::now();
            lifecycle.observe_rotation(
                now,
                reauthentication.generation(),
                tls_config
                    .as_ref()
                    .map(|config| config.material_status().epoch()),
                &edge_key,
            );
            if lifecycle.retirement(now).is_some() {
                retirement_tx.send_replace(true);
                let hard_deadline = match lifecycle.hard_deadline() {
                    Ok(deadline) => deadline,
                    Err(_) => {
                        connection_cancellation.store(true, Ordering::Release);
                        return;
                    }
                };
                tokio::select! {
                    _ = server_shutdown.changed() => {}
                    _ = tokio::time::sleep_until(hard_deadline) => {
                        lifecycle.record_hard_overrun();
                    }
                }
                hard_tx.send_replace(true);
                connection_cancellation.store(true, Ordering::Release);
                return;
            }
            tokio::select! {
                biased;
                _ = server_shutdown.changed() => {
                    hard_tx.send_replace(true);
                    connection_cancellation.store(true, Ordering::Release);
                    return;
                }
                _ = reauthentication_rx.changed() => {}
                _ = wait_consensus_material_change(&mut material_rx) => {}
                _ = tokio::time::sleep_until(lifecycle.retire_at()) => {}
            }
        }
    });
    (ConsensusLifecycleTask(task), retirement_rx, hard_rx)
}

#[allow(clippy::too_many_arguments)]
async fn handle_consensus_connection(
    stream: TcpStream,
    tls_config: Option<opc_tls::AuthenticatedServerConfig>,
    membership: SessionMembershipAdmission,
    handler: Arc<dyn SessionConsensusRpcHandler>,
    handler_executions: Arc<Semaphore>,
    max_frame_size: usize,
    idle_timeout: Duration,
    setup_deadline: tokio::time::Instant,
    rpc_timeout: Duration,
    cancellation: Arc<AtomicBool>,
    server_shutdown: tokio::sync::watch::Receiver<bool>,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
) -> Result<(), ProtocolError> {
    if tokio::time::Instant::now() >= setup_deadline {
        return Err(consensus_setup_timeout_error());
    }
    configure_consensus_tcp_socket(&stream).map_err(ProtocolError::Io)?;
    if let Some(tls_config) = tls_config {
        let generation = reauthentication.generation();
        let handshake = tls_config
            .begin_handshake()
            .map_err(|_| ProtocolError::Authentication)?;
        let acceptor =
            tokio_rustls::TlsAcceptor::from(consensus_server_tls_config(handshake.rustls_config()));
        let tls_stream = tokio::time::timeout_at(setup_deadline, acceptor.accept(stream))
            .await
            .map_err(|_| consensus_setup_timeout_error())?
            .map_err(classify_tls_io_error)?;
        let established_at = tokio::time::Instant::now();
        if tls_stream.get_ref().1.alpn_protocol() != Some(SESSION_CONSENSUS_ALPN) {
            return Err(ProtocolError::UnexpectedResponse);
        }
        let peer = opc_tls::peer_tls_identity_from_server_connection(tls_stream.get_ref().1)
            .map_err(|_| ProtocolError::Authentication)?;
        let local_certificate_expiry = CertificateExpiryEvidence::capture(
            handshake.leaf_expires_at(),
            handshake.certificate_chain_expires_at(),
            established_at,
        );
        let peer_certificate_expiry = CertificateExpiryEvidence::capture(
            peer.leaf_expires_at(),
            peer.certificate_chain_expires_at(),
            established_at,
        );
        let (mut reader, mut writer) = tokio::io::split(tls_stream);
        dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::Authenticated(peer.spiffe_id().clone()),
            PendingConsensusLifecycle {
                handshake: Some(handshake),
                tls_config: Some(tls_config),
                local_certificate_expiry: Some(local_certificate_expiry),
                peer_certificate_expiry: Some(peer_certificate_expiry),
                established_at,
                generation,
                #[cfg(test)]
                expire_at_final_ack_boundary: false,
            },
            membership,
            handler,
            handler_executions,
            max_frame_size,
            idle_timeout,
            setup_deadline,
            rpc_timeout,
            &cancellation,
            server_shutdown,
            lifecycle_policy,
            reauthentication,
        )
        .await
    } else {
        let (mut reader, mut writer) = tokio::io::split(stream);
        dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            PendingConsensusLifecycle::insecure(reauthentication.generation()),
            membership,
            handler,
            handler_executions,
            max_frame_size,
            idle_timeout,
            setup_deadline,
            rpc_timeout,
            &cancellation,
            server_shutdown,
            lifecycle_policy,
            reauthentication,
        )
        .await
    }
}

fn consensus_setup_timeout_error() -> ProtocolError {
    ProtocolError::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        "consensus connection setup timed out",
    ))
}

async fn reject_consensus_bootstrap<W>(
    writer: &mut W,
    error: SessionConsensusPeerError,
    setup_deadline: tokio::time::Instant,
    cancellation: &AtomicBool,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    // `Rejected` is the bootstrap-only retirement sentinel. Keeping it out of
    // this ordinary error path proves that a real authentication, scope,
    // contract, or protocol rejection cannot be masked as a retryable local
    // rotation race.
    if error == SessionConsensusPeerError::Rejected {
        return Err(ProtocolError::InvalidWireValue);
    }
    write_frame_bounded_until_cancellable(
        writer,
        &SessionConsensusBootstrapResponse::Rejected(error),
        MAX_HANDSHAKE_FRAME_SIZE,
        setup_deadline,
        cancellation,
    )
    .await
}

async fn retire_consensus_bootstrap<W>(
    writer: &mut W,
    setup_deadline: tokio::time::Instant,
    cancellation: &AtomicBool,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    tracing::debug!(
        reason = "rotation_bootstrap_retired",
        "retiring authenticated consensus connection before request admission"
    );
    write_frame_bounded_until_cancellable(
        writer,
        &SessionConsensusBootstrapResponse::Rejected(SessionConsensusPeerError::Rejected),
        MAX_HANDSHAKE_FRAME_SIZE,
        setup_deadline,
        cancellation,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn write_consensus_call_response<W>(
    writer: &mut W,
    call_id: uuid::Uuid,
    response: SessionConsensusWireResponse,
    max_frame_size: usize,
    timeout: Duration,
    cancellation: &AtomicBool,
    hard_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or(ProtocolError::InvalidWireValue)?;
    let outbound = SessionConsensusTransportResponse::Call { call_id, response };
    tokio::select! {
        biased;
        _ = hard_rx.changed() => Ok(()),
        result = write_frame_bounded_until_cancellable(
            writer,
            &outbound,
            max_frame_size,
            deadline,
            cancellation,
        ) => result,
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_consensus<R, W>(
    reader: &mut R,
    writer: &mut W,
    peer_identity: ConnectionPeerIdentity,
    pending_lifecycle: PendingConsensusLifecycle,
    membership: SessionMembershipAdmission,
    handler: Arc<dyn SessionConsensusRpcHandler>,
    handler_executions: Arc<Semaphore>,
    max_frame_size: usize,
    idle_timeout: Duration,
    setup_deadline: tokio::time::Instant,
    rpc_timeout: Duration,
    global_cancellation: &AtomicBool,
    server_shutdown: tokio::sync::watch::Receiver<bool>,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
) -> Result<(), ProtocolError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    #[cfg(test)]
    let expire_at_final_ack_boundary = pending_lifecycle.expire_at_final_ack_boundary;
    let bootstrap_lifecycle = pending_lifecycle.provisional_lifecycle(lifecycle_policy)?;
    let bootstrap_cancellation =
        Arc::new(AtomicBool::new(global_cancellation.load(Ordering::Acquire)));
    let bootstrap_hard_deadline = bootstrap_lifecycle
        .hard_deadline()
        .map_err(|_| ProtocolError::InvalidWireValue)?;
    let mut bootstrap_task_shutdown = server_shutdown.clone();
    let task_cancellation = bootstrap_cancellation.clone();
    let bootstrap_hard_lifecycle = bootstrap_lifecycle.clone();
    let _bootstrap_hard_task = ConsensusLifecycleTask(tokio::spawn(async move {
        tokio::select! {
            _ = bootstrap_task_shutdown.changed() => {}
            _ = tokio::time::sleep_until(bootstrap_hard_deadline) => {
                let now = tokio::time::Instant::now();
                let _ = bootstrap_hard_lifecycle.retirement(now);
                bootstrap_hard_lifecycle.record_hard_overrun();
            }
        }
        task_cancellation.store(true, Ordering::Release);
    }));
    let server_cancellation = bootstrap_cancellation.as_ref();
    let mut bootstrap_shutdown = server_shutdown.clone();
    let mut bootstrap_reauthentication_rx = reauthentication.subscribe();
    let mut bootstrap_material_rx = pending_lifecycle
        .tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedServerConfig::subscribe_material_changes);
    let hello: SessionConsensusBootstrapRequest = {
        let hello_read =
            tokio::time::timeout_at(setup_deadline, read_frame(reader, MAX_HANDSHAKE_FRAME_SIZE));
        tokio::pin!(hello_read);
        loop {
            let now = tokio::time::Instant::now();
            let current_material_status = pending_lifecycle
                .tls_config
                .as_ref()
                .map(opc_tls::AuthenticatedServerConfig::material_status);
            let mismatch = bootstrap_lifecycle.evidence_mismatch_reason(
                reauthentication.generation(),
                current_material_status.map(|status| status.epoch()),
            );
            if let Some(reason) = mismatch {
                bootstrap_lifecycle.record_forced_retirement(reason);
                return retire_consensus_bootstrap(writer, setup_deadline, server_cancellation)
                    .await;
            }
            if !material_status_matches_admission(
                bootstrap_lifecycle.admitted_material_epoch(),
                current_material_status,
            ) {
                bootstrap_lifecycle.record_forced_retirement(RetirementReason::MaterialEpoch);
                return retire_consensus_bootstrap(writer, setup_deadline, server_cancellation)
                    .await;
            }
            if bootstrap_lifecycle.retirement(now).is_some() {
                return retire_consensus_bootstrap(writer, setup_deadline, server_cancellation)
                    .await;
            }
            tokio::select! {
                biased;
                _ = bootstrap_shutdown.changed() => {
                    return Err(ProtocolError::Io(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "consensus server stopped during bootstrap",
                    )));
                }
                changed = bootstrap_reauthentication_rx.changed() => {
                    if changed.is_err() {
                        return Err(ProtocolError::Authentication);
                    }
                }
                _ = wait_consensus_material_change(&mut bootstrap_material_rx) => {}
                _ = tokio::time::sleep_until(bootstrap_lifecycle.retire_at()) => {}
                result = &mut hello_read => {
                    let result = result.map_err(|_| consensus_setup_timeout_error())?;
                    if tokio::time::Instant::now() >= setup_deadline {
                        return Err(consensus_setup_timeout_error());
                    }
                    break result?;
                },
            }
        }
    };
    let SessionConsensusBootstrapRequest::Hello(hello) = hello;
    if hello.transport_revision != SESSION_CONSENSUS_TRANSPORT_REVISION
        || !hello.contract_profile.is_current()
    {
        reject_consensus_bootstrap(
            writer,
            SessionConsensusPeerError::Protocol,
            setup_deadline,
            server_cancellation,
        )
        .await?;
        return Err(ProtocolError::ContractMismatch);
    }
    let requested_response_frame_size =
        match negotiate_response_frame_size(hello.requested_response_frame_size, max_frame_size) {
            Ok(size) => size,
            Err(error) => {
                reject_consensus_bootstrap(
                    writer,
                    SessionConsensusPeerError::Protocol,
                    setup_deadline,
                    server_cancellation,
                )
                .await?;
                return Err(error);
            }
        };
    let effective_response_frame_size = checked_frame_size(requested_response_frame_size)?;
    if effective_response_frame_size < MIN_SESSION_CONSENSUS_FRAME_SIZE {
        reject_consensus_bootstrap(
            writer,
            SessionConsensusPeerError::Protocol,
            setup_deadline,
            server_cancellation,
        )
        .await?;
        return Err(ProtocolError::ContractMismatch);
    }
    let server_request_frame_size = checked_wire_frame_size(max_frame_size)?;

    let sender_replica_id = match ReplicaId::new(hello.sender_replica_id) {
        Ok(replica_id) => replica_id,
        Err(_) => {
            reject_consensus_bootstrap(
                writer,
                SessionConsensusPeerError::Protocol,
                setup_deadline,
                server_cancellation,
            )
            .await?;
            return Err(ProtocolError::InvalidWireValue);
        }
    };
    let expected_server_replica_id = match ReplicaId::new(hello.expected_server_replica_id) {
        Ok(replica_id) => replica_id,
        Err(_) => {
            reject_consensus_bootstrap(
                writer,
                SessionConsensusPeerError::Protocol,
                setup_deadline,
                server_cancellation,
            )
            .await?;
            return Err(ProtocolError::InvalidWireValue);
        }
    };
    let authenticated_spiffe = match &peer_identity {
        ConnectionPeerIdentity::Authenticated(actual) => Some(actual),
        ConnectionPeerIdentity::InsecureTest => None,
    };
    let membership_scope = match tokio::time::timeout_at(
        setup_deadline,
        membership.admit_engine_bootstrap(
            &sender_replica_id,
            &expected_server_replica_id,
            hello.identity,
            hello.sender_node_id,
            hello.expected_server_node_id,
            authenticated_spiffe,
        ),
    )
    .await
    {
        Ok(Ok(scope)) if tokio::time::Instant::now() < setup_deadline => scope,
        Err(_) | Ok(Ok(_)) => return Err(consensus_setup_timeout_error()),
        Ok(Err(error)) => {
            reject_consensus_bootstrap(writer, error, setup_deadline, server_cancellation).await?;
            return Err(ProtocolError::Authentication);
        }
    };
    let binding = membership_scope.binding().clone();

    let mut admission_reauthentication_rx = reauthentication.subscribe();
    let (mut lifecycle, lifecycle_tls_config) = match pending_lifecycle
        .admit(lifecycle_policy, reauthentication.generation())
    {
        Ok(admitted) => admitted,
        // Authentication and scope already succeeded. Prove the local
        // epoch/generation retirement before any Openraft request can be
        // dispatched, allowing exactly this cold-connect attempt to be
        // retried safely.
        Err(PendingConsensusAdmissionError::Retired(reason)) => {
            bootstrap_lifecycle.record_forced_retirement(reason);
            return retire_consensus_bootstrap(writer, setup_deadline, server_cancellation).await;
        }
        Err(PendingConsensusAdmissionError::Protocol(error)) => return Err(error),
    };
    drop(bootstrap_lifecycle);
    let mut admission_material_rx = lifecycle_tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedServerConfig::subscribe_material_changes);
    let edge_key = directed_connection_key(
        b"consensus",
        sender_replica_id.as_str(),
        binding.local_replica_id().as_str(),
    );
    let now = tokio::time::Instant::now();
    let admitted_material_epoch = lifecycle.admitted_material_epoch();
    let current_material_status = lifecycle_tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedServerConfig::material_status);
    lifecycle.observe_rotation(
        now,
        reauthentication.generation(),
        current_material_status.map(|status| status.epoch()),
        &edge_key,
    );
    if let Some(reason) = lifecycle.evidence_mismatch_reason(
        reauthentication.generation(),
        current_material_status.map(|status| status.epoch()),
    ) {
        lifecycle.record_forced_retirement(reason);
        return retire_consensus_bootstrap(writer, setup_deadline, server_cancellation).await;
    }
    if admission_reauthentication_rx.has_changed().unwrap_or(true) {
        lifecycle.record_forced_retirement(RetirementReason::Explicit);
        return retire_consensus_bootstrap(writer, setup_deadline, server_cancellation).await;
    }
    if !material_status_matches_admission(admitted_material_epoch, current_material_status) {
        lifecycle.record_forced_retirement(RetirementReason::MaterialEpoch);
        return retire_consensus_bootstrap(writer, setup_deadline, server_cancellation).await;
    }
    if lifecycle.retirement(now).is_some() {
        return retire_consensus_bootstrap(writer, setup_deadline, server_cancellation).await;
    }
    let bootstrap_membership_lease = match tokio::time::timeout_at(
        setup_deadline,
        membership.revalidate_bootstrap_scope(&membership_scope),
    )
    .await
    {
        Ok(Ok(lease)) if tokio::time::Instant::now() < setup_deadline => lease,
        Err(_) | Ok(Ok(_)) => return Err(consensus_setup_timeout_error()),
        Ok(Err(error)) => {
            reject_consensus_bootstrap(writer, error, setup_deadline, server_cancellation).await?;
            return Err(ProtocolError::Authentication);
        }
    };
    drop(_bootstrap_hard_task);
    let connection_cancellation = Arc::new(AtomicBool::new(false));
    let admitted_generation = lifecycle.admitted_generation();
    let mut admission_shutdown = server_shutdown.clone();
    let (_lifecycle_task, mut retirement_rx, mut hard_rx) = spawn_consensus_lifecycle(
        lifecycle.clone(),
        edge_key,
        lifecycle_tls_config.clone(),
        reauthentication.clone(),
        server_shutdown,
        connection_cancellation.clone(),
    );
    let accepted = SessionConsensusBootstrapResponse::Accepted(SessionConsensusBootstrapAck {
        transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
        contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
        identity: binding.consensus_identity(),
        server_node_id: binding.local_consensus_node_id(),
        accepted_sender_node_id: hello.sender_node_id,
        handshake_nonce: hello.handshake_nonce,
        accepted_response_frame_size: requested_response_frame_size,
        server_request_frame_size,
    });
    // This is the final zero-Accepted-byte boundary. Once the write future is
    // polled it may have emitted a partial Accepted frame, so a subsequent
    // retirement must conservatively close instead of appending the reserved
    // bootstrap retirement response.
    let pre_ack_material_status = lifecycle_tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedServerConfig::material_status);
    if let Some(reason) = lifecycle.evidence_mismatch_reason(
        reauthentication.generation(),
        pre_ack_material_status.map(|status| status.epoch()),
    ) {
        lifecycle.record_forced_retirement(reason);
        return retire_consensus_bootstrap(
            writer,
            setup_deadline,
            connection_cancellation.as_ref(),
        )
        .await;
    }
    if !material_status_matches_admission(admitted_material_epoch, pre_ack_material_status) {
        lifecycle.record_forced_retirement(RetirementReason::MaterialEpoch);
        return retire_consensus_bootstrap(
            writer,
            setup_deadline,
            connection_cancellation.as_ref(),
        )
        .await;
    }
    if *retirement_rx.borrow() || *hard_rx.borrow() {
        return retire_consensus_bootstrap(
            writer,
            setup_deadline,
            connection_cancellation.as_ref(),
        )
        .await;
    }
    #[cfg(test)]
    if expire_at_final_ack_boundary {
        // Deterministically model the soft deadline crossing after the earlier
        // sample while the spawned lifecycle task has not been scheduled.
        lifecycle.expire_at_final_ack_boundary_for_test();
    }
    if lifecycle.retirement(tokio::time::Instant::now()).is_some() {
        return retire_consensus_bootstrap(
            writer,
            setup_deadline,
            connection_cancellation.as_ref(),
        )
        .await;
    }
    {
        let acknowledgement = write_frame_bounded_until_cancellable(
            writer,
            &accepted,
            MAX_HANDSHAKE_FRAME_SIZE,
            setup_deadline,
            connection_cancellation.as_ref(),
        );
        tokio::pin!(acknowledgement);
        loop {
            tokio::select! {
                biased;
                _ = admission_shutdown.changed() => return Ok(()),
                changed = admission_reauthentication_rx.changed() => {
                    if changed.is_err() || reauthentication.generation() != admitted_generation {
                        lifecycle.record_forced_retirement(RetirementReason::Explicit);
                        return Ok(());
                    }
                }
                _ = wait_consensus_material_change(&mut admission_material_rx) => {
                    let status = lifecycle_tls_config
                        .as_ref()
                        .map(opc_tls::AuthenticatedServerConfig::material_status);
                    if !material_status_matches_admission(admitted_material_epoch, status) {
                        lifecycle.record_forced_retirement(RetirementReason::MaterialEpoch);
                        return Ok(());
                    }
                }
                _ = hard_rx.changed() => return Ok(()),
                _ = retirement_rx.changed() => return Ok(()),
                result = &mut acknowledgement => {
                    result?;
                    if tokio::time::Instant::now() >= setup_deadline {
                        return Err(consensus_setup_timeout_error());
                    }
                    break;
                }
            }
        }
    }
    drop(bootstrap_membership_lease);
    let connection_cancellation = connection_cancellation.as_ref();

    loop {
        if *retirement_rx.borrow() || *hard_rx.borrow() {
            return Ok(());
        }
        let inbound_result = tokio::select! {
            biased;
            _ = hard_rx.changed() => return Ok(()),
            _ = retirement_rx.changed() => return Ok(()),
            inbound = read_authenticated_frame_within(reader, max_frame_size, idle_timeout) => inbound,
        };
        let inbound: SessionConsensusTransportRequest = match inbound_result {
            Ok(Some(request)) => request,
            Ok(None) => {
                lifecycle.record_forced_retirement(RetirementReason::IdleTimeout);
                return Ok(());
            }
            Err(ProtocolError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let call_id = inbound.call_id();
        let response = match inbound.into_wire_call() {
            Err(_) => SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::Protocol),
            },
            Ok((_, request)) => {
                let handler_deadline = tokio::time::Instant::now()
                    .checked_add(rpc_timeout)
                    .ok_or(ProtocolError::InvalidWireValue)?;
                let execution_permit = tokio::select! {
                    biased;
                    _ = hard_rx.changed() => return Ok(()),
                    permit = tokio::time::timeout_at(
                        handler_deadline,
                        Arc::clone(&handler_executions).acquire_owned(),
                    ) => match permit {
                        Ok(Ok(permit)) => Some(permit),
                        Ok(Err(_)) | Err(_) => None,
                    },
                };
                let Some(execution_permit) = execution_permit else {
                    return write_consensus_call_response(
                        writer,
                        call_id,
                        SessionConsensusWireResponse {
                            result: Err(SessionConsensusPeerError::Timeout),
                        },
                        effective_response_frame_size,
                        idle_timeout,
                        connection_cancellation,
                        &mut hard_rx,
                    )
                    .await;
                };
                let scope_admission = tokio::time::timeout_at(
                    handler_deadline,
                    membership.revalidate_engine_scope(
                        &membership_scope,
                        request.identity,
                        request.sender,
                        request.family,
                    ),
                )
                .await;
                match scope_admission {
                    Ok(Err(error)) => SessionConsensusWireResponse { result: Err(error) },
                    Err(_) => SessionConsensusWireResponse {
                        result: Err(SessionConsensusPeerError::Timeout),
                    },
                    Ok(Ok(membership_lease)) => {
                        let handler = Arc::clone(&handler);
                        let authenticated_sender = hello.sender_node_id;
                        let mut handler_task = tokio::spawn(async move {
                            let _membership_lease = membership_lease;
                            let _execution_permit = execution_permit;
                            handler.handle(authenticated_sender, request).await
                        });
                        let handled = tokio::select! {
                            biased;
                            _ = hard_rx.changed() => None,
                            handled = tokio::time::timeout_at(handler_deadline, &mut handler_task) => {
                                Some(handled)
                            },
                        };
                        match handled {
                            None => {
                                drop(handler_task);
                                return Ok(());
                            }
                            Some(Ok(Ok(response))) if response.validate().is_ok() => response,
                            Some(Ok(Ok(_))) | Some(Ok(Err(_))) => SessionConsensusWireResponse {
                                result: Err(SessionConsensusPeerError::Protocol),
                            },
                            Some(Err(_)) => {
                                // Dropping a JoinHandle detaches rather than cancels the task.
                                // The bounded execution permit and owned membership lease remain
                                // held until the handler (and any queued RaftCore call it awaits)
                                // reaches an actual terminal result.
                                drop(handler_task);
                                SessionConsensusWireResponse {
                                    result: Err(SessionConsensusPeerError::Timeout),
                                }
                            }
                        }
                    }
                }
            }
        };
        let deadline = tokio::time::Instant::now()
            .checked_add(idle_timeout)
            .ok_or(ProtocolError::InvalidWireValue)?;
        let outbound = SessionConsensusTransportResponse::Call { call_id, response };
        tokio::select! {
            biased;
            _ = hard_rx.changed() => return Ok(()),
            result = write_frame_bounded_until_cancellable(
                writer,
                &outbound,
                effective_response_frame_size,
                deadline,
                connection_cancellation,
            ) => result?,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex as StdMutex;
    use std::{pin::Pin, task::Context, task::Poll};

    use opc_session_store::{
        QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
        ReplicaTlsIdentity, SessionConsensusRpcFamily, SessionOp,
    };
    // Used only by the plaintext-transport tests below.
    #[cfg(feature = "insecure-test")]
    use opc_session_store::{
        SessionConsensusClusterId, SessionTopologyTransitionId, SessionTopologyTransitionRequest,
    };
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::sync::Notify;

    use super::*;
    use crate::identity::{
        SessionClusterId, SessionConfigurationEpoch, SessionConfigurationGeneration,
        SessionPlacementPolicy, SessionReplicationManifest,
    };
    use crate::protocol::{write_frame, Request, SessionConsensusContractProfile};

    /// The published 728bc5/PR #732 profile must stay explicit here: the
    /// application revision alone was insufficient to distinguish its
    /// Postcard tag-27 `FinalizeOperatorRecoveryV2` from the merged roster
    /// profile, so a future revision bump must not turn this regression into a
    /// merely adjacent-profile check.
    fn former_728bc5_application_revision_3_profile() -> SessionConsensusContractProfile {
        SessionConsensusContractProfile {
            wire_schema_revision: 5,
            application_revision: 3,
            error_set_revision: 6,
            max_rpc_payload_bytes: 2_097_152,
            max_roster_rpc_payload_bytes: 2_253_338,
            min_frame_size: 9_437_184,
            max_frame_size: 16_777_216,
        }
    }

    async fn set_remote_retirement_probe_boundary(
        peer: &RemoteSessionConsensusPeer,
        probe_at: tokio::time::Instant,
    ) {
        let mut state = peer.connection_pool.cold_connection.state.lock().await;
        let gate = state
            .remote_retirement_probe_gate
            .as_mut()
            .expect("authenticated retirement must arm the shared probe gate");
        gate.next_probe_at = Some(probe_at);
        drop(state);
        peer.connection_pool
            .cold_connection
            .changed
            .notify_waiters();
    }

    async fn make_remote_retirement_probe_due(peer: &RemoteSessionConsensusPeer) {
        set_remote_retirement_probe_boundary(peer, tokio::time::Instant::now()).await;
    }

    fn test_cold_epoch() -> ConsensusColdConnectionEpoch {
        let (_server_binding, client_binding) = bindings();
        ConsensusColdConnectionEpoch {
            consensus_identity: client_binding.consensus_identity(),
            remote_node_id: client_binding.remote_consensus_node_id(),
            reauthentication_generation: 0,
            material_epoch: None,
        }
    }

    #[test]
    fn consensus_bootstrap_protocol_error_mapper_preserves_tls_alert_categories() {
        use tokio_rustls::rustls::{AlertDescription, Error};

        let credential_alert = ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            Error::AlertReceived(AlertDescription::CertificateRequired),
        ));
        assert_eq!(
            bootstrap_protocol_error_to_peer_error(credential_alert),
            SessionConsensusPeerError::Authentication,
            "a rustls credential alert read during Hello/HelloAck is authentication"
        );

        let transport_reset = ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "test reset",
        ));
        assert_eq!(
            bootstrap_protocol_error_to_peer_error(transport_reset),
            SessionConsensusPeerError::Unavailable,
            "ordinary bootstrap transport closure remains unavailable"
        );

        let deadline = ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "test deadline",
        ));
        assert_eq!(
            bootstrap_protocol_error_to_peer_error(deadline),
            SessionConsensusPeerError::Timeout,
            "a real bootstrap deadline remains timeout"
        );

        let tls_protocol = ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            Error::AlertReceived(AlertDescription::NoApplicationProtocol),
        ));
        assert_eq!(
            bootstrap_protocol_error_to_peer_error(tls_protocol),
            SessionConsensusPeerError::Protocol,
            "non-credential rustls alerts remain protocol failures"
        );
    }

    #[derive(Debug)]
    struct CountingHandler(AtomicUsize);

    #[async_trait]
    impl SessionConsensusRpcHandler for CountingHandler {
        async fn handle(
            &self,
            _authenticated_sender: SessionConsensusNodeId,
            request: SessionConsensusWireRequest,
        ) -> SessionConsensusWireResponse {
            self.0.fetch_add(1, Ordering::Relaxed);
            SessionConsensusWireResponse {
                result: Ok(request.payload),
            }
        }
    }

    #[cfg(feature = "insecure-test")]
    #[derive(Debug)]
    struct CancellationUnsafeQueuedHandler {
        queued: Arc<Notify>,
        release_core: Arc<Notify>,
        core_completed: Arc<Notify>,
    }

    #[cfg(feature = "insecure-test")]
    impl CancellationUnsafeQueuedHandler {
        fn new() -> Self {
            Self {
                queued: Arc::new(Notify::new()),
                release_core: Arc::new(Notify::new()),
                core_completed: Arc::new(Notify::new()),
            }
        }
    }

    #[async_trait]
    #[cfg(feature = "insecure-test")]
    impl SessionConsensusRpcHandler for CancellationUnsafeQueuedHandler {
        async fn handle(
            &self,
            _authenticated_sender: SessionConsensusNodeId,
            request: SessionConsensusWireRequest,
        ) -> SessionConsensusWireResponse {
            let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
            let queued = Arc::clone(&self.queued);
            let release_core = Arc::clone(&self.release_core);
            let core_completed = Arc::clone(&self.core_completed);
            tokio::spawn(async move {
                let release = release_core.notified();
                queued.notify_one();
                release.await;
                core_completed.notify_one();
                let _ = completion_tx.send(SessionConsensusWireResponse {
                    result: Ok(request.payload),
                });
            });
            completion_rx.await.unwrap_or(SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::Unavailable),
            })
        }
    }

    struct PartialConsensusAcknowledgementWriter {
        bytes: Arc<StdMutex<Vec<u8>>>,
        first_chunk_written: bool,
        wrote_first_chunk: Arc<Notify>,
    }

    impl AsyncWrite for PartialConsensusAcknowledgementWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            if self.first_chunk_written {
                return Poll::Pending;
            }
            let written = buffer.len().min(2);
            self.bytes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(&buffer[..written]);
            self.first_chunk_written = true;
            self.wrote_first_chunk.notify_one();
            Poll::Ready(Ok(written))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Pending
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    fn descriptor(index: u16) -> QuorumReplicaDescriptor {
        QuorumReplicaDescriptor::new(
            ReplicaId::new(format!("replica-{index}")).expect("replica ID"),
            ReplicaEndpoint::new(format!("replica-{index}.invalid"), 7443).expect("endpoint"),
            ReplicaTlsIdentity::new(format!(
                "spiffe://test.invalid/tenant/test/ns/default/sa/session/nf/smf/instance/{index}"
            ))
            .expect("TLS identity"),
            ReplicaFailureDomain::new(format!("zone-{index}")).expect("failure domain"),
            ReplicaBackingIdentity::new(format!("disk-{index}")).expect("backing identity"),
        )
    }

    fn bindings() -> (LocalReplicaBinding, RemoteReplicaBinding) {
        let manifest = Arc::new(
            SessionReplicationManifest::try_new_with_epoch(
                SessionClusterId::new("consensus-raw-rejection").expect("cluster"),
                SessionConfigurationGeneration::new("legacy").expect("legacy generation"),
                SessionConfigurationEpoch::new(1).expect("epoch"),
                vec![descriptor(1), descriptor(2)],
            )
            .expect("manifest"),
        );
        let client = manifest
            .bind_local(ReplicaId::new("replica-1").expect("client ID"))
            .expect("client binding")
            .bind_remote(ReplicaId::new("replica-2").expect("server ID"))
            .expect("remote binding");
        let server = manifest
            .bind_local(ReplicaId::new("replica-2").expect("server ID"))
            .expect("server binding");
        (server, client)
    }

    #[tokio::test]
    async fn consensus_tcp_setup_enables_nodelay_for_outbound_and_accepted_sockets() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind consensus TCP setup listener");
        let address = listener
            .local_addr()
            .expect("read consensus TCP setup listener address");
        let (outbound, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let outbound = outbound.expect("connect consensus TCP setup client");
        let (accepted, _) = accepted.expect("accept consensus TCP setup client");

        outbound
            .set_nodelay(false)
            .expect("enable fixture Nagle delay on outbound socket");
        accepted
            .set_nodelay(false)
            .expect("enable fixture Nagle delay on accepted socket");
        configure_consensus_tcp_socket(&outbound).expect("configure outbound consensus TCP socket");
        configure_consensus_tcp_socket(&accepted).expect("configure accepted consensus TCP socket");

        assert!(
            outbound
                .nodelay()
                .expect("inspect outbound consensus TCP socket"),
            "outbound consensus setup must disable Nagle before TLS or Hello"
        );
        assert!(
            accepted
                .nodelay()
                .expect("inspect accepted consensus TCP socket"),
            "accepted consensus setup must disable Nagle before TLS or Hello"
        );
    }

    #[cfg(feature = "insecure-test")]
    #[tokio::test(start_paused = true)]
    async fn accepted_setup_deadline_expires_before_a_delayed_child_can_poll_hello() {
        let (server_binding, client_binding) = bindings();
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let hook = ConsensusAcceptedSetupHook::new();
        let setup_timeout = Duration::from_millis(20);
        let mut server = SessionConsensusServer::new_insecure(handler.clone(), server_binding)
            .with_idle_timeout(setup_timeout);
        server.post_accept_setup_hook = Some(Arc::clone(&hook));
        let (handle, address) = server
            .listen("127.0.0.1:0".parse().expect("consensus bind address"))
            .await
            .expect("start consensus listener");

        let mut client = TcpStream::connect(address)
            .await
            .expect("connect accepted consensus client");
        hook.entered.notified().await;
        write_frame(
            &mut client,
            &SessionConsensusBootstrapRequest::Hello(SessionConsensusBootstrapHello {
                transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
                contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
                sender_replica_id: client_binding.local_replica_id().as_str().to_owned(),
                expected_server_replica_id: client_binding.remote_replica_id().as_str().to_owned(),
                identity: client_binding.consensus_identity(),
                sender_node_id: client_binding.local_consensus_node_id(),
                expected_server_node_id: client_binding.remote_consensus_node_id(),
                handshake_nonce: uuid::Uuid::new_v4(),
                requested_response_frame_size: u32::try_from(MIN_SESSION_CONSENSUS_FRAME_SIZE)
                    .expect("minimum frame size fits wire field"),
            }),
        )
        .await
        .expect("queue Hello while accepted child is held");

        tokio::time::advance(setup_timeout).await;
        hook.release.notify_one();
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        let mut eof = [0_u8; 1];
        assert!(
            match tokio::time::timeout(Duration::from_millis(1), client.read(&mut eof)).await {
                Ok(Ok(0)) => true,
                Ok(Err(error)) => error.kind() == io::ErrorKind::ConnectionReset,
                Ok(Ok(_)) | Err(_) => false,
            },
            "the accept-time deadline closes before TLS or Hello work can start"
        );
        assert_eq!(
            handler.0.load(Ordering::Relaxed),
            0,
            "an accepted child released at its exact setup boundary admits no Hello or handler work"
        );
        handle.abort_and_wait().await;
    }

    #[tokio::test(start_paused = true)]
    async fn setup_deadline_is_not_renewed_after_tls_budget_reaches_accepted() {
        let (server_binding, client_binding) = bindings();
        let reauthentication = SessionReauthenticationControl::new();
        let pending = PendingConsensusLifecycle::insecure(reauthentication.generation());
        let mut reader = std::io::Cursor::new(valid_consensus_hello_bytes(&client_binding).await);
        let bytes = Arc::new(StdMutex::new(Vec::new()));
        let wrote_first_chunk = Arc::new(Notify::new());
        let first_chunk = wrote_first_chunk.notified();
        tokio::pin!(first_chunk);
        let mut writer = PartialConsensusAcknowledgementWriter {
            bytes,
            first_chunk_written: false,
            wrote_first_chunk: Arc::clone(&wrote_first_chunk),
        };
        let cancellation = AtomicBool::new(false);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let setup_timeout = Duration::from_millis(20);
        let setup_deadline = tokio::time::Instant::now() + setup_timeout;

        // Model a TLS completion that leaves precisely one millisecond for
        // Hello, authority admission, and Accepted. Those later stages must
        // retain the accept-time deadline instead of receiving a fresh window.
        tokio::time::advance(setup_timeout - Duration::from_millis(1)).await;
        let dispatch = dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            pending,
            SessionMembershipAdmission::from_current_binding(server_binding),
            Arc::new(CountingHandler(AtomicUsize::new(0))),
            Arc::new(Semaphore::new(1)),
            MAX_NEGOTIATED_FRAME_SIZE,
            setup_timeout,
            setup_deadline,
            Duration::from_secs(1),
            &cancellation,
            shutdown_rx,
            test_consensus_lifecycle_policy(),
            reauthentication,
        );
        tokio::pin!(dispatch);
        tokio::select! {
            _ = &mut first_chunk => {}
            result = &mut dispatch => panic!("Accepted did not begin before the setup boundary: {result:?}"),
        }

        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(matches!(
            dispatch.await,
            Err(ProtocolError::Io(ref error)) if error.kind() == io::ErrorKind::TimedOut
        ));
    }

    #[cfg(feature = "insecure-test")]
    fn membership_manifest(epoch: u64, members: &[u16]) -> Arc<SessionReplicationManifest> {
        Arc::new(
            SessionReplicationManifest::try_new_with_epoch(
                SessionClusterId::new("consensus-membership-transition").expect("cluster"),
                SessionConfigurationGeneration::new("legacy").expect("legacy generation"),
                SessionConfigurationEpoch::new(epoch).expect("epoch"),
                members.iter().copied().map(descriptor).collect(),
            )
            .expect("membership manifest"),
        )
    }

    #[cfg(feature = "insecure-test")]
    fn membership_transition_request(
        transition_id: SessionTopologyTransitionId,
        expected_epoch: u64,
        desired_epoch: u64,
        members: &[u16],
    ) -> SessionTopologyTransitionRequest {
        SessionTopologyTransitionRequest::try_new(
            transition_id,
            SessionConsensusClusterId::new("consensus-membership-transition").expect("cluster"),
            SessionConfigurationEpoch::new(expected_epoch).expect("expected epoch"),
            SessionConfigurationEpoch::new(desired_epoch).expect("desired epoch"),
            members.iter().copied().map(descriptor).collect(),
            Duration::from_secs(10),
        )
        .expect("membership transition request")
    }

    #[test]
    fn cold_connect_budget_reserves_one_third_of_the_append_soft_ttl() {
        let now = tokio::time::Instant::now();
        let append_soft_ttl = Duration::from_millis(1_500);
        let call_deadline = now + append_soft_ttl;
        let connect_deadline = contained_cold_connect_deadline(now, call_deadline);

        assert_eq!(connect_deadline.duration_since(now), Duration::from_secs(1));
        assert_eq!(
            call_deadline.duration_since(connect_deadline),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn cold_connect_budget_retains_the_profile_cap_for_long_rpc_families() {
        let now = tokio::time::Instant::now();
        let call_deadline = now + Duration::from_secs(10);
        let connect_deadline = contained_cold_connect_deadline(now, call_deadline);

        assert_eq!(
            connect_deadline.duration_since(now),
            DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout()
        );
        assert_eq!(
            call_deadline.duration_since(connect_deadline),
            Duration::from_millis(8_500)
        );
    }

    #[test]
    fn remote_retirement_wait_reserves_the_boundary_plus_a_complete_cold_setup() {
        let epoch = test_cold_epoch();
        let now = tokio::time::Instant::now();
        let probe_at = now + Duration::from_millis(100);
        let gate = ConsensusRemoteRetirementProbeGate {
            epoch,
            next_probe_at: Some(probe_at),
        };
        let complete_probe_deadline =
            probe_at + DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout();

        assert_eq!(
            gate.waitable_probe_at(epoch, complete_probe_deadline),
            Some(probe_at)
        );
        assert_eq!(
            gate.waitable_probe_at(epoch, complete_probe_deadline - Duration::from_nanos(1),),
            None,
            "a caller that cannot contain one complete post-boundary setup must remain prompt"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn remote_retirement_probe_claim_at_the_exact_call_deadline_starts_zero_setup() {
        let (_server_binding, client_binding) = bindings();
        let resolutions = Arc::new(AtomicUsize::new(0));
        let resolver: RemoteAddrResolver = {
            let resolutions = Arc::clone(&resolutions);
            Arc::new(move || {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Box::pin(std::future::pending::<io::Result<SocketAddr>>())
            })
        };
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding,
            Some(Duration::from_secs(10)),
        );
        let coordinator = Arc::clone(&peer.connection_pool.cold_connection);
        let epoch = peer.cold_connector().epoch();
        let now = tokio::time::Instant::now();
        let probe_at = now + Duration::from_millis(100);
        coordinator.state.lock().await.remote_retirement_probe_gate =
            Some(ConsensusRemoteRetirementProbeGate {
                epoch,
                next_probe_at: Some(probe_at),
            });

        let hook = ConsensusColdClaimLockHook::new();
        hook.armed.store(false, Ordering::Release);
        *coordinator
            .pre_claim_state_lock_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&hook));
        let call_deadline = probe_at + DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout();
        let claim = {
            let peer = peer.clone();
            tokio::spawn(async move { peer.claim_or_start_cold_connection(call_deadline).await })
        };
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert!(!claim.is_finished());
        assert_eq!(resolutions.load(Ordering::SeqCst), 0);

        hook.armed.store(true, Ordering::Release);
        tokio::time::advance(Duration::from_millis(100)).await;
        hook.entered.notified().await;
        tokio::time::advance(DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout()).await;
        hook.release.notify_one();

        assert!(matches!(
            claim.await.expect("join exact-deadline claim"),
            Err(SessionConsensusPeerError::Timeout)
        ));
        tokio::task::yield_now().await;
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            0,
            "an exact-deadline claimant must not start a detached physical setup"
        );
        assert!(matches!(
            coordinator.state.lock().await.phase,
            ConsensusColdConnectionPhase::Idle
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn detached_cold_deadline_starts_at_admission_before_the_task_is_polled() {
        let (_server_binding, client_binding) = bindings();
        let resolutions = Arc::new(AtomicUsize::new(0));
        let resolver: RemoteAddrResolver = {
            let resolutions = Arc::clone(&resolutions);
            Arc::new(move || {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Box::pin(std::future::pending::<io::Result<SocketAddr>>())
            })
        };
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding,
            Some(Duration::from_secs(5)),
        );
        let connector = peer.cold_connector();
        let coordinator = Arc::clone(&peer.connection_pool.cold_connection);
        let attempt_id = uuid::Uuid::new_v4();
        let epoch = connector.epoch();
        let admitted_at = tokio::time::Instant::now();
        let attempt_deadline = admitted_at
            .checked_add(DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout())
            .expect("test cold deadline");
        coordinator.state.lock().await.phase = ConsensusColdConnectionPhase::Connecting {
            attempt_id,
            epoch,
            attempt_deadline,
            receipt: Arc::new(ConsensusColdAttemptReceipt::default()),
            remote_retirement_probe: false,
        };
        tokio::time::advance(
            DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout() + Duration::from_millis(1),
        )
        .await;

        run_detached_consensus_connection_attempt(
            connector,
            Arc::clone(&coordinator),
            Arc::clone(&peer.connection_pool.reconnect_gate),
            peer.connection_pool.shutdown.subscribe(),
            attempt_id,
            epoch,
            attempt_deadline,
        )
        .await;

        assert_eq!(resolutions.load(Ordering::SeqCst), 0);
        let state = coordinator.state.lock().await;
        assert!(matches!(
            state.phase,
            ConsensusColdConnectionPhase::Failed {
                attempt_id: current_attempt_id,
                epoch: current_epoch,
                error: SessionConsensusPeerError::Timeout,
            } if current_attempt_id == attempt_id && current_epoch == epoch
        ));
        assert_eq!(state.no_admission_marker, attempt_id);
    }

    #[tokio::test(start_paused = true)]
    async fn post_accepted_bootstrap_deadline_records_one_global_timeout_terminal() {
        const CHILD_MARKER: &str = "OPC_SESSION_NET_POST_ACCEPTED_BOOTSTRAP_METRICS_CHILD";
        if std::env::var_os(CHILD_MARKER).is_none() {
            let status = std::process::Command::new(
                std::env::current_exe().expect("current session-net test executable"),
            )
            .args([
                "--exact",
                "consensus::tests::post_accepted_bootstrap_deadline_records_one_global_timeout_terminal",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_MARKER, "1")
            .status()
            .expect("run isolated post-bootstrap metrics child");
            assert!(
                status.success(),
                "isolated post-bootstrap metrics child passes"
            );
            return;
        }
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let (server_binding, client_binding) = bindings();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind authenticated bootstrap server");
        let address = listener
            .local_addr()
            .expect("read authenticated bootstrap address");
        let server_release = Arc::new(Notify::new());
        let server_release_for_task = Arc::clone(&server_release);
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener
                .accept()
                .await
                .expect("accept authenticated bootstrap");
            let hello: SessionConsensusBootstrapRequest =
                read_frame(&mut tcp, MAX_HANDSHAKE_FRAME_SIZE)
                    .await
                    .expect("read bootstrap Hello");
            let SessionConsensusBootstrapRequest::Hello(hello) = hello;
            write_frame(
                &mut tcp,
                &SessionConsensusBootstrapResponse::Accepted(SessionConsensusBootstrapAck {
                    transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
                    contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
                    identity: hello.identity,
                    server_node_id: server_binding.local_consensus_node_id(),
                    accepted_sender_node_id: hello.sender_node_id,
                    handshake_nonce: hello.handshake_nonce,
                    accepted_response_frame_size: hello.requested_response_frame_size,
                    server_request_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
                }),
            )
            .await
            .expect("write bootstrap Accepted");
            server_release_for_task.notified().await;
        });
        let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding,
            Some(Duration::from_secs(5)),
        );
        let connector = peer.cold_connector();
        let coordinator = Arc::clone(&peer.connection_pool.cold_connection);
        let attempt_id = uuid::Uuid::new_v4();
        let epoch = connector.epoch();
        let attempt_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let receipt = Arc::new(ConsensusColdAttemptReceipt::default());
        coordinator.state.lock().await.phase = ConsensusColdConnectionPhase::Connecting {
            attempt_id,
            epoch,
            attempt_deadline,
            receipt: Arc::clone(&receipt),
            remote_retirement_probe: false,
        };
        let metrics = || {
            (
                METRICS
                    .session_net_connection_attempts
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_successes
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_failure_transport
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_failure_authentication
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_failure_timeout
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_failure_protocol
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_failure_backend
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_superseded
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_abandoned
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_reconnect_attempts
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_reconnect_failures
                    .load(Ordering::Relaxed),
            )
        };
        let before = metrics();
        let hook = ConsensusPostAcceptedBootstrapHook::new();
        let mut attempt = {
            let connector = connector.clone();
            let coordinator = Arc::clone(&coordinator);
            let reconnect_gate = Arc::clone(&peer.connection_pool.reconnect_gate);
            let shutdown = peer.connection_pool.shutdown.subscribe();
            let hook = Arc::clone(&hook);
            tokio::spawn(async move {
                CONSENSUS_POST_ACCEPTED_BOOTSTRAP_HOOK
                    .scope(
                        hook,
                        run_detached_consensus_connection_attempt(
                            connector,
                            coordinator,
                            reconnect_gate,
                            shutdown,
                            attempt_id,
                            epoch,
                            attempt_deadline,
                        ),
                    )
                    .await;
            })
        };

        tokio::select! {
            _ = hook.entered.notified() => {}
            result = &mut attempt => {
                result.expect("join setup that ended before its accepted bootstrap hook");
                let state = coordinator.state.lock().await;
                let error = match state.phase {
                    ConsensusColdConnectionPhase::Failed { error, .. } => Some(error),
                    _ => None,
                };
                panic!("setup ended before its accepted bootstrap hook: {error:?}");
            }
        }
        tokio::time::advance(Duration::from_secs(10) + Duration::from_millis(1)).await;
        hook.release.notify_one();
        server_release.notify_one();
        attempt.await.expect("join post-bootstrap deadline attempt");
        server.await.expect("join authenticated bootstrap server");

        assert_eq!(receipt.terminal(), Some(SessionConsensusPeerError::Timeout));
        let after = metrics();
        assert_eq!(after.0 - before.0, 1, "one setup starts exactly once");
        assert_eq!(after.4 - before.4, 1, "deadline is a timeout terminal");
        assert_eq!(
            after.9 - before.9,
            1,
            "timeout consumes one reconnect attempt"
        );
        assert_eq!(
            after.10 - before.10,
            1,
            "timeout records one reconnect failure"
        );
        assert_eq!(after.8 - before.8, 0, "finished timeout is never abandoned");
        assert_eq!(after.1 - before.1, 0, "expired setup is never successful");
        assert_eq!(after.2 - before.2, 0);
        assert_eq!(after.3 - before.3, 0);
        assert_eq!(after.5 - before.5, 0);
        assert_eq!(after.6 - before.6, 0);
        assert_eq!(after.7 - before.7, 0);
        let terminal_delta = (after.1 - before.1)
            + (after.2 - before.2)
            + (after.3 - before.3)
            + (after.4 - before.4)
            + (after.5 - before.5)
            + (after.6 - before.6)
            + (after.7 - before.7)
            + (after.8 - before.8);
        assert_eq!(
            terminal_delta,
            after.0 - before.0,
            "global terminal conservation"
        );
    }

    #[tokio::test]
    async fn post_accepted_bootstrap_deadline_during_ready_lock_wait_records_one_global_timeout_terminal(
    ) {
        const CHILD_MARKER: &str = "OPC_SESSION_NET_POST_ACCEPTED_READY_LOCK_METRICS_CHILD";
        if std::env::var_os(CHILD_MARKER).is_none() {
            let status = std::process::Command::new(
                std::env::current_exe().expect("current session-net test executable"),
            )
            .args([
                "--exact",
                "consensus::tests::post_accepted_bootstrap_deadline_during_ready_lock_wait_records_one_global_timeout_terminal",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_MARKER, "1")
            .status()
            .expect("run isolated ready-lock deadline metrics child");
            assert!(
                status.success(),
                "isolated ready-lock deadline metrics child passes"
            );
            return;
        }
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let (server_binding, client_binding) = bindings();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind authenticated bootstrap server");
        let address = listener
            .local_addr()
            .expect("read authenticated bootstrap address");
        let server_release = Arc::new(Notify::new());
        let server_release_for_task = Arc::clone(&server_release);
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener
                .accept()
                .await
                .expect("accept authenticated bootstrap");
            let hello: SessionConsensusBootstrapRequest =
                read_frame(&mut tcp, MAX_HANDSHAKE_FRAME_SIZE)
                    .await
                    .expect("read bootstrap Hello");
            let SessionConsensusBootstrapRequest::Hello(hello) = hello;
            write_frame(
                &mut tcp,
                &SessionConsensusBootstrapResponse::Accepted(SessionConsensusBootstrapAck {
                    transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
                    contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
                    identity: hello.identity,
                    server_node_id: server_binding.local_consensus_node_id(),
                    accepted_sender_node_id: hello.sender_node_id,
                    handshake_nonce: hello.handshake_nonce,
                    accepted_response_frame_size: hello.requested_response_frame_size,
                    server_request_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
                }),
            )
            .await
            .expect("write bootstrap Accepted");
            server_release_for_task.notified().await;
        });
        let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding,
            Some(Duration::from_secs(5)),
        );
        let connector = peer.cold_connector();
        let coordinator = Arc::clone(&peer.connection_pool.cold_connection);
        let attempt_id = uuid::Uuid::new_v4();
        let epoch = connector.epoch();
        let attempt_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let receipt = Arc::new(ConsensusColdAttemptReceipt::default());
        coordinator.state.lock().await.phase = ConsensusColdConnectionPhase::Connecting {
            attempt_id,
            epoch,
            attempt_deadline,
            receipt: Arc::clone(&receipt),
            remote_retirement_probe: false,
        };
        let metrics = || {
            (
                METRICS
                    .session_net_connection_attempts
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_successes
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_failure_transport
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_failure_authentication
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_failure_timeout
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_failure_protocol
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_failure_backend
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_superseded
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_connection_abandoned
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_reconnect_attempts
                    .load(Ordering::Relaxed),
                METRICS
                    .session_net_reconnect_failures
                    .load(Ordering::Relaxed),
            )
        };
        let before = metrics();
        let accepted_hook = ConsensusPostAcceptedBootstrapHook::new();
        let ready_hook = ConsensusPostAcceptedBootstrapHook::new();
        let mut attempt = {
            let connector = connector.clone();
            let coordinator = Arc::clone(&coordinator);
            let reconnect_gate = Arc::clone(&peer.connection_pool.reconnect_gate);
            let shutdown = peer.connection_pool.shutdown.subscribe();
            let accepted_hook = Arc::clone(&accepted_hook);
            let ready_hook = Arc::clone(&ready_hook);
            tokio::spawn(async move {
                CONSENSUS_POST_ACCEPTED_BOOTSTRAP_HOOK
                    .scope(
                        accepted_hook,
                        CONSENSUS_PRE_READY_PUBLICATION_HOOK.scope(
                            ready_hook,
                            run_detached_consensus_connection_attempt(
                                connector,
                                coordinator,
                                reconnect_gate,
                                shutdown,
                                attempt_id,
                                epoch,
                                attempt_deadline,
                            ),
                        ),
                    )
                    .await;
            })
        };

        tokio::select! {
            _ = accepted_hook.entered.notified() => {}
            result = &mut attempt => {
                result.expect("join setup that ended before its accepted-bootstrap hook");
                let state = coordinator.state.lock().await;
                let error = match state.phase {
                    ConsensusColdConnectionPhase::Failed { error, .. } => Some(error),
                    _ => None,
                };
                panic!("setup ended before its accepted-bootstrap hook: {error:?}");
            }
        }
        tokio::time::pause();
        let remaining_until_deadline =
            attempt_deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining_until_deadline.is_zero(),
            "Accepted bootstrap must precede the controlled deadline crossing"
        );
        let state_guard = coordinator.state.lock().await;
        accepted_hook.release.notify_one();
        for _ in 0..10_000 {
            if ready_hook.arrived.load(Ordering::Acquire) {
                break;
            }
            assert!(
                !attempt.is_finished(),
                "setup ended before its ready-publication hook"
            );
            // Keeping this controller future runnable prevents Tokio's paused
            // clock from auto-advancing to the attempt deadline between the
            // two deterministic test-only seams.
            tokio::task::yield_now().await;
        }
        assert!(
            ready_hook.arrived.load(Ordering::Acquire),
            "setup did not reach its ready-publication hook within the bounded scheduler turns"
        );
        ready_hook.release.notify_one();
        tokio::task::yield_now().await;
        assert!(
            !attempt.is_finished(),
            "ready publication must remain behind the held coordinator lock"
        );
        tokio::time::advance(remaining_until_deadline + Duration::from_millis(1)).await;
        drop(state_guard);
        server_release.notify_one();
        attempt.await.expect("join ready-lock deadline attempt");
        server.await.expect("join authenticated bootstrap server");

        assert_eq!(receipt.terminal(), Some(SessionConsensusPeerError::Timeout));
        let after = metrics();
        assert_eq!(after.0 - before.0, 1, "one setup starts exactly once");
        assert_eq!(after.4 - before.4, 1, "deadline is a timeout terminal");
        assert_eq!(
            after.9 - before.9,
            1,
            "timeout consumes one reconnect attempt"
        );
        assert_eq!(
            after.10 - before.10,
            1,
            "timeout records one reconnect failure"
        );
        assert_eq!(after.8 - before.8, 0, "finished timeout is never abandoned");
        assert_eq!(after.1 - before.1, 0, "expired setup is never successful");
        assert_eq!(after.2 - before.2, 0);
        assert_eq!(after.3 - before.3, 0);
        assert_eq!(after.5 - before.5, 0);
        assert_eq!(after.6 - before.6, 0);
        assert_eq!(after.7 - before.7, 0);
        let terminal_delta = (after.1 - before.1)
            + (after.2 - before.2)
            + (after.3 - before.3)
            + (after.4 - before.4)
            + (after.5 - before.5)
            + (after.6 - before.6)
            + (after.7 - before.7)
            + (after.8 - before.8);
        assert_eq!(
            terminal_delta,
            after.0 - before.0,
            "global terminal conservation"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cold_ready_at_the_contained_deadline_is_never_published() {
        let coordinator = ConsensusColdConnectionCoordinator::new();
        let epoch = test_cold_epoch();
        let attempt_id = uuid::Uuid::new_v4();
        let now = tokio::time::Instant::now();
        coordinator.state.lock().await.phase = ConsensusColdConnectionPhase::Connecting {
            attempt_id,
            epoch,
            attempt_deadline: now,
            receipt: Arc::new(ConsensusColdAttemptReceipt::default()),
            remote_retirement_probe: false,
        };
        let lifecycle = ConnectionLifecycle::new(
            ConnectionLifecyclePolicy::try_new(
                Duration::from_secs(60),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::ZERO,
            )
            .expect("deadline publication lifecycle"),
            now,
            None,
            None,
            epoch.reauthentication_generation,
            epoch.material_epoch,
        )
        .expect("deadline publication connection lifecycle");
        let connection = Box::new(ConsensusConnection {
            reader: Box::new(tokio::io::empty()),
            writer: Box::new(tokio::io::sink()),
            response_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            request_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            admission_attempt_id: None,
            lifecycle,
            last_successful_correlated_use: None,
            idle_deadline_origin: now,
        });
        assert_eq!(
            coordinator
                .publish_ready(attempt_id, epoch, connection)
                .await,
            ConsensusPublishReadyOutcome::TimedOut
        );
        let state = coordinator.state.lock().await;
        assert!(matches!(
            state.phase,
            ConsensusColdConnectionPhase::Failed {
                error: SessionConsensusPeerError::Timeout,
                ..
            }
        ));
        assert!(
            state.remote_retirement_probe_gate.is_none(),
            "a local deadline overrun is not authenticated remote-retirement evidence"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cold_ready_publication_rechecks_lifecycle_after_coordinator_lock_wait() {
        let (_server_binding, client_binding) = bindings();
        let coordinator = ConsensusColdConnectionCoordinator::new();
        let attempt_id = uuid::Uuid::new_v4();
        let epoch = ConsensusColdConnectionEpoch {
            consensus_identity: client_binding.consensus_identity(),
            remote_node_id: client_binding.remote_consensus_node_id(),
            reauthentication_generation: 0,
            material_epoch: None,
        };
        let established_at = tokio::time::Instant::now();
        let maximum_age = Duration::from_millis(10);
        let lifecycle_policy = ConnectionLifecyclePolicy::try_new(
            maximum_age,
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::ZERO,
        )
        .expect("publication-race lifecycle policy");
        let connection = |established_at| {
            Box::new(ConsensusConnection {
                reader: Box::new(tokio::io::empty()),
                writer: Box::new(tokio::io::sink()),
                response_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
                request_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
                admission_attempt_id: None,
                lifecycle: ConnectionLifecycle::new(
                    lifecycle_policy,
                    established_at,
                    None,
                    None,
                    epoch.reauthentication_generation,
                    epoch.material_epoch,
                )
                .expect("publication-race connection lifecycle"),
                last_successful_correlated_use: None,
                idle_deadline_origin: established_at,
            })
        };
        let mut state = coordinator.state.lock().await;
        state.phase = ConsensusColdConnectionPhase::Connecting {
            attempt_id,
            epoch,
            attempt_deadline: established_at + Duration::from_secs(1),
            receipt: Arc::new(ConsensusColdAttemptReceipt::default()),
            remote_retirement_probe: false,
        };
        let publish = {
            let coordinator = Arc::clone(&coordinator);
            let connection = connection(established_at);
            tokio::spawn(async move {
                coordinator
                    .publish_ready(attempt_id, epoch, connection)
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert!(
            !publish.is_finished(),
            "publication must remain behind the held coordinator lock"
        );

        tokio::time::advance(maximum_age + Duration::from_millis(1)).await;
        drop(state);
        assert_eq!(
            publish.await.expect("join lifecycle-fenced publication"),
            ConsensusPublishReadyOutcome::Retired(RetirementReason::MaximumAge)
        );
        let state = coordinator.state.lock().await;
        assert!(matches!(
            state.phase,
            ConsensusColdConnectionPhase::Failed {
                attempt_id: current_attempt_id,
                epoch: current_epoch,
                error: SessionConsensusPeerError::Unavailable,
            } if current_attempt_id == attempt_id && current_epoch == epoch
        ));
        assert_eq!(state.no_admission_marker, attempt_id);
        assert!(
            state.remote_retirement_probe_gate.is_none(),
            "local maximum-age retirement is not authenticated remote-retirement evidence"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cold_ready_peer_credential_retirement_seeds_the_exact_epoch_probe_gate() {
        let coordinator = ConsensusColdConnectionCoordinator::new();
        let epoch = test_cold_epoch();
        let attempt_id = uuid::Uuid::new_v4();
        let now = tokio::time::Instant::now();
        let expired = opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::now_utc() - time::Duration::seconds(1),
        );
        let peer_expiry = CertificateExpiryEvidence::capture(expired, expired, now);
        let lifecycle = ConnectionLifecycle::new(
            ConnectionLifecyclePolicy::default(),
            now,
            None,
            Some(peer_expiry),
            epoch.reauthentication_generation,
            epoch.material_epoch,
        )
        .expect("peer-expired publication lifecycle");
        coordinator.state.lock().await.phase = ConsensusColdConnectionPhase::Connecting {
            attempt_id,
            epoch,
            attempt_deadline: now + Duration::from_secs(1),
            receipt: Arc::new(ConsensusColdAttemptReceipt::default()),
            remote_retirement_probe: false,
        };

        assert_eq!(
            coordinator
                .publish_ready(
                    attempt_id,
                    epoch,
                    Box::new(cached_consensus_connection(lifecycle)),
                )
                .await,
            ConsensusPublishReadyOutcome::Retired(RetirementReason::PeerLeafExpiry)
        );
        let state = coordinator.state.lock().await;
        assert!(matches!(
            state.phase,
            ConsensusColdConnectionPhase::Failed {
                error: SessionConsensusPeerError::Unavailable,
                ..
            }
        ));
        assert!(
            state
                .remote_retirement_probe_gate
                .is_some_and(|gate| gate.epoch == epoch),
            "authenticated peer credential retirement seeds the exact-epoch probe gate"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cold_attempt_receipts_survive_later_receipt_replacement() {
        let (_server_binding, client_binding) = bindings();
        let coordinator = ConsensusColdConnectionCoordinator::new();
        let epoch = ConsensusColdConnectionEpoch {
            consensus_identity: client_binding.consensus_identity(),
            remote_node_id: client_binding.remote_consensus_node_id(),
            reauthentication_generation: 0,
            material_epoch: None,
        };
        let attempt_a = uuid::Uuid::new_v4();
        let receipt_a = Arc::new(ConsensusColdAttemptReceipt::default());
        coordinator.state.lock().await.phase = ConsensusColdConnectionPhase::Connecting {
            attempt_id: attempt_a,
            epoch,
            attempt_deadline: tokio::time::Instant::now() + Duration::from_secs(1),
            receipt: Arc::clone(&receipt_a),
            remote_retirement_probe: false,
        };
        // These clones model two callers that joined A before it completed.
        let first_a_waiter = Arc::clone(&receipt_a);
        let delayed_a_waiter = Arc::clone(&receipt_a);
        coordinator
            .publish_failure(attempt_a, epoch, SessionConsensusPeerError::Authentication)
            .await;

        // A genuinely later caller consumes A's shared state and installs B
        // before the delayed A waiter reacquires the coordinator lock.
        let attempt_b = uuid::Uuid::new_v4();
        let receipt_b = Arc::new(ConsensusColdAttemptReceipt::default());
        {
            let mut state = coordinator.state.lock().await;
            state.phase = ConsensusColdConnectionPhase::Connecting {
                attempt_id: attempt_b,
                epoch,
                attempt_deadline: tokio::time::Instant::now() + Duration::from_secs(1),
                receipt: Arc::clone(&receipt_b),
                remote_retirement_probe: false,
            };
        }
        coordinator
            .publish_failure(attempt_b, epoch, SessionConsensusPeerError::Protocol)
            .await;

        assert_eq!(
            first_a_waiter.terminal(),
            Some(SessionConsensusPeerError::Authentication)
        );
        assert_eq!(
            delayed_a_waiter.terminal(),
            Some(SessionConsensusPeerError::Authentication),
            "an overtaken A waiter must never infer B from global state"
        );
        assert_eq!(
            receipt_b.terminal(),
            Some(SessionConsensusPeerError::Protocol)
        );
        let state = coordinator.state.lock().await;
        assert!(matches!(
            state.phase,
            ConsensusColdConnectionPhase::Failed {
                attempt_id,
                error: SessionConsensusPeerError::Protocol,
                ..
            } if attempt_id == attempt_b
        ));
        assert_eq!(state.no_admission_marker, attempt_b);
    }

    #[tokio::test(start_paused = true)]
    async fn remote_retirement_probe_gate_uses_the_fixed_profile_interval_and_rearms_failed_probes()
    {
        let (_server_binding, client_binding) = bindings();
        let coordinator = ConsensusColdConnectionCoordinator::new();
        let epoch = ConsensusColdConnectionEpoch {
            consensus_identity: client_binding.consensus_identity(),
            remote_node_id: client_binding.remote_consensus_node_id(),
            reauthentication_generation: 0,
            material_epoch: None,
        };
        let rejected_attempt = uuid::Uuid::new_v4();
        let rejected_receipt = Arc::new(ConsensusColdAttemptReceipt::default());
        coordinator.state.lock().await.phase = ConsensusColdConnectionPhase::Connecting {
            attempt_id: rejected_attempt,
            epoch,
            attempt_deadline: tokio::time::Instant::now() + Duration::from_secs(1),
            receipt: Arc::clone(&rejected_receipt),
            remote_retirement_probe: false,
        };
        coordinator
            .publish_failure(rejected_attempt, epoch, SessionConsensusPeerError::Rejected)
            .await;

        assert_eq!(
            rejected_receipt.terminal(),
            Some(SessionConsensusPeerError::Unavailable),
            "remote bootstrap retirement is an exact pre-Call unavailable receipt"
        );
        assert!(matches!(
            coordinator.state.lock().await.phase,
            ConsensusColdConnectionPhase::Failed {
                attempt_id,
                error: SessionConsensusPeerError::Unavailable,
                ..
            } if attempt_id == rejected_attempt
        ));

        let now = tokio::time::Instant::now();
        assert!(
            coordinator
                .state
                .lock()
                .await
                .remote_retirement_probe_gate
                .is_some_and(|gate| gate.blocks(epoch, now)),
            "the authenticated retirement RED case must block later same-epoch setup"
        );
        tokio::time::advance(DURABLE_CONSENSUS_REMOTE_RETIREMENT_PROBE_INTERVAL).await;
        let now = tokio::time::Instant::now();
        assert!(
            coordinator
                .state
                .lock()
                .await
                .remote_retirement_probe_gate
                .is_some_and(|gate| gate.probe_is_due(epoch, now)),
            "exactly the fixed profile boundary admits one later probe owner"
        );

        let failed_probe = uuid::Uuid::new_v4();
        coordinator.state.lock().await.phase = ConsensusColdConnectionPhase::Connecting {
            attempt_id: failed_probe,
            epoch,
            attempt_deadline: tokio::time::Instant::now() + Duration::from_secs(1),
            receipt: Arc::new(ConsensusColdAttemptReceipt::default()),
            remote_retirement_probe: true,
        };
        coordinator
            .publish_failure(
                failed_probe,
                epoch,
                SessionConsensusPeerError::Authentication,
            )
            .await;
        let now = tokio::time::Instant::now();
        assert!(
            coordinator
                .state
                .lock()
                .await
                .remote_retirement_probe_gate
                .is_some_and(|gate| gate.blocks(epoch, now)),
            "a failed same-epoch probe must re-arm rather than becoming call-rate driven"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn credential_retirement_seed_is_due_now_monotonic_and_excludes_idle_and_maximum_age() {
        let coordinator = ConsensusColdConnectionCoordinator::new();
        let epoch = test_cold_epoch();
        coordinator
            .seed_credential_retirement_probe(epoch, None, None, RetirementReason::PeerLeafExpiry)
            .await;
        let now = tokio::time::Instant::now();
        assert!(coordinator
            .state
            .lock()
            .await
            .remote_retirement_probe_gate
            .is_some_and(|gate| gate.probe_is_due(epoch, now)));

        let attempt_id = uuid::Uuid::new_v4();
        coordinator.state.lock().await.phase = ConsensusColdConnectionPhase::Connecting {
            attempt_id,
            epoch,
            attempt_deadline: now + Duration::from_secs(1),
            receipt: Arc::new(ConsensusColdAttemptReceipt::default()),
            remote_retirement_probe: true,
        };
        coordinator
            .publish_failure(attempt_id, epoch, SessionConsensusPeerError::Authentication)
            .await;
        let blocked_until = coordinator
            .state
            .lock()
            .await
            .remote_retirement_probe_gate
            .expect("failed immediate probe must re-arm")
            .next_probe_at;
        coordinator
            .seed_credential_retirement_probe(
                epoch,
                None,
                None,
                RetirementReason::PeerCertificateChainExpiry,
            )
            .await;
        assert_eq!(
            coordinator
                .state
                .lock()
                .await
                .remote_retirement_probe_gate
                .expect("same epoch gate remains installed")
                .next_probe_at,
            blocked_until,
            "a concurrent credential retirement must not reopen a failed probe window"
        );

        let other = ConsensusColdConnectionCoordinator::new();
        other
            .seed_credential_retirement_probe(epoch, None, None, RetirementReason::IdleTimeout)
            .await;
        other
            .seed_credential_retirement_probe(epoch, None, None, RetirementReason::MaximumAge)
            .await;
        assert!(other
            .state
            .lock()
            .await
            .remote_retirement_probe_gate
            .is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn accepted_same_epoch_peer_credential_successor_suppresses_only_strictly_older_lane() {
        let coordinator = ConsensusColdConnectionCoordinator::new();
        let epoch = test_cold_epoch();
        let old_attempt = uuid::Uuid::new_v4();
        let accepted_attempt = uuid::Uuid::new_v4();
        let now = tokio::time::Instant::now();
        let wall_now = time::OffsetDateTime::now_utc();
        let old_peer_expiry =
            opc_types::Timestamp::from_offset_datetime(wall_now + time::Duration::seconds(30));
        let accepted_peer_expiry =
            opc_types::Timestamp::from_offset_datetime(wall_now + time::Duration::seconds(60));
        let accepted_peer_evidence =
            CertificateExpiryEvidence::capture(accepted_peer_expiry, accepted_peer_expiry, now);
        {
            let mut state = coordinator.state.lock().await;
            state.phase = ConsensusColdConnectionPhase::Connecting {
                attempt_id: accepted_attempt,
                epoch,
                attempt_deadline: now + Duration::from_secs(1),
                receipt: Arc::new(ConsensusColdAttemptReceipt::default()),
                remote_retirement_probe: true,
            };
            state.remote_retirement_probe_gate = Some(ConsensusRemoteRetirementProbeGate {
                epoch,
                next_probe_at: Some(now),
            });
        }
        let accepted = cached_consensus_connection(
            ConnectionLifecycle::new(
                ConnectionLifecyclePolicy::default(),
                now,
                None,
                Some(accepted_peer_evidence),
                epoch.reauthentication_generation,
                epoch.material_epoch,
            )
            .expect("accepted successor lifecycle"),
        );
        assert_eq!(
            coordinator
                .publish_ready(accepted_attempt, epoch, Box::new(accepted))
                .await,
            ConsensusPublishReadyOutcome::Published
        );
        assert!(
            coordinator
                .state
                .lock()
                .await
                .remote_retirement_probe_gate
                .is_none(),
            "the accepted same-epoch successor clears its existing probe gate"
        );

        coordinator
            .seed_credential_retirement_probe(
                epoch,
                Some(old_attempt),
                Some(old_peer_expiry),
                RetirementReason::PeerLeafExpiry,
            )
            .await;
        assert!(
            coordinator
                .state
                .lock()
                .await
                .remote_retirement_probe_gate
                .is_none(),
            "a delayed lane with strictly older peer-credential evidence cannot reopen the gate"
        );

        coordinator
            .seed_credential_retirement_probe(
                epoch,
                Some(accepted_attempt),
                Some(accepted_peer_expiry),
                RetirementReason::PeerLeafExpiry,
            )
            .await;
        assert!(coordinator
            .state
            .lock()
            .await
            .remote_retirement_probe_gate
            .is_some_and(|gate| gate.probe_is_due(epoch, tokio::time::Instant::now())));

        coordinator.state.lock().await.remote_retirement_probe_gate = None;
        coordinator
            .seed_credential_retirement_probe(
                epoch,
                Some(old_attempt),
                Some(accepted_peer_expiry),
                RetirementReason::PeerLeafExpiry,
            )
            .await;
        assert!(
            coordinator
                .state
                .lock()
                .await
                .remote_retirement_probe_gate
                .is_some(),
            "equal peer-credential evidence is incomparable and must seed fail-closed"
        );

        coordinator.state.lock().await.remote_retirement_probe_gate = None;
        coordinator
            .seed_credential_retirement_probe(
                epoch,
                Some(old_attempt),
                Some(old_peer_expiry),
                RetirementReason::LocalLeafExpiry,
            )
            .await;
        assert!(
            coordinator
                .state
                .lock()
                .await
                .remote_retirement_probe_gate
                .is_some(),
            "same-epoch local-credential retirement remains applicable"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn accepted_newer_epoch_suppresses_delayed_older_epoch_credential_retirement() {
        let coordinator = ConsensusColdConnectionCoordinator::new();
        let older_epoch = test_cold_epoch();
        let accepted_epoch = ConsensusColdConnectionEpoch {
            reauthentication_generation: older_epoch.reauthentication_generation + 1,
            ..older_epoch
        };
        coordinator.state.lock().await.latest_accepted_connection =
            Some(ConsensusAcceptedConnection {
                epoch: accepted_epoch,
                attempt_id: uuid::Uuid::new_v4(),
                peer_certificate_effective_expiry: None,
            });

        coordinator
            .seed_credential_retirement_probe(
                older_epoch,
                None,
                None,
                RetirementReason::LocalLeafExpiry,
            )
            .await;
        assert!(
            coordinator
                .state
                .lock()
                .await
                .remote_retirement_probe_gate
                .is_none(),
            "an older connector epoch cannot reopen a gate after a newer Accepted bootstrap"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn accepted_incomparable_material_tracking_mode_keeps_retirement_fail_closed() {
        let coordinator = ConsensusColdConnectionCoordinator::new();
        let retired_epoch = test_cold_epoch();
        let material = crate::test_support::RotatableClientMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/client",
        );
        let accepted_epoch = ConsensusColdConnectionEpoch {
            material_epoch: Some(material.config().material_status().epoch()),
            ..retired_epoch
        };
        assert!(!accepted_epoch.is_strictly_newer_than(retired_epoch));
        assert!(!retired_epoch.is_strictly_newer_than(accepted_epoch));
        coordinator.state.lock().await.latest_accepted_connection =
            Some(ConsensusAcceptedConnection {
                epoch: accepted_epoch,
                attempt_id: uuid::Uuid::new_v4(),
                peer_certificate_effective_expiry: None,
            });

        coordinator
            .seed_credential_retirement_probe(
                retired_epoch,
                None,
                None,
                RetirementReason::LocalLeafExpiry,
            )
            .await;
        assert!(coordinator
            .state
            .lock()
            .await
            .remote_retirement_probe_gate
            .is_some_and(|gate| {
                gate.epoch == retired_epoch
                    && gate.probe_is_due(retired_epoch, tokio::time::Instant::now())
            }));
    }

    #[tokio::test(start_paused = true)]
    async fn older_ready_publication_preserves_a_newer_retirement_gate() {
        let coordinator = ConsensusColdConnectionCoordinator::new();
        let older_epoch = test_cold_epoch();
        let newer_epoch = ConsensusColdConnectionEpoch {
            reauthentication_generation: older_epoch.reauthentication_generation + 1,
            ..older_epoch
        };
        let attempt_id = uuid::Uuid::new_v4();
        let now = tokio::time::Instant::now();
        {
            let mut state = coordinator.state.lock().await;
            state.phase = ConsensusColdConnectionPhase::Connecting {
                attempt_id,
                epoch: older_epoch,
                attempt_deadline: now + Duration::from_secs(1),
                receipt: Arc::new(ConsensusColdAttemptReceipt::default()),
                remote_retirement_probe: false,
            };
            state.remote_retirement_probe_gate = Some(ConsensusRemoteRetirementProbeGate {
                epoch: newer_epoch,
                next_probe_at: Some(now + DURABLE_CONSENSUS_REMOTE_RETIREMENT_PROBE_INTERVAL),
            });
        }
        let connection = cached_consensus_connection(
            ConnectionLifecycle::new(
                ConnectionLifecyclePolicy::default(),
                now,
                None,
                None,
                older_epoch.reauthentication_generation,
                older_epoch.material_epoch,
            )
            .expect("older accepted connection lifecycle"),
        );
        assert_eq!(
            coordinator
                .publish_ready(attempt_id, older_epoch, Box::new(connection))
                .await,
            ConsensusPublishReadyOutcome::Published
        );
        assert!(coordinator
            .state
            .lock()
            .await
            .remote_retirement_probe_gate
            .is_some_and(|gate| gate.epoch == newer_epoch));
    }

    #[tokio::test]
    async fn delayed_stale_credential_retirement_cannot_replace_current_remote_retirement_gate() {
        let (_server_binding, client_binding) = bindings();
        let (address, server) =
            bootstrap_retirement_then_consensus_response_server(client_binding.clone()).await;
        let resolutions = Arc::new(AtomicUsize::new(0));
        let resolve: RemoteAddrResolver = {
            let resolutions = Arc::clone(&resolutions);
            Arc::new(move || {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { Ok(address) })
            })
        };
        let reauthentication = SessionReauthenticationControl::new();
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolve),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(10)),
        )
        .with_reauthentication_control(reauthentication.clone());
        let request = || {
            SessionConsensusWireRequest::try_new(
                client_binding.consensus_identity(),
                client_binding.local_consensus_node_id(),
                ConsensusRpcFamily::Vote,
                b"stale-retirement-cannot-displace-current-gate".to_vec(),
            )
            .expect("bounded request")
        };

        let stale_epoch = peer.cold_connector().epoch();
        reauthentication
            .request_reauthentication()
            .expect("advance to the current connector epoch");
        let current_epoch = peer.cold_connector().epoch();
        assert_ne!(stale_epoch, current_epoch);

        assert_eq!(
            peer.call(request()).await,
            Err(SessionConsensusPeerError::Unavailable),
            "the current authenticated bootstrap rejection arms its own gate"
        );
        assert_eq!(resolutions.load(Ordering::SeqCst), 1);

        peer.connection_pool
            .cold_connection
            .seed_credential_retirement_probe(
                stale_epoch,
                None,
                None,
                RetirementReason::PeerLeafExpiry,
            )
            .await;
        let now = tokio::time::Instant::now();
        assert!(
            peer.connection_pool
                .cold_connection
                .state
                .lock()
                .await
                .remote_retirement_probe_gate
                .is_some_and(|gate| {
                    gate.epoch == current_epoch && gate.blocks(current_epoch, now)
                }),
            "a delayed stale-lane retirement must not displace the current protected window"
        );

        let waiting_peer = peer.clone();
        let waiting_request = request();
        let waiting_call = tokio::spawn(async move { waiting_peer.call(waiting_request).await });
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert!(
            !waiting_call.is_finished(),
            "a current-epoch caller waits for the fixed probe boundary rather than failing at operation rate"
        );
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            1,
            "the waiting current call performs zero physical setups before the boundary"
        );

        make_remote_retirement_probe_due(&peer).await;
        assert_eq!(
            waiting_call.await.expect("waiting current-epoch call"),
            Ok(SessionConsensusWireResponse {
                result: Ok(b"stale-retirement-cannot-displace-current-gate".to_vec()),
            }),
            "the waiting same-epoch call is admitted at the fixed boundary"
        );
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            2,
            "exactly one physical setup starts at the probe boundary"
        );
        assert_eq!(
            server.await.expect("bootstrap retirement recovery server"),
            (2, 1),
            "the protected window sends no Call and the boundary recovery sends one"
        );
    }

    #[tokio::test]
    async fn newer_credential_retirement_replaces_an_older_exact_epoch_probe_gate() {
        let (_server_binding, client_binding) = bindings();
        let (address, server) =
            bootstrap_retirement_then_consensus_response_server(client_binding.clone()).await;
        let resolutions = Arc::new(AtomicUsize::new(0));
        let resolve: RemoteAddrResolver = {
            let resolutions = Arc::clone(&resolutions);
            Arc::new(move || {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { Ok(address) })
            })
        };
        let reauthentication = SessionReauthenticationControl::new();
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolve),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(10)),
        )
        .with_reauthentication_control(reauthentication.clone());
        let request = || {
            SessionConsensusWireRequest::try_new(
                client_binding.consensus_identity(),
                client_binding.local_consensus_node_id(),
                ConsensusRpcFamily::Vote,
                b"newer-retirement-replaces-older-gate".to_vec(),
            )
            .expect("bounded request")
        };

        let stale_epoch = peer.cold_connector().epoch();
        peer.connection_pool
            .cold_connection
            .seed_credential_retirement_probe(
                stale_epoch,
                None,
                None,
                RetirementReason::PeerLeafExpiry,
            )
            .await;
        reauthentication
            .request_reauthentication()
            .expect("advance to the current connector epoch");
        let current_epoch = peer.cold_connector().epoch();
        peer.connection_pool
            .cold_connection
            .seed_credential_retirement_probe(
                current_epoch,
                None,
                None,
                RetirementReason::PeerLeafExpiry,
            )
            .await;
        assert!(
            peer.connection_pool
                .cold_connection
                .state
                .lock()
                .await
                .remote_retirement_probe_gate
                .is_some_and(|gate| {
                    gate.epoch == current_epoch
                        && gate.probe_is_due(current_epoch, tokio::time::Instant::now())
                }),
            "a current cached credential retirement replaces the old exact-epoch gate"
        );

        assert_eq!(
            peer.call(request()).await,
            Err(SessionConsensusPeerError::Unavailable),
            "the current due-now probe observes authenticated bootstrap retirement"
        );
        assert_eq!(resolutions.load(Ordering::SeqCst), 1);
        let waiting_peer = peer.clone();
        let waiting_request = request();
        let waiting_call = tokio::spawn(async move { waiting_peer.call(waiting_request).await });
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert!(
            !waiting_call.is_finished(),
            "the current gate holds later callers until the fixed probe boundary"
        );
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            1,
            "the protected current window starts zero extra physical setups before the boundary"
        );

        make_remote_retirement_probe_due(&peer).await;
        assert_eq!(
            waiting_call.await.expect("waiting current caller"),
            Ok(SessionConsensusWireResponse {
                result: Ok(b"newer-retirement-replaces-older-gate".to_vec()),
            }),
            "the waiting current caller starts the one probe at the fixed boundary"
        );
        assert_eq!(resolutions.load(Ordering::SeqCst), 2);
        assert_eq!(
            server.await.expect("bootstrap retirement recovery server"),
            (2, 1),
            "only the boundary recovery transmits a Call"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn newer_material_epoch_replaces_an_equal_reauthentication_probe_gate() {
        let material = crate::test_support::RotatableClientMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/client",
        );
        let config = material.config();
        let previous_epoch = ConsensusColdConnectionEpoch {
            material_epoch: Some(config.material_status().epoch()),
            ..test_cold_epoch()
        };
        material.rotate();
        let current_epoch = ConsensusColdConnectionEpoch {
            material_epoch: Some(config.material_status().epoch()),
            ..previous_epoch
        };
        assert_eq!(
            current_epoch.reauthentication_generation, previous_epoch.reauthentication_generation,
            "replacement is ordered by material publication, not reauthentication"
        );
        assert!(current_epoch.is_strictly_newer_than(previous_epoch));

        let mut state = ConsensusColdConnectionState {
            phase: ConsensusColdConnectionPhase::Idle,
            no_admission_marker: uuid::Uuid::nil(),
            remote_retirement_probe_gate: None,
            latest_accepted_connection: None,
        };
        state.remote_retirement_probe_gate = Some(ConsensusRemoteRetirementProbeGate {
            epoch: previous_epoch,
            next_probe_at: Some(
                tokio::time::Instant::now() + DURABLE_CONSENSUS_REMOTE_RETIREMENT_PROBE_INTERVAL,
            ),
        });
        ConsensusColdConnectionCoordinator::seed_credential_retirement_probe_gate(
            &mut state,
            current_epoch,
            None,
            None,
            RetirementReason::PeerLeafExpiry,
        );
        assert!(state.remote_retirement_probe_gate.is_some_and(|gate| {
            gate.epoch == current_epoch
                && gate.probe_is_due(current_epoch, tokio::time::Instant::now())
        }));
    }

    #[tokio::test(start_paused = true)]
    async fn staged_ready_credential_retirement_seeds_the_due_now_probe_gate() {
        let coordinator = ConsensusColdConnectionCoordinator::new();
        let epoch = test_cold_epoch();
        let now = tokio::time::Instant::now();
        let expired = opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::now_utc() - time::Duration::seconds(1),
        );
        let peer_expiry = CertificateExpiryEvidence::capture(expired, expired, now);
        let lifecycle = ConnectionLifecycle::new(
            ConnectionLifecyclePolicy::default(),
            now,
            None,
            Some(peer_expiry),
            epoch.reauthentication_generation,
            epoch.material_epoch,
        )
        .expect("peer-expired staged lifecycle");
        let attempt_id = uuid::Uuid::new_v4();
        coordinator.state.lock().await.phase = ConsensusColdConnectionPhase::Ready {
            attempt_id,
            epoch,
            connection: Box::new(cached_consensus_connection(lifecycle)),
        };

        assert!(
            coordinator
                .invalidate_ready(attempt_id, ConsensusStagedConnectionInvalidation::Lifecycle,)
                .await
        );
        let state = coordinator.state.lock().await;
        assert!(matches!(state.phase, ConsensusColdConnectionPhase::Idle));
        assert!(state
            .remote_retirement_probe_gate
            .is_some_and(|gate| gate.probe_is_due(epoch, tokio::time::Instant::now())));
    }

    #[tokio::test(start_paused = true)]
    async fn joined_cold_receipt_is_rechecked_after_the_claim_lock_gap() {
        let (_server_binding, client_binding) = bindings();
        let resolver: RemoteAddrResolver =
            Arc::new(|| Box::pin(std::future::pending::<io::Result<SocketAddr>>()));
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding,
            Some(Duration::from_secs(5)),
        );
        let coordinator = Arc::clone(&peer.connection_pool.cold_connection);
        let epoch = peer.cold_connector().epoch();
        let attempt_a = uuid::Uuid::new_v4();
        coordinator.state.lock().await.phase = ConsensusColdConnectionPhase::Connecting {
            attempt_id: attempt_a,
            epoch,
            attempt_deadline: tokio::time::Instant::now() + Duration::from_secs(1),
            receipt: Arc::new(ConsensusColdAttemptReceipt::default()),
            remote_retirement_probe: false,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let first_a_waiter = {
            let peer = peer.clone();
            tokio::spawn(async move { peer.claim_or_start_cold_connection(deadline).await })
        };
        let second_a_waiter = {
            let peer = peer.clone();
            tokio::spawn(async move { peer.claim_or_start_cold_connection(deadline).await })
        };
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        let hook = ConsensusColdClaimLockHook::new();
        *coordinator
            .pre_claim_state_lock_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&hook));
        coordinator.changed.notify_waiters();
        hook.entered.notified().await;

        coordinator
            .publish_failure(attempt_a, epoch, SessionConsensusPeerError::Authentication)
            .await;
        let attempt_b = uuid::Uuid::new_v4();
        coordinator.state.lock().await.phase = ConsensusColdConnectionPhase::Connecting {
            attempt_id: attempt_b,
            epoch,
            attempt_deadline: tokio::time::Instant::now() + Duration::from_secs(1),
            receipt: Arc::new(ConsensusColdAttemptReceipt::default()),
            remote_retirement_probe: false,
        };
        coordinator
            .publish_failure(attempt_b, epoch, SessionConsensusPeerError::Protocol)
            .await;
        hook.release.notify_one();

        assert!(matches!(
            first_a_waiter.await.expect("join first A waiter"),
            Err(SessionConsensusPeerError::Authentication)
        ));
        assert!(matches!(
            second_a_waiter.await.expect("join second A waiter"),
            Err(SessionConsensusPeerError::Authentication)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn published_ready_retirement_advances_one_marker_per_later_call() {
        let (_server_binding, client_binding) = bindings();
        let coordinator = ConsensusColdConnectionCoordinator::new();
        let epoch = ConsensusColdConnectionEpoch {
            consensus_identity: client_binding.consensus_identity(),
            remote_node_id: client_binding.remote_consensus_node_id(),
            reauthentication_generation: 0,
            material_epoch: None,
        };
        let maximum_age = Duration::from_millis(10);
        let lifecycle_policy = ConnectionLifecyclePolicy::try_new(
            maximum_age,
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::ZERO,
        )
        .expect("post-publication race lifecycle policy");

        for logical_call in 0..2 {
            let attempt_id = uuid::Uuid::new_v4();
            let established_at = tokio::time::Instant::now();
            coordinator.state.lock().await.phase = ConsensusColdConnectionPhase::Connecting {
                attempt_id,
                epoch,
                attempt_deadline: established_at + Duration::from_secs(1),
                receipt: Arc::new(ConsensusColdAttemptReceipt::default()),
                remote_retirement_probe: false,
            };
            let connection = Box::new(ConsensusConnection {
                reader: Box::new(tokio::io::empty()),
                writer: Box::new(tokio::io::sink()),
                response_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
                request_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
                admission_attempt_id: None,
                lifecycle: ConnectionLifecycle::new(
                    lifecycle_policy,
                    established_at,
                    None,
                    None,
                    epoch.reauthentication_generation,
                    epoch.material_epoch,
                )
                .expect("post-publication race lifecycle"),
                last_successful_correlated_use: None,
                idle_deadline_origin: established_at,
            });
            assert_eq!(
                coordinator
                    .publish_ready(attempt_id, epoch, connection)
                    .await,
                ConsensusPublishReadyOutcome::Published
            );

            // Schedule lifecycle retirement after publication but before a
            // joined claimant can take the staged socket. This transition
            // must consume this logical call without dispatching a Call.
            tokio::time::advance(maximum_age).await;
            coordinator
                .invalidate_ready(attempt_id, ConsensusStagedConnectionInvalidation::Lifecycle)
                .await;
            let state = coordinator.state.lock().await;
            assert!(matches!(state.phase, ConsensusColdConnectionPhase::Idle));
            assert_eq!(
                state.no_admission_marker, attempt_id,
                "logical call {logical_call} owns exactly one no-admission marker"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_failed_cold_claimants_share_one_terminal_receipt() {
        let (_server_binding, client_binding) = bindings();
        let material = crate::test_support::RotatableClientMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/1",
        );
        let resolutions = Arc::new(AtomicUsize::new(0));
        let first_resolution_started = Arc::new(Notify::new());
        let release_first_resolution = Arc::new(Notify::new());
        let resolver: RemoteAddrResolver = {
            let resolutions = Arc::clone(&resolutions);
            let first_resolution_started = Arc::clone(&first_resolution_started);
            let release_first_resolution = Arc::clone(&release_first_resolution);
            Arc::new(move || {
                let resolution = resolutions.fetch_add(1, Ordering::SeqCst);
                let first_resolution_started = Arc::clone(&first_resolution_started);
                let release_first_resolution = Arc::clone(&release_first_resolution);
                Box::pin(async move {
                    if resolution == 0 {
                        first_resolution_started.notify_one();
                        release_first_resolution.notified().await;
                    }
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "test resolver unavailable",
                    ))
                })
            })
        };
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .expect("fixed reconnect cooldown policy");
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            Some(material.config()),
            client_binding.clone(),
            Some(Duration::from_secs(5)),
        )
        .with_connection_lifecycle(policy);
        let request = || {
            SessionConsensusWireRequest::try_new(
                client_binding.consensus_identity(),
                client_binding.local_consensus_node_id(),
                SessionConsensusRpcFamily::Vote,
                b"shared-failed-cold-receipt".to_vec(),
            )
            .expect("bounded request")
        };

        let first = {
            let peer = peer.clone();
            let request = request();
            tokio::spawn(async move { peer.call(request).await })
        };
        first_resolution_started.notified().await;
        let second = {
            let peer = peer.clone();
            let request = request();
            tokio::spawn(async move { peer.call(request).await })
        };
        // The resolver cannot finish until explicitly released, so yielding
        // lets the second logical call claim the already connecting attempt.
        tokio::task::yield_now().await;
        assert_eq!(resolutions.load(Ordering::SeqCst), 1);
        release_first_resolution.notify_waiters();

        assert_eq!(
            first.await.expect("join first cold claimant"),
            Err(SessionConsensusPeerError::Unavailable)
        );
        assert_eq!(
            second.await.expect("join second cold claimant"),
            Err(SessionConsensusPeerError::Unavailable)
        );
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            1,
            "joined failed claimants must not consume the receipt into another setup"
        );

        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            peer.call(request()).await,
            Err(SessionConsensusPeerError::Unavailable)
        );
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            2,
            "a distinct later logical call may replace the settled receipt"
        );

        material.rotate();
        assert_eq!(
            peer.call(request()).await,
            Err(SessionConsensusPeerError::Unavailable)
        );
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            3,
            "new material must supersede the old receipt without waiting out its cooldown"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_cooldown_beyond_cold_deadline_returns_once_without_spinning() {
        let (_server_binding, client_binding) = bindings();
        let resolutions = Arc::new(AtomicUsize::new(0));
        let resolver: RemoteAddrResolver = {
            let resolutions = Arc::clone(&resolutions);
            Arc::new(move || {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Box::pin(std::future::pending::<io::Result<SocketAddr>>())
            })
        };
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::ZERO,
        )
        .expect("long reconnect cooldown policy");
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(5)),
        )
        .with_connection_lifecycle(policy);
        let started_at = tokio::time::Instant::now();
        peer.connection_pool
            .reconnect_gate
            .acquire(started_at + Duration::from_secs(1), 0, None)
            .await
            .expect("seed failed reconnect attempt")
            .failed();
        let request = || {
            SessionConsensusWireRequest::try_new(
                client_binding.consensus_identity(),
                client_binding.local_consensus_node_id(),
                SessionConsensusRpcFamily::Vote,
                b"cooldown-no-admission".to_vec(),
            )
            .expect("bounded request")
        };

        assert_eq!(
            peer.call(request()).await,
            Err(SessionConsensusPeerError::Unavailable)
        );
        assert_eq!(tokio::time::Instant::now(), started_at);
        assert_eq!(resolutions.load(Ordering::SeqCst), 0);
        {
            let state = peer.connection_pool.cold_connection.state.lock().await;
            assert!(matches!(
                state.phase,
                ConsensusColdConnectionPhase::Failed {
                    error: SessionConsensusPeerError::Unavailable,
                    ..
                }
            ));
            assert_ne!(state.no_admission_marker, uuid::Uuid::nil());
        }

        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(
            peer.call_with_timeout(request(), Duration::from_millis(100))
                .await,
            Err(SessionConsensusPeerError::Timeout)
        );
        assert_eq!(resolutions.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn claimant_records_explicit_retirement_before_dropping_stale_ready_connection() {
        let (_server_binding, client_binding) = bindings();
        let control = SessionReauthenticationControl::new();
        let resolver: RemoteAddrResolver =
            Arc::new(|| Box::pin(std::future::pending::<io::Result<SocketAddr>>()));
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding,
            Some(Duration::from_secs(1)),
        )
        .with_reauthentication_control(control.clone());
        let staged_epoch = peer.cold_connector().epoch();
        let attempt_id = uuid::Uuid::new_v4();
        let now = tokio::time::Instant::now();
        let lifecycle = ConnectionLifecycle::new(
            peer.lifecycle_policy,
            now,
            None,
            None,
            staged_epoch.reauthentication_generation,
            None,
        )
        .expect("staged connection lifecycle");
        let retirement_probe = lifecycle.clone();
        let (stream, _remote) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(stream);
        peer.connection_pool
            .cold_connection
            .state
            .lock()
            .await
            .phase = ConsensusColdConnectionPhase::Ready {
            attempt_id,
            epoch: staged_epoch,
            connection: Box::new(ConsensusConnection {
                reader: Box::new(reader),
                writer: Box::new(writer),
                response_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
                request_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
                admission_attempt_id: None,
                lifecycle,
                last_successful_correlated_use: None,
                idle_deadline_origin: now,
            }),
        };
        control
            .request_reauthentication()
            .expect("advance staged connection generation");

        assert!(matches!(
            peer.claim_or_start_cold_connection(now + Duration::from_millis(10))
                .await,
            Err(SessionConsensusPeerError::Timeout)
        ));
        assert_eq!(retirement_probe.recorded_retirement_count(), 1);
        assert_eq!(
            retirement_probe.recorded_retirement_reason(),
            Some(RetirementReason::Explicit)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn claimant_records_material_retirement_before_dropping_stale_ready_connection() {
        let (_server_binding, client_binding) = bindings();
        let material = crate::test_support::RotatableClientMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/1",
        );
        let tls_config = material.config();
        let resolver: RemoteAddrResolver =
            Arc::new(|| Box::pin(std::future::pending::<io::Result<SocketAddr>>()));
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            Some(tls_config.clone()),
            client_binding,
            Some(Duration::from_secs(1)),
        );
        let staged_epoch = peer.cold_connector().epoch();
        let attempt_id = uuid::Uuid::new_v4();
        let now = tokio::time::Instant::now();
        let lifecycle = ConnectionLifecycle::new(
            peer.lifecycle_policy,
            now,
            None,
            None,
            staged_epoch.reauthentication_generation,
            staged_epoch.material_epoch,
        )
        .expect("staged connection lifecycle");
        let retirement_probe = lifecycle.clone();
        let (stream, mut remote) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(stream);
        peer.connection_pool
            .cold_connection
            .state
            .lock()
            .await
            .phase = ConsensusColdConnectionPhase::Ready {
            attempt_id,
            epoch: staged_epoch,
            connection: Box::new(ConsensusConnection {
                reader: Box::new(reader),
                writer: Box::new(writer),
                response_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
                request_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
                admission_attempt_id: None,
                lifecycle,
                last_successful_correlated_use: None,
                idle_deadline_origin: now,
            }),
        };
        material.rotate();

        assert!(matches!(
            peer.claim_or_start_cold_connection(now + Duration::from_millis(10))
                .await,
            Err(SessionConsensusPeerError::Timeout)
        ));
        assert_eq!(retirement_probe.recorded_retirement_count(), 1);
        assert_eq!(
            retirement_probe.recorded_retirement_reason(),
            Some(RetirementReason::MaterialEpoch)
        );
        let mut dispatched = Vec::new();
        remote
            .read_to_end(&mut dispatched)
            .await
            .expect("inspect staged connection dispatch");
        assert!(dispatched.is_empty());
    }

    #[cfg(feature = "insecure-test")]
    #[tokio::test(start_paused = true)]
    async fn unproven_cached_lane_does_not_clear_shared_reconnect_cooldown() {
        let (_server_binding, client_binding) = bindings();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::ZERO,
        )
        .expect("lifecycle policy");
        let peer = RemoteSessionConsensusPeer::new_insecure(
            client_binding,
            "127.0.0.1:9".parse().expect("test address"),
            Some(Duration::from_secs(1)),
        )
        .with_connection_lifecycle(policy);
        let now = tokio::time::Instant::now();
        peer.connection_pool
            .reconnect_gate
            .acquire(now + Duration::from_secs(1), 0, None)
            .await
            .expect("seed reconnect attempt")
            .failed();

        let (stream, _remote) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(stream);
        let mut connection = ConsensusConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            response_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            request_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            admission_attempt_id: None,
            lifecycle: ConnectionLifecycle::new(policy, now, None, None, 0, None)
                .expect("connection lifecycle"),
            last_successful_correlated_use: None,
            idle_deadline_origin: now,
        };
        assert!(peer.connection_is_current(&mut connection, now));

        let gate = Arc::clone(&peer.connection_pool.reconnect_gate);
        let waiting = tokio::spawn(async move {
            gate.acquire(now + Duration::from_secs(1), 0, None)
                .await
                .expect("cooled reconnect attempt")
        });
        tokio::task::yield_now().await;
        assert!(
            !waiting.is_finished(),
            "an unproven cached socket must not erase a failed reconnect cooldown"
        );

        tokio::time::advance(Duration::from_millis(99)).await;
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        waiting.await.expect("reconnect admission task").succeeded();
    }

    #[cfg(feature = "insecure-test")]
    #[tokio::test(start_paused = true)]
    async fn cached_consensus_lane_honors_material_rotation_jitter_before_retirement() {
        let (_server_binding, client_binding) = bindings();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_millis(10),
            Duration::from_millis(80),
            Duration::from_secs(10),
        )
        .expect("lifecycle policy");
        let material = crate::test_support::RotatableClientMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/1",
        );
        let tls_config = material.config();
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::pinned("127.0.0.1:9".parse().expect("test address")),
            Some(tls_config.clone()),
            client_binding.clone(),
            Some(Duration::from_secs(1)),
        )
        .with_connection_lifecycle(policy);
        let now = tokio::time::Instant::now();
        let (stream, _remote) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(stream);
        let mut connection = ConsensusConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            response_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            request_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            admission_attempt_id: None,
            lifecycle: ConnectionLifecycle::new(
                policy,
                now,
                None,
                None,
                0,
                Some(tls_config.material_status().epoch()),
            )
            .expect("connection lifecycle"),
            last_successful_correlated_use: None,
            idle_deadline_origin: now,
        };
        let edge_key = directed_connection_key(
            b"consensus",
            client_binding.local_replica_id().as_str(),
            client_binding.remote_replica_id().as_str(),
        );
        let jitter = policy.deterministic_jitter(&edge_key);
        assert!(!jitter.is_zero(), "fixture must exercise a non-zero jitter");

        material.rotate();
        assert!(peer.connection_is_current(&mut connection, now));
        tokio::time::advance(jitter - Duration::from_nanos(1)).await;
        assert!(peer.connection_is_current(&mut connection, tokio::time::Instant::now()));
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert!(!peer.connection_is_current(&mut connection, tokio::time::Instant::now()));
    }

    #[cfg(feature = "insecure-test")]
    #[tokio::test(start_paused = true)]
    async fn cached_consensus_lane_retires_immediately_for_explicit_reauthentication() {
        let (_server_binding, client_binding) = bindings();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_millis(10),
            Duration::from_millis(80),
            Duration::from_secs(30),
        )
        .expect("lifecycle policy");
        let control = SessionReauthenticationControl::new();
        let peer = RemoteSessionConsensusPeer::new_insecure(
            client_binding,
            "127.0.0.1:9".parse().expect("test address"),
            Some(Duration::from_secs(1)),
        )
        .with_connection_lifecycle(policy)
        .with_reauthentication_control(control.clone());
        let now = tokio::time::Instant::now();
        let (stream, _remote) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(stream);
        let mut connection = ConsensusConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            response_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            request_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            admission_attempt_id: None,
            lifecycle: ConnectionLifecycle::new(policy, now, None, None, 0, None)
                .expect("connection lifecycle"),
            last_successful_correlated_use: None,
            idle_deadline_origin: now,
        };

        control
            .request_reauthentication()
            .expect("rotate generation");
        assert!(!peer.connection_is_current(&mut connection, now));
    }

    #[tokio::test(start_paused = true)]
    async fn consensus_epoch_supersession_conserves_connection_attempt_accounting() {
        let (_server_binding, client_binding) = bindings();
        let control = SessionReauthenticationControl::new();
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let attempts = Arc::new(AtomicUsize::new(0));
        let resolver: RemoteAddrResolver = {
            let attempts = Arc::clone(&attempts);
            Arc::new(move || {
                let entered_tx = entered_tx.clone();
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    entered_tx.send(attempt).expect("report resolver entry");
                    std::future::pending::<io::Result<SocketAddr>>().await
                })
            })
        };
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(1)),
        )
        .with_reauthentication_control(control.clone());
        let request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::Vote,
            b"supersede-connect".to_vec(),
        )
        .expect("bounded request");
        let accounting = Arc::new(crate::lifecycle::ConnectionAttemptTestAccounting::default());
        let pool_owner = peer.clone();
        let call = tokio::spawn(crate::lifecycle::CONNECTION_ATTEMPT_TEST_ACCOUNTING.scope(
            Arc::clone(&accounting),
            async move { peer.call(request).await },
        ));

        assert_eq!(entered_rx.recv().await, Some(0));
        control.request_reauthentication().expect("advance epoch");
        assert_eq!(entered_rx.recv().await, Some(1));
        assert_eq!(accounting.snapshot(), (2, 1, 1, 0));

        call.abort();
        assert!(call
            .await
            .expect_err("call must be cancelled")
            .is_cancelled());
        assert_eq!(
            accounting.snapshot(),
            (2, 1, 1, 0),
            "cancelling the caller must leave its detached replacement setup alive"
        );
        drop(pool_owner);
        tokio::time::timeout(Duration::from_secs(1), async {
            while accounting.snapshot().1 < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pool shutdown must settle the detached replacement setup");
        assert_eq!(accounting.snapshot(), (2, 2, 1, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn active_remote_retirement_probe_is_superseded_without_waiting_for_its_deadline() {
        let (_server_binding, client_binding) = bindings();
        let control = SessionReauthenticationControl::new();
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let attempts = Arc::new(AtomicUsize::new(0));
        let resolver: RemoteAddrResolver = {
            let attempts = Arc::clone(&attempts);
            Arc::new(move || {
                let entered_tx = entered_tx.clone();
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    entered_tx.send(attempt).expect("report resolver entry");
                    std::future::pending::<io::Result<SocketAddr>>().await
                })
            })
        };
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(1)),
        )
        .with_reauthentication_control(control.clone());
        let old_epoch = peer.cold_connector().epoch();
        peer.connection_pool
            .cold_connection
            .seed_credential_retirement_probe(
                old_epoch,
                None,
                None,
                RetirementReason::PeerLeafExpiry,
            )
            .await;
        let request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::Vote,
            b"supersede-active-retirement-probe".to_vec(),
        )
        .expect("bounded request");
        let accounting = Arc::new(crate::lifecycle::ConnectionAttemptTestAccounting::default());
        let pool_owner = peer.clone();
        let call = tokio::spawn(crate::lifecycle::CONNECTION_ATTEMPT_TEST_ACCOUNTING.scope(
            Arc::clone(&accounting),
            async move { peer.call(request).await },
        ));

        assert_eq!(entered_rx.recv().await, Some(0));
        {
            let state = pool_owner
                .connection_pool
                .cold_connection
                .state
                .lock()
                .await;
            assert!(matches!(
                state.phase,
                ConsensusColdConnectionPhase::Connecting {
                    epoch,
                    remote_retirement_probe: true,
                    ..
                } if epoch == old_epoch
            ));
        }

        control.request_reauthentication().expect("advance epoch");
        assert_eq!(entered_rx.recv().await, Some(1));
        let new_epoch = pool_owner.cold_connector().epoch();
        let state = pool_owner
            .connection_pool
            .cold_connection
            .state
            .lock()
            .await;
        assert!(matches!(
            state.phase,
            ConsensusColdConnectionPhase::Connecting {
                epoch,
                remote_retirement_probe: false,
                ..
            } if epoch == new_epoch
        ));
        assert_eq!(
            accounting.snapshot(),
            (2, 1, 1, 0),
            "the live claimant owns exactly one new-epoch setup while the old active probe terminalizes as superseded"
        );
        drop(state);

        call.abort();
        assert!(call
            .await
            .expect_err("call must be cancelled")
            .is_cancelled());
        assert_eq!(
            accounting.snapshot(),
            (2, 1, 1, 0),
            "caller cancellation must not supersede the detached new-epoch setup"
        );
        drop(pool_owner);
        tokio::time::timeout(Duration::from_secs(1), async {
            while accounting.snapshot().1 < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pool shutdown must settle the detached new-epoch setup");
        assert_eq!(accounting.snapshot(), (2, 2, 1, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn active_remote_retirement_probe_is_superseded_by_material_epoch_without_waiting_for_its_deadline(
    ) {
        let (_server_binding, client_binding) = bindings();
        let material = crate::test_support::RotatableClientMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/client",
        );
        let tls_config = material.config();
        let reauthentication = SessionReauthenticationControl::new();
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let attempts = Arc::new(AtomicUsize::new(0));
        let resolver: RemoteAddrResolver = {
            let attempts = Arc::clone(&attempts);
            Arc::new(move || {
                let entered_tx = entered_tx.clone();
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    entered_tx.send(attempt).expect("report resolver entry");
                    std::future::pending::<io::Result<SocketAddr>>().await
                })
            })
        };
        let peer = RemoteSessionConsensusPeer::new_with_resolver(
            client_binding.clone(),
            resolver,
            tls_config.clone(),
            Some(Duration::from_secs(1)),
        )
        .with_reauthentication_control(reauthentication.clone());
        let old_epoch = peer.cold_connector().epoch();
        assert_eq!(
            old_epoch.material_epoch,
            Some(tls_config.material_status().epoch())
        );
        peer.connection_pool
            .cold_connection
            .seed_credential_retirement_probe(
                old_epoch,
                None,
                None,
                RetirementReason::PeerLeafExpiry,
            )
            .await;
        let request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::Vote,
            b"supersede-active-retirement-probe-material-epoch".to_vec(),
        )
        .expect("bounded request");
        let accounting = Arc::new(crate::lifecycle::ConnectionAttemptTestAccounting::default());
        let pool_owner = peer.clone();
        let call = tokio::spawn(crate::lifecycle::CONNECTION_ATTEMPT_TEST_ACCOUNTING.scope(
            Arc::clone(&accounting),
            async move { peer.call(request).await },
        ));

        assert_eq!(entered_rx.recv().await, Some(0));
        let (old_attempt_id, old_attempt_deadline, old_receipt) = {
            let state = pool_owner
                .connection_pool
                .cold_connection
                .state
                .lock()
                .await;
            match &state.phase {
                ConsensusColdConnectionPhase::Connecting {
                    attempt_id,
                    epoch,
                    attempt_deadline,
                    receipt,
                    remote_retirement_probe,
                } => {
                    assert_eq!(*epoch, old_epoch);
                    assert!(remote_retirement_probe);
                    (*attempt_id, *attempt_deadline, Arc::clone(receipt))
                }
                _ => panic!("expected an active old-epoch retirement probe"),
            }
        };
        let rotated_at = tokio::time::Instant::now();
        material.rotate();
        assert_eq!(
            reauthentication.generation(),
            old_epoch.reauthentication_generation,
            "the causal successor is authenticated TLS material, not reauthentication"
        );

        assert_eq!(entered_rx.recv().await, Some(1));
        let new_epoch = pool_owner.cold_connector().epoch();
        assert_eq!(
            new_epoch.reauthentication_generation, old_epoch.reauthentication_generation,
            "material rotation must not advance reauthentication"
        );
        assert!(new_epoch.is_strictly_newer_than(old_epoch));
        assert!(
            tokio::time::Instant::now() < old_attempt_deadline,
            "the replacement must start before the active old probe's original deadline"
        );
        assert_eq!(
            tokio::time::Instant::now(),
            rotated_at,
            "the material successor must start without advancing paused time"
        );
        let state = pool_owner
            .connection_pool
            .cold_connection
            .state
            .lock()
            .await;
        assert!(matches!(
            state.phase,
            ConsensusColdConnectionPhase::Connecting {
                attempt_id,
                epoch,
                remote_retirement_probe: false,
                ..
            } if attempt_id != old_attempt_id && epoch == new_epoch
        ));
        drop(state);
        assert_eq!(
            old_receipt.terminal(),
            Some(SessionConsensusPeerError::Unavailable),
            "the superseded old probe must terminalize its exact stale receipt"
        );
        assert_eq!(
            accounting.snapshot(),
            (2, 1, 1, 0),
            "the live original claimant starts one material-successor attempt while the old probe records exactly one terminal supersession"
        );
        assert!(
            !call.is_finished(),
            "the original claimant remains alive while its new material-epoch attempt connects"
        );

        call.abort();
        assert!(call
            .await
            .expect_err("call must be cancelled")
            .is_cancelled());
        assert_eq!(
            accounting.snapshot(),
            (2, 1, 1, 0),
            "cancelling the original caller must not terminalize the material-successor attempt"
        );
        drop(pool_owner);
        tokio::time::timeout(Duration::from_secs(1), async {
            while accounting.snapshot().1 < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pool shutdown must settle the detached material-successor attempt");
        assert_eq!(accounting.snapshot(), (2, 2, 1, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn consensus_soft_timeout_classifies_pending_connect_without_abandoning() {
        let (_server_binding, client_binding) = bindings();
        let resolver: RemoteAddrResolver =
            Arc::new(|| Box::pin(std::future::pending::<io::Result<SocketAddr>>()));
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(30)),
        );
        let request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::AppendEntries,
            b"openraft-soft-timeout".to_vec(),
        )
        .expect("bounded request");
        let accounting = Arc::new(crate::lifecycle::ConnectionAttemptTestAccounting::default());
        let started_at = tokio::time::Instant::now();

        let result = crate::lifecycle::CONNECTION_ATTEMPT_TEST_ACCOUNTING
            .scope(Arc::clone(&accounting), async {
                peer.call_with_timeout(request, Duration::from_millis(100))
                    .await
            })
            .await;

        assert_eq!(result, Err(SessionConsensusPeerError::Timeout));
        let elapsed = tokio::time::Instant::now().duration_since(started_at);
        let expected = Duration::from_millis(100).saturating_mul(2) / 3;
        assert!(
            elapsed >= expected && elapsed <= expected + Duration::from_millis(1),
            "the pending cold phase must leave one third of the soft TTL undispatched: elapsed={elapsed:?}, expected={expected:?}"
        );
        let (attempts, terminals, superseded, abandoned) = accounting.snapshot();
        assert!(attempts > 0, "the stalled resolver must start an attempt");
        assert_eq!(terminals, 0);
        assert_eq!(superseded, 0);
        assert_eq!(abandoned, 0);
        tokio::time::advance(DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout()).await;
        tokio::task::yield_now().await;
        assert_eq!(accounting.snapshot(), (attempts, attempts, 0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn configured_ceiling_also_reserves_post_connect_rpc_time() {
        let (_server_binding, client_binding) = bindings();
        let resolver: RemoteAddrResolver =
            Arc::new(|| Box::pin(std::future::pending::<io::Result<SocketAddr>>()));
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding.clone(),
            Some(Duration::from_millis(50)),
        );
        let request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::AppendEntries,
            b"configured-soft-ceiling".to_vec(),
        )
        .expect("bounded request");
        let accounting = Arc::new(crate::lifecycle::ConnectionAttemptTestAccounting::default());
        let started_at = tokio::time::Instant::now();

        let result = crate::lifecycle::CONNECTION_ATTEMPT_TEST_ACCOUNTING
            .scope(Arc::clone(&accounting), async {
                peer.call_with_timeout(request, Duration::from_millis(500))
                    .await
            })
            .await;

        assert_eq!(result, Err(SessionConsensusPeerError::Timeout));
        let elapsed = tokio::time::Instant::now().duration_since(started_at);
        let expected = Duration::from_millis(50).saturating_mul(2) / 3;
        assert!(
            elapsed >= expected && elapsed <= expected + Duration::from_millis(1),
            "the configured cold phase exceeded its proportional allocation: elapsed={elapsed:?}, expected={expected:?}"
        );
        let (attempts, terminals, superseded, abandoned) = accounting.snapshot();
        assert!(attempts > 0, "the stalled resolver must start an attempt");
        assert_eq!(terminals, 0);
        assert_eq!(superseded, 0);
        assert_eq!(abandoned, 0);
        drop(peer);
        tokio::time::timeout(Duration::from_secs(1), async {
            while accounting.snapshot().1 < attempts {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pool shutdown must settle detached attempt accounting");
        assert_eq!(accounting.snapshot(), (attempts, attempts, 0, attempts));
    }

    #[tokio::test(start_paused = true)]
    async fn cold_consensus_epoch_change_wakes_reconnect_cooldown() {
        let (_server_binding, client_binding) = bindings();
        let control = SessionReauthenticationControl::new();
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let entered_tx = entered_tx.clone();
            Box::pin(async move {
                entered_tx.send(()).expect("report resolver entry");
                std::future::pending::<io::Result<SocketAddr>>().await
            })
        });
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .expect("lifecycle policy");
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(5)),
        )
        .with_connection_lifecycle(policy)
        .with_reauthentication_control(control.clone());
        let started_at = tokio::time::Instant::now();
        peer.connection_pool
            .reconnect_gate
            .acquire(
                started_at + Duration::from_secs(2),
                control.generation(),
                None,
            )
            .await
            .expect("seed reconnect attempt")
            .failed();
        let request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::Vote,
            b"cold-epoch-wake".to_vec(),
        )
        .expect("bounded request");
        let call = tokio::spawn(async move { peer.call(request).await });
        tokio::task::yield_now().await;
        assert!(
            entered_rx.try_recv().is_err(),
            "the old epoch cooldown must initially hold a cold consensus caller"
        );

        control.request_reauthentication().expect("advance epoch");
        assert_eq!(entered_rx.recv().await, Some(()));
        assert_eq!(
            tokio::time::Instant::now(),
            started_at,
            "the new epoch must bypass the old cooldown without advancing time"
        );

        call.abort();
        assert!(call
            .await
            .expect_err("call must be cancelled")
            .is_cancelled());
    }

    fn test_consensus_lifecycle_policy() -> ConnectionLifecyclePolicy {
        ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_millis(1),
            Duration::from_millis(5),
            Duration::ZERO,
        )
        .expect("test consensus lifecycle policy")
    }

    async fn valid_consensus_hello_bytes(binding: &RemoteReplicaBinding) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_frame(
            &mut bytes,
            &SessionConsensusBootstrapRequest::Hello(SessionConsensusBootstrapHello {
                transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
                contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
                sender_replica_id: binding.local_replica_id().as_str().to_owned(),
                expected_server_replica_id: binding.remote_replica_id().as_str().to_owned(),
                identity: binding.consensus_identity(),
                sender_node_id: binding.local_consensus_node_id(),
                expected_server_node_id: binding.remote_consensus_node_id(),
                handshake_nonce: uuid::Uuid::nil(),
                requested_response_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
            }),
        )
        .await
        .expect("encode valid consensus Hello");
        bytes
    }

    fn connection_outcome_metrics() -> crate::test_support::ConnectionOutcomeMetricSnapshot {
        crate::test_support::CONNECTION_OUTCOME_TEST_ACCOUNTING
            .try_with(|accounting| accounting.snapshot())
            .expect("connection outcome accounting scope")
    }

    fn record_test_idle_retirement() {
        let lifecycle = ConnectionLifecycle::new(
            test_consensus_lifecycle_policy(),
            tokio::time::Instant::now(),
            None,
            None,
            0,
            None,
        )
        .expect("test connection lifecycle");
        lifecycle.record_forced_retirement(RetirementReason::IdleTimeout);
    }

    #[tokio::test]
    async fn connection_outcome_delta_isolated_from_writer_outside_test_scope() {
        let accounting = Arc::new(crate::test_support::ConnectionOutcomeTestAccounting::default());
        crate::test_support::CONNECTION_OUTCOME_TEST_ACCOUNTING
            .scope(accounting, async {
                let before = connection_outcome_metrics();

                tokio::spawn(async { record_test_idle_retirement() })
                    .await
                    .expect("outside metric writer");
                record_test_idle_retirement();

                let after = connection_outcome_metrics();
                assert_eq!(after.idle_retirements, before.idle_retirements + 1);
                assert_eq!(after.timeout_failures, before.timeout_failures);
                assert_eq!(after.successes, before.successes);
                assert_eq!(after.drain_started, before.drain_started + 1);
                assert_eq!(after.drain_completed, before.drain_completed + 1);
            })
            .await;
    }

    async fn wait_for_drain_completion(minimum: u64) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while connection_outcome_metrics().drain_completed < minimum {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aborted consensus lifecycle task must release its draining metric");
    }

    async fn dispatch_after_authentication(
        trailing_frame_bytes: &[u8],
    ) -> (Result<(), ProtocolError>, Vec<u8>) {
        let (server_binding, client_binding) = bindings();
        let reauthentication = SessionReauthenticationControl::new();
        let pending = PendingConsensusLifecycle::insecure(reauthentication.generation());
        let mut input = valid_consensus_hello_bytes(&client_binding).await;
        input.extend_from_slice(trailing_frame_bytes);
        let (mut peer, mut reader) = tokio::io::duplex(input.len() + 16);
        peer.write_all(&input)
            .await
            .expect("write authenticated consensus test input");
        let mut writer = Vec::new();
        let cancellation = AtomicBool::new(false);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let result = dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            pending,
            SessionMembershipAdmission::from_current_binding(server_binding),
            Arc::new(CountingHandler(AtomicUsize::new(0))),
            Arc::new(Semaphore::new(1)),
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_millis(20),
            tokio::time::Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
            &cancellation,
            shutdown_rx,
            test_consensus_lifecycle_policy(),
            reauthentication,
        )
        .await;
        drop(peer);
        (result, writer)
    }

    async fn assert_consensus_server_distinguishes_authenticated_idle_from_active_frame_timeout() {
        let before_idle = connection_outcome_metrics();
        let (idle_result, acknowledgement) = dispatch_after_authentication(&[]).await;
        record_consensus_server_connection_outcome(&idle_result);
        idle_result.expect("byte-idle authenticated consensus connection is a policy retirement");
        wait_for_drain_completion(before_idle.drain_completed + 1).await;
        let after_idle = connection_outcome_metrics();
        assert_eq!(
            after_idle.idle_retirements,
            before_idle.idle_retirements + 1
        );
        assert_eq!(after_idle.timeout_failures, before_idle.timeout_failures);
        assert!(after_idle.successes > before_idle.successes);
        assert!(after_idle.drain_started > before_idle.drain_started);
        assert!(after_idle.drain_completed > before_idle.drain_completed);
        let mut acknowledgement = std::io::Cursor::new(acknowledgement);
        assert!(matches!(
            read_frame::<_, SessionConsensusBootstrapResponse>(
                &mut acknowledgement,
                MAX_HANDSHAKE_FRAME_SIZE,
            )
            .await
            .expect("decode authenticated consensus acknowledgement"),
            SessionConsensusBootstrapResponse::Accepted(_)
        ));

        let before_partial = connection_outcome_metrics();
        let (partial_result, _acknowledgement) = dispatch_after_authentication(&[0]).await;
        assert!(matches!(
            partial_result,
            Err(ProtocolError::Io(ref error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        record_consensus_server_connection_outcome(&partial_result);
        let after_partial = connection_outcome_metrics();
        assert_eq!(
            after_partial.idle_retirements, before_partial.idle_retirements,
            "one active consensus frame byte must preserve the slowloris timeout failure"
        );
        assert!(after_partial.timeout_failures > before_partial.timeout_failures);

        let before_handshake = connection_outcome_metrics();
        let (server_binding, _client_binding) = bindings();
        let reauthentication = SessionReauthenticationControl::new();
        let pending = PendingConsensusLifecycle::insecure(reauthentication.generation());
        let (_peer, mut reader) = tokio::io::duplex(16);
        let mut writer = Vec::new();
        let cancellation = AtomicBool::new(false);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handshake_result = dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            pending,
            SessionMembershipAdmission::from_current_binding(server_binding),
            Arc::new(CountingHandler(AtomicUsize::new(0))),
            Arc::new(Semaphore::new(1)),
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_millis(20),
            tokio::time::Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
            &cancellation,
            shutdown_rx,
            test_consensus_lifecycle_policy(),
            reauthentication,
        )
        .await;
        assert!(matches!(
            handshake_result,
            Err(ProtocolError::Io(ref error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        record_consensus_server_connection_outcome(&handshake_result);
        let after_handshake = connection_outcome_metrics();
        assert_eq!(
            after_handshake.idle_retirements,
            before_handshake.idle_retirements
        );
        assert!(after_handshake.timeout_failures > before_handshake.timeout_failures);
    }

    #[tokio::test]
    async fn consensus_server_distinguishes_authenticated_idle_from_active_frame_timeout() {
        let accounting = Arc::new(crate::test_support::ConnectionOutcomeTestAccounting::default());
        crate::test_support::CONNECTION_OUTCOME_TEST_ACCOUNTING
            .scope(
                accounting,
                assert_consensus_server_distinguishes_authenticated_idle_from_active_frame_timeout(
                ),
            )
            .await;
    }

    #[tokio::test]
    async fn consensus_pre_hello_generation_retirement_emits_one_no_dispatch_control() {
        let (server_binding, _client_binding) = bindings();
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let reauthentication = SessionReauthenticationControl::new();
        let pending = PendingConsensusLifecycle::insecure(reauthentication.generation());
        reauthentication
            .request_reauthentication()
            .expect("advance consensus test generation");
        let mut reader = tokio::io::empty();
        let mut writer = Vec::new();
        let cancellation = AtomicBool::new(false);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            pending,
            SessionMembershipAdmission::from_current_binding(server_binding),
            handler.clone(),
            Arc::new(Semaphore::new(1)),
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_secs(1),
            tokio::time::Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
            &cancellation,
            shutdown_rx,
            test_consensus_lifecycle_policy(),
            reauthentication,
        )
        .await
        .expect("pre-Hello consensus retirement is an expected control exchange");

        let mut encoded = std::io::Cursor::new(writer);
        assert!(matches!(
            read_frame::<_, SessionConsensusBootstrapResponse>(
                &mut encoded,
                MAX_HANDSHAKE_FRAME_SIZE,
            )
            .await
            .expect("read consensus retirement control"),
            SessionConsensusBootstrapResponse::Rejected(SessionConsensusPeerError::Rejected)
        ));
        assert_eq!(
            usize::try_from(encoded.position()).expect("cursor position"),
            encoded.get_ref().len(),
            "exactly one consensus control frame must be emitted"
        );
        assert_eq!(handler.0.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn consensus_expiry_crossing_at_final_zero_ack_boundary_emits_only_retirement_control() {
        let (server_binding, client_binding) = bindings();
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let reauthentication = SessionReauthenticationControl::new();
        let mut pending = PendingConsensusLifecycle::insecure(reauthentication.generation());
        pending.expire_at_final_ack_boundary = true;
        let mut input = valid_consensus_hello_bytes(&client_binding).await;
        let hello_bytes = input.len();
        let request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::Vote,
            b"must-not-dispatch".to_vec(),
        )
        .expect("bounded consensus request");
        write_frame(
            &mut input,
            &SessionConsensusTransportRequest::Call {
                call_id: uuid::Uuid::nil(),
                request,
            },
        )
        .await
        .expect("append Openraft call behind valid consensus Hello");
        let mut reader = std::io::Cursor::new(input);
        let mut writer = Vec::new();
        let cancellation = AtomicBool::new(false);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            pending,
            SessionMembershipAdmission::from_current_binding(server_binding),
            handler.clone(),
            Arc::new(Semaphore::new(1)),
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_secs(1),
            tokio::time::Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
            &cancellation,
            shutdown_rx,
            test_consensus_lifecycle_policy(),
            reauthentication,
        )
        .await
        .expect("final-boundary consensus expiry is an expected control exchange");

        assert_eq!(
            usize::try_from(reader.position()).expect("reader position"),
            hello_bytes,
            "no Openraft call bytes may be read or dispatched"
        );
        let mut encoded = std::io::Cursor::new(writer);
        assert!(matches!(
            read_frame::<_, SessionConsensusBootstrapResponse>(
                &mut encoded,
                MAX_HANDSHAKE_FRAME_SIZE,
            )
            .await
            .expect("read final-boundary consensus retirement control"),
            SessionConsensusBootstrapResponse::Rejected(SessionConsensusPeerError::Rejected)
        ));
        assert_eq!(
            usize::try_from(encoded.position()).expect("writer position"),
            encoded.get_ref().len(),
            "one complete retirement control and zero Accepted bytes must be emitted"
        );
        assert_eq!(handler.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn consensus_post_hello_pre_admit_material_change_is_recorded_once() {
        let material = crate::test_support::RotatableServerMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/server",
        );
        let tls_config = material.config();
        let handshake = tls_config
            .begin_handshake()
            .expect("capture pre-rotation consensus material");
        let established_at = tokio::time::Instant::now();
        let pending = PendingConsensusLifecycle {
            handshake: Some(handshake),
            tls_config: Some(tls_config),
            local_certificate_expiry: None,
            peer_certificate_expiry: None,
            established_at,
            generation: 0,
            expire_at_final_ack_boundary: false,
        };
        let policy = test_consensus_lifecycle_policy();
        let bootstrap_lifecycle = pending
            .provisional_lifecycle(policy)
            .expect("provisional post-TLS consensus lifecycle");

        // This admission gate runs after the consensus Hello has passed its
        // identity/scope checks and before Accepted or any Openraft call.
        material.rotate();
        let reason = match pending.admit(policy, 0) {
            Err(PendingConsensusAdmissionError::Retired(reason)) => reason,
            Err(PendingConsensusAdmissionError::Protocol(error)) => {
                panic!("consensus material race was misclassified as protocol: {error}")
            }
            Ok(_) => panic!("stale consensus handshake snapshot must not be admitted"),
        };
        assert_eq!(reason, RetirementReason::MaterialEpoch);
        bootstrap_lifecycle.record_forced_retirement(reason);
        bootstrap_lifecycle.record_forced_retirement(reason);
        assert_eq!(
            bootstrap_lifecycle.recorded_retirement_count(),
            1,
            "the consensus admission race must publish one retirement outcome"
        );
    }

    #[tokio::test]
    async fn consensus_rotation_after_ack_bytes_start_never_appends_retirement_control() {
        let (server_binding, client_binding) = bindings();
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let reauthentication = SessionReauthenticationControl::new();
        let pending = PendingConsensusLifecycle::insecure(reauthentication.generation());
        let mut reader = std::io::Cursor::new(valid_consensus_hello_bytes(&client_binding).await);
        let bytes = Arc::new(StdMutex::new(Vec::new()));
        let wrote_first_chunk = Arc::new(Notify::new());
        let first_chunk = wrote_first_chunk.notified();
        tokio::pin!(first_chunk);
        let mut writer = PartialConsensusAcknowledgementWriter {
            bytes: Arc::clone(&bytes),
            first_chunk_written: false,
            wrote_first_chunk: Arc::clone(&wrote_first_chunk),
        };
        let cancellation = AtomicBool::new(false);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let dispatch = dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            pending,
            SessionMembershipAdmission::from_current_binding(server_binding),
            handler.clone(),
            Arc::new(Semaphore::new(1)),
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_secs(1),
            tokio::time::Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
            &cancellation,
            shutdown_rx,
            test_consensus_lifecycle_policy(),
            reauthentication.clone(),
        );
        tokio::pin!(dispatch);
        tokio::select! {
            _ = &mut first_chunk => {}
            result = &mut dispatch => panic!("consensus dispatch ended before partial Ack: {result:?}"),
        }
        reauthentication
            .request_reauthentication()
            .expect("retire consensus connection after Ack transmission starts");
        tokio::time::timeout(Duration::from_secs(1), &mut dispatch)
            .await
            .expect("partial consensus Ack retirement must close promptly")
            .expect("partial consensus Ack retirement is a conservative close");

        let written = bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            written.len(),
            2,
            "only the partial Ack prefix may be written"
        );
        assert!(!String::from_utf8_lossy(&written).contains("Rejected"));
        assert_eq!(handler.0.load(Ordering::Relaxed), 0);
    }

    async fn raw_consensus_connection(
        addr: SocketAddr,
        binding: &RemoteReplicaBinding,
    ) -> TcpStream {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let nonce = uuid::Uuid::new_v4();
        write_frame(
            &mut stream,
            &SessionConsensusBootstrapRequest::Hello(SessionConsensusBootstrapHello {
                transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
                contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
                sender_replica_id: binding.local_replica_id().as_str().to_owned(),
                expected_server_replica_id: binding.remote_replica_id().as_str().to_owned(),
                identity: binding.consensus_identity(),
                sender_node_id: binding.local_consensus_node_id(),
                expected_server_node_id: binding.remote_consensus_node_id(),
                handshake_nonce: nonce,
                requested_response_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
            }),
        )
        .await
        .expect("write Hello");
        let response: SessionConsensusBootstrapResponse =
            read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read acknowledgement");
        assert!(matches!(
            response,
            SessionConsensusBootstrapResponse::Accepted(SessionConsensusBootstrapAck {
                handshake_nonce,
                ..
            }) if handshake_nonce == nonce
        ));
        stream
    }

    async fn bootstrap_retirement_then_consensus_response_server(
        server_binding: RemoteReplicaBinding,
    ) -> (SocketAddr, tokio::task::JoinHandle<(usize, usize)>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind consensus bootstrap-retirement listener");
        let address = listener
            .local_addr()
            .expect("consensus bootstrap-retirement address");
        let task = tokio::spawn(async move {
            let mut application_calls = 0;
            for attempt in 0..2 {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("accept consensus bootstrap client");
                let hello: SessionConsensusBootstrapRequest =
                    read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                        .await
                        .expect("read consensus bootstrap Hello");
                let SessionConsensusBootstrapRequest::Hello(hello) = hello;
                if attempt == 0 {
                    write_frame(
                        &mut stream,
                        &SessionConsensusBootstrapResponse::Rejected(
                            SessionConsensusPeerError::Rejected,
                        ),
                    )
                    .await
                    .expect("write consensus pre-admission retirement control");
                    if matches!(
                        tokio::time::timeout(
                            Duration::from_millis(100),
                            read_frame::<_, SessionConsensusTransportRequest>(
                                &mut stream,
                                MAX_NEGOTIATED_FRAME_SIZE,
                            ),
                        )
                        .await,
                        Ok(Ok(_))
                    ) {
                        application_calls += 1;
                    }
                    continue;
                }
                write_frame(
                    &mut stream,
                    &SessionConsensusBootstrapResponse::Accepted(SessionConsensusBootstrapAck {
                        transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
                        contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
                        identity: hello.identity,
                        server_node_id: server_binding.remote_consensus_node_id(),
                        accepted_sender_node_id: hello.sender_node_id,
                        handshake_nonce: hello.handshake_nonce,
                        accepted_response_frame_size: hello.requested_response_frame_size,
                        server_request_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
                    }),
                )
                .await
                .expect("write fresh consensus acknowledgement");
                let call: SessionConsensusTransportRequest =
                    read_frame(&mut stream, MAX_NEGOTIATED_FRAME_SIZE)
                        .await
                        .expect("read fresh consensus call");
                let SessionConsensusTransportRequest::Call { call_id, request } = call else {
                    panic!("expected ordinary consensus call");
                };
                application_calls += 1;
                write_frame(
                    &mut stream,
                    &SessionConsensusTransportResponse::Call {
                        call_id,
                        response: SessionConsensusWireResponse {
                            result: Ok(request.payload),
                        },
                    },
                )
                .await
                .expect("write fresh consensus response");
            }
            (2, application_calls)
        });
        (address, task)
    }

    async fn repeated_bootstrap_retirement_then_later_call_recovery_server(
        server_binding: RemoteReplicaBinding,
    ) -> (SocketAddr, tokio::task::JoinHandle<(usize, usize)>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind repeated consensus bootstrap-retirement listener");
        let address = listener
            .local_addr()
            .expect("repeated consensus bootstrap-retirement address");
        let task = tokio::spawn(async move {
            let mut application_calls = 0;
            for attempt in 0..4 {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("accept repeated consensus bootstrap client");
                let hello: SessionConsensusBootstrapRequest =
                    read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                        .await
                        .expect("read repeated consensus bootstrap Hello");
                let SessionConsensusBootstrapRequest::Hello(hello) = hello;
                if attempt < 3 {
                    write_frame(
                        &mut stream,
                        &SessionConsensusBootstrapResponse::Rejected(
                            SessionConsensusPeerError::Rejected,
                        ),
                    )
                    .await
                    .expect("write repeated consensus pre-admission retirement control");
                    if matches!(
                        tokio::time::timeout(
                            Duration::from_millis(100),
                            read_frame::<_, SessionConsensusTransportRequest>(
                                &mut stream,
                                MAX_NEGOTIATED_FRAME_SIZE,
                            ),
                        )
                        .await,
                        Ok(Ok(_))
                    ) {
                        application_calls += 1;
                    }
                    continue;
                }
                write_frame(
                    &mut stream,
                    &SessionConsensusBootstrapResponse::Accepted(SessionConsensusBootstrapAck {
                        transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
                        contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
                        identity: hello.identity,
                        server_node_id: server_binding.remote_consensus_node_id(),
                        accepted_sender_node_id: hello.sender_node_id,
                        handshake_nonce: hello.handshake_nonce,
                        accepted_response_frame_size: hello.requested_response_frame_size,
                        server_request_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
                    }),
                )
                .await
                .expect("write post-epoch consensus acknowledgement");
                let call: SessionConsensusTransportRequest =
                    read_frame(&mut stream, MAX_NEGOTIATED_FRAME_SIZE)
                        .await
                        .expect("read post-epoch consensus call");
                let SessionConsensusTransportRequest::Call { call_id, request } = call else {
                    panic!("expected ordinary consensus call");
                };
                application_calls += 1;
                write_frame(
                    &mut stream,
                    &SessionConsensusTransportResponse::Call {
                        call_id,
                        response: SessionConsensusWireResponse {
                            result: Ok(request.payload),
                        },
                    },
                )
                .await
                .expect("write post-epoch consensus response");
            }
            (4, application_calls)
        });
        (address, task)
    }

    #[tokio::test]
    async fn consensus_bootstrap_retirement_requires_a_later_logical_call() {
        let (_server_binding, client_binding) = bindings();
        let (address, server) =
            bootstrap_retirement_then_consensus_response_server(client_binding.clone()).await;
        let resolve: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolve),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(2)),
        )
        .with_connection_lifecycle(
            ConnectionLifecyclePolicy::try_new(
                Duration::from_secs(10),
                Duration::from_secs(1),
                Duration::from_millis(1),
                Duration::from_millis(5),
                Duration::ZERO,
            )
            .expect("test consensus lifecycle policy"),
        );
        let request = || {
            SessionConsensusWireRequest::try_new(
                client_binding.consensus_identity(),
                client_binding.local_consensus_node_id(),
                SessionConsensusRpcFamily::Vote,
                b"fresh-consensus-route".to_vec(),
            )
            .expect("bounded consensus request")
        };

        assert_eq!(
            peer.call(request()).await,
            Err(SessionConsensusPeerError::Unavailable),
            "an authenticated no-Call receipt must report pre-Call unavailability"
        );
        make_remote_retirement_probe_due(&peer).await;
        assert_eq!(
            peer.call(request()).await,
            Ok(SessionConsensusWireResponse {
                result: Ok(b"fresh-consensus-route".to_vec()),
            }),
            "a genuinely later logical call may recover the same epoch"
        );
        assert_eq!(
            server.await.expect("consensus bootstrap-retirement server"),
            (2, 1),
            "the retired route must receive no Openraft call and the fresh route exactly one"
        );
    }

    #[tokio::test]
    async fn remote_retirement_probe_gate_prevents_the_prior_operation_rate_setup_storm() {
        let (_server_binding, client_binding) = bindings();
        let (address, server) =
            repeated_bootstrap_retirement_then_later_call_recovery_server(client_binding.clone())
                .await;
        let resolutions = Arc::new(AtomicUsize::new(0));
        let resolve: RemoteAddrResolver = {
            let resolutions = Arc::clone(&resolutions);
            Arc::new(move || {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { Ok(address) })
            })
        };
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolve),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(10)),
        )
        .with_connection_lifecycle(
            ConnectionLifecyclePolicy::try_new(
                Duration::from_secs(10),
                Duration::from_secs(1),
                Duration::from_millis(1),
                Duration::from_millis(5),
                Duration::ZERO,
            )
            .expect("test consensus lifecycle policy"),
        );
        let request = || {
            SessionConsensusWireRequest::try_new(
                client_binding.consensus_identity(),
                client_binding.local_consensus_node_id(),
                SessionConsensusRpcFamily::Vote,
                b"bounded-consensus-retirement".to_vec(),
            )
            .expect("bounded request")
        };

        assert_eq!(
            peer.call(request()).await,
            Err(SessionConsensusPeerError::Unavailable)
        );
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            1,
            "one logical call performs exactly one physical setup"
        );

        assert_eq!(
            peer.call_with_timeout(request(), Duration::from_millis(100))
                .await,
            Err(SessionConsensusPeerError::Unavailable),
            "a caller that cannot reach the fixed boundary retains a prompt pre-Call no-admission result"
        );
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            1,
            "a short inside-window caller performs zero physical setups"
        );

        set_remote_retirement_probe_boundary(
            &peer,
            tokio::time::Instant::now() + Duration::from_millis(100),
        )
        .await;
        assert_eq!(
            peer.call_with_timeout(
                request(),
                DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout(),
            )
            .await,
            Err(SessionConsensusPeerError::Unavailable),
            "an Openraft-sized caller stays prompt even when its deadline crosses the probe boundary"
        );
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            1,
            "a caller without a complete post-boundary cold budget performs zero physical setups"
        );
        set_remote_retirement_probe_boundary(
            &peer,
            tokio::time::Instant::now() + DURABLE_CONSENSUS_REMOTE_RETIREMENT_PROBE_INTERVAL,
        )
        .await;

        let first_blocked = {
            let peer = peer.clone();
            let request = request();
            tokio::spawn(async move { peer.call(request).await })
        };
        let second_blocked = {
            let peer = peer.clone();
            let request = request();
            tokio::spawn(async move { peer.call(request).await })
        };
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        for blocked in [&first_blocked, &second_blocked] {
            assert!(
                !blocked.is_finished(),
                "same-epoch callers remain pending until the shared fixed probe boundary"
            );
        }
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            1,
            "many concurrent same-epoch calls start no setup before the fixed boundary"
        );

        make_remote_retirement_probe_due(&peer).await;
        for outcome in [
            first_blocked.await.expect("first blocked caller"),
            second_blocked.await.expect("second blocked caller"),
        ] {
            assert_eq!(
                outcome,
                Err(SessionConsensusPeerError::Unavailable),
                "all boundary callers share the failed probe's pre-Call receipt"
            );
        }
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            2,
            "at the fixed boundary exactly one same-epoch caller owns the physical probe"
        );

        let rearmed_peer = peer.clone();
        let rearmed_request = request();
        let rearmed_call = tokio::spawn(async move { rearmed_peer.call(rearmed_request).await });
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            2,
            "the failed probe re-arms its fixed window without another setup"
        );
        make_remote_retirement_probe_due(&peer).await;
        assert_eq!(
            rearmed_call.await.expect("rearmed waiting caller"),
            Err(SessionConsensusPeerError::Unavailable),
            "a failed same-epoch probe re-arms the fixed window"
        );
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            3,
            "the re-armed boundary permits exactly one physical setup"
        );

        let recovering_peer = peer.clone();
        let recovering_request = request();
        let recovering_call =
            tokio::spawn(async move { recovering_peer.call(recovering_request).await });
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        make_remote_retirement_probe_due(&peer).await;
        assert_eq!(
            recovering_call.await.expect("recovering waiting caller"),
            Ok(SessionConsensusWireResponse {
                result: Ok(b"bounded-consensus-retirement".to_vec()),
            }),
            "a waiting same-epoch call recovers at the re-armed fixed boundary"
        );
        assert_eq!(resolutions.load(Ordering::SeqCst), 4);
        assert!(
            peer.connection_pool
                .cold_connection
                .state
                .lock()
                .await
                .remote_retirement_probe_gate
                .is_none(),
            "a usable authenticated Accepted bootstrap clears the remote-retirement probe gate"
        );
        assert_eq!(
            server
                .await
                .expect("repeated bootstrap-retirement later-call recovery server"),
            (4, 1),
            "neither retired route may receive an OpenRaft call and the later route receives exactly one"
        );
    }

    #[tokio::test]
    async fn newer_reauthentication_epoch_bypasses_remote_retirement_probe_gate_immediately() {
        let (_server_binding, client_binding) = bindings();
        let (address, server) =
            bootstrap_retirement_then_consensus_response_server(client_binding.clone()).await;
        let resolutions = Arc::new(AtomicUsize::new(0));
        let resolve: RemoteAddrResolver = {
            let resolutions = Arc::clone(&resolutions);
            Arc::new(move || {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { Ok(address) })
            })
        };
        let reauthentication = SessionReauthenticationControl::new();
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolve),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(2)),
        )
        .with_reauthentication_control(reauthentication.clone());
        let request = || {
            SessionConsensusWireRequest::try_new(
                client_binding.consensus_identity(),
                client_binding.local_consensus_node_id(),
                ConsensusRpcFamily::Vote,
                b"newer-epoch-bypasses-retirement-probe-gate".to_vec(),
            )
            .expect("bounded request")
        };

        assert_eq!(
            peer.call(request()).await,
            Err(SessionConsensusPeerError::Unavailable)
        );
        assert_eq!(resolutions.load(Ordering::SeqCst), 1);
        reauthentication
            .request_reauthentication()
            .expect("advance test reauthentication epoch");

        assert_eq!(
            peer.call(request()).await,
            Ok(SessionConsensusWireResponse {
                result: Ok(b"newer-epoch-bypasses-retirement-probe-gate".to_vec()),
            }),
            "a genuinely newer local reauthentication epoch bypasses immediately"
        );
        assert_eq!(resolutions.load(Ordering::SeqCst), 2);
        assert!(
            peer.connection_pool
                .cold_connection
                .state
                .lock()
                .await
                .remote_retirement_probe_gate
                .is_none(),
            "the succeeding Accepted connection clears the old gate"
        );
        assert_eq!(
            server.await.expect("bootstrap retirement recovery server"),
            (2, 1),
            "the retired epoch has zero Openraft Calls and only the newer Accepted epoch dispatches one"
        );
    }

    #[tokio::test]
    async fn rejected_is_reserved_exclusively_for_consensus_bootstrap_retirement() {
        let mut sink = tokio::io::sink();
        let cancellation = AtomicBool::new(false);
        assert!(matches!(
            reject_consensus_bootstrap(
                &mut sink,
                SessionConsensusPeerError::Rejected,
                tokio::time::Instant::now() + Duration::from_secs(1),
                &cancellation,
            )
            .await,
            Err(ProtocolError::InvalidWireValue)
        ));

        let (mut writer, mut reader) = tokio::io::duplex(1024);
        retire_consensus_bootstrap(
            &mut writer,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &cancellation,
        )
        .await
        .expect("write reserved bootstrap retirement");
        assert!(matches!(
            read_frame::<_, SessionConsensusBootstrapResponse>(
                &mut reader,
                MAX_HANDSHAKE_FRAME_SIZE,
            )
            .await
            .expect("read reserved bootstrap retirement"),
            SessionConsensusBootstrapResponse::Rejected(SessionConsensusPeerError::Rejected)
        ));
    }

    #[tokio::test]
    async fn bad_or_incomplete_consensus_response_connection_is_never_reused() {
        let (_server_binding, client_binding) = bindings();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind adversarial consensus listener");
        let addr = listener.local_addr().expect("adversarial listener address");
        let server_binding = client_binding.clone();
        let server = tokio::spawn(async move {
            for attempt in 0..3 {
                let (mut stream, _) = listener.accept().await.expect("accept consensus client");
                let hello: SessionConsensusBootstrapRequest =
                    read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                        .await
                        .expect("read consensus Hello");
                let SessionConsensusBootstrapRequest::Hello(hello) = hello;
                write_frame(
                    &mut stream,
                    &SessionConsensusBootstrapResponse::Accepted(SessionConsensusBootstrapAck {
                        transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
                        contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
                        identity: hello.identity,
                        server_node_id: server_binding.remote_consensus_node_id(),
                        accepted_sender_node_id: hello.sender_node_id,
                        handshake_nonce: hello.handshake_nonce,
                        accepted_response_frame_size: hello.requested_response_frame_size,
                        server_request_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
                    }),
                )
                .await
                .expect("write consensus acknowledgement");
                let call: SessionConsensusTransportRequest =
                    read_frame(&mut stream, MAX_NEGOTIATED_FRAME_SIZE)
                        .await
                        .expect("read consensus call");
                let SessionConsensusTransportRequest::Call { call_id, request } = call else {
                    panic!("expected ordinary consensus call");
                };
                if attempt == 1 {
                    // EOF after a complete request leaves the response position
                    // unknown and must make this stream permanently unusable.
                    continue;
                }
                let response_call_id = if attempt == 0 {
                    uuid::Uuid::new_v4()
                } else {
                    call_id
                };
                write_frame(
                    &mut stream,
                    &SessionConsensusTransportResponse::Call {
                        call_id: response_call_id,
                        response: SessionConsensusWireResponse {
                            result: Ok(request.payload),
                        },
                    },
                )
                .await
                .expect("write consensus response");
            }
        });
        let resolutions = Arc::new(AtomicUsize::new(0));
        let counted_resolver: RemoteAddrResolver = {
            let resolutions = Arc::clone(&resolutions);
            Arc::new(move || {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { Ok(addr) })
            })
        };
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, counted_resolver),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(1)),
        );
        let wire_request = |payload: &'static [u8]| {
            SessionConsensusWireRequest::try_new(
                client_binding.consensus_identity(),
                client_binding.local_consensus_node_id(),
                SessionConsensusRpcFamily::Vote,
                payload.to_vec(),
            )
            .expect("bounded consensus request")
        };

        assert_eq!(
            peer.call(wire_request(b"wrong-correlation")).await,
            Err(SessionConsensusPeerError::Protocol)
        );
        assert_eq!(
            peer.call(wire_request(b"incomplete-response")).await,
            Err(SessionConsensusPeerError::Unavailable)
        );
        assert_eq!(
            peer.call(wire_request(b"fresh-after-errors")).await,
            Ok(SessionConsensusWireResponse {
                result: Ok(b"fresh-after-errors".to_vec()),
            })
        );
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            3,
            "correlation failure and EOF must each force one fresh bootstrap"
        );
        server.await.expect("adversarial consensus server");
    }

    #[tokio::test]
    async fn consensus_bootstrap_rejects_former_pr_732_tag_27_app3_profile_before_handler() {
        let (server_binding, client_binding) = bindings();
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let server = SessionConsensusServer::from_transport(
            handler.clone(),
            None,
            SessionMembershipAdmission::from_current_binding(server_binding),
        );
        let (handle, addr) = server
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("listen");

        for (transport_revision, contract_profile) in [
            (
                SESSION_CONSENSUS_TRANSPORT_REVISION - 1,
                CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
            ),
            (5, former_728bc5_application_revision_3_profile()),
            (
                SESSION_CONSENSUS_TRANSPORT_REVISION,
                SessionConsensusContractProfile {
                    error_set_revision: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE
                        .error_set_revision
                        - 1,
                    ..CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE
                },
            ),
        ] {
            let mut stream = TcpStream::connect(addr).await.expect("connect");
            write_frame(
                &mut stream,
                &SessionConsensusBootstrapRequest::Hello(SessionConsensusBootstrapHello {
                    transport_revision,
                    contract_profile,
                    sender_replica_id: client_binding.local_replica_id().as_str().to_owned(),
                    expected_server_replica_id: client_binding
                        .remote_replica_id()
                        .as_str()
                        .to_owned(),
                    identity: client_binding.consensus_identity(),
                    sender_node_id: client_binding.local_consensus_node_id(),
                    expected_server_node_id: client_binding.remote_consensus_node_id(),
                    handshake_nonce: uuid::Uuid::new_v4(),
                    requested_response_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
                }),
            )
            .await
            .expect("write incompatible-profile Hello");
            assert!(matches!(
                read_frame::<_, SessionConsensusBootstrapResponse>(
                    &mut stream,
                    MAX_HANDSHAKE_FRAME_SIZE
                )
                .await
                .expect("read rejection"),
                SessionConsensusBootstrapResponse::Rejected(SessionConsensusPeerError::Protocol)
            ));
        }
        assert_eq!(handler.0.load(Ordering::Relaxed), 0);
        handle.abort_and_wait().await;
    }

    #[tokio::test]
    async fn consensus_client_rejects_former_pr_732_tag_27_app3_profile_before_call() {
        let (_server_binding, client_binding) = bindings();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind incompatible HelloAck listener");
        let address = listener.local_addr().expect("listener address");
        let server_binding = client_binding.clone();
        let server = tokio::spawn(async move {
            let mut calls = 0;
            for (transport_revision, contract_profile) in [
                (5, former_728bc5_application_revision_3_profile()),
                (
                    SESSION_CONSENSUS_TRANSPORT_REVISION,
                    SessionConsensusContractProfile {
                        error_set_revision: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE
                            .error_set_revision
                            - 1,
                        ..CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE
                    },
                ),
            ] {
                let (mut stream, _) = listener.accept().await.expect("accept client");
                let SessionConsensusBootstrapRequest::Hello(hello) =
                    read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                        .await
                        .expect("read Hello");
                write_frame(
                    &mut stream,
                    &SessionConsensusBootstrapResponse::Accepted(SessionConsensusBootstrapAck {
                        transport_revision,
                        contract_profile,
                        identity: hello.identity,
                        server_node_id: server_binding.remote_consensus_node_id(),
                        accepted_sender_node_id: hello.sender_node_id,
                        handshake_nonce: hello.handshake_nonce,
                        accepted_response_frame_size: hello.requested_response_frame_size,
                        server_request_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
                    }),
                )
                .await
                .expect("write incompatible HelloAck");
                if matches!(
                    tokio::time::timeout(
                        Duration::from_millis(100),
                        read_frame::<_, SessionConsensusTransportRequest>(
                            &mut stream,
                            MAX_NEGOTIATED_FRAME_SIZE,
                        ),
                    )
                    .await,
                    Ok(Ok(_))
                ) {
                    calls += 1;
                }
            }
            calls
        });
        let resolve: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolve),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(1)),
        );
        let request = || {
            SessionConsensusWireRequest::try_new(
                client_binding.consensus_identity(),
                client_binding.local_consensus_node_id(),
                SessionConsensusRpcFamily::Vote,
                b"reject-adjacent-hello-ack-profile".to_vec(),
            )
            .expect("bounded request")
        };
        assert_eq!(
            peer.call(request()).await,
            Err(SessionConsensusPeerError::ScopeMismatch)
        );
        assert_eq!(
            peer.call(request()).await,
            Err(SessionConsensusPeerError::ScopeMismatch)
        );
        assert_eq!(server.await.expect("incompatible HelloAck server"), 0);
    }

    #[tokio::test]
    async fn fixed_quorum_network_handshake_rejects_mixed_placement_policies() {
        let descriptors = vec![descriptor(1), descriptor(2), descriptor(3)];
        let strict = Arc::new(
            SessionReplicationManifest::try_new_with_epoch(
                SessionClusterId::new("fixed-policy-handshake").expect("cluster"),
                SessionConfigurationGeneration::new("fixed").expect("generation"),
                SessionConfigurationEpoch::new(1).expect("epoch"),
                descriptors.clone(),
            )
            .expect("strict manifest"),
        );
        let reduced = Arc::new(
            SessionReplicationManifest::try_new_with_epoch_and_placement_policy(
                SessionClusterId::new("fixed-policy-handshake").expect("cluster"),
                SessionConfigurationGeneration::new("fixed").expect("generation"),
                SessionConfigurationEpoch::new(1).expect("epoch"),
                descriptors,
                SessionPlacementPolicy::AllowReducedResilience,
            )
            .expect("reduced manifest"),
        );
        assert_eq!(
            strict.consensus_identity(),
            reduced.consensus_identity(),
            "dynamic-profile identity remains descriptor-derived"
        );
        assert_ne!(
            strict.fixed_durable_quorum_consensus_identity(),
            reduced.fixed_durable_quorum_consensus_identity(),
            "fixed policy must bind the authenticated authority scope"
        );
        assert_ne!(
            strict.consensus_identity(),
            strict.fixed_durable_quorum_consensus_identity(),
            "the fixed authority profile must not share the dynamic scope"
        );

        let server_binding = strict
            .bind_fixed_durable_quorum_local(ReplicaId::new("replica-2").expect("server ID"))
            .expect("strict server binding");
        let client_binding = reduced
            .bind_fixed_durable_quorum_local(ReplicaId::new("replica-1").expect("client ID"))
            .expect("reduced client binding")
            .bind_remote(ReplicaId::new("replica-2").expect("server ID"))
            .expect("remote binding");
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let server = SessionConsensusServer::from_transport(
            handler.clone(),
            None,
            SessionMembershipAdmission::from_current_binding(server_binding),
        );
        let (handle, address) = server
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("listen");
        let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(1)),
        );
        let request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::Vote,
            b"fixed-policy-scope".to_vec(),
        )
        .expect("bounded request");
        assert_eq!(
            peer.call(request).await,
            Err(SessionConsensusPeerError::ScopeMismatch)
        );
        let dynamic_client_binding = strict
            .bind_local(ReplicaId::new("replica-1").expect("client ID"))
            .expect("dynamic client binding")
            .bind_remote(ReplicaId::new("replica-2").expect("server ID"))
            .expect("dynamic remote binding");
        let dynamic_resolver: RemoteAddrResolver =
            Arc::new(move || Box::pin(async move { Ok(address) }));
        let dynamic_peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&dynamic_client_binding, dynamic_resolver),
            None,
            dynamic_client_binding.clone(),
            Some(Duration::from_secs(1)),
        );
        let dynamic_request = SessionConsensusWireRequest::try_new(
            dynamic_client_binding.consensus_identity(),
            dynamic_client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::Vote,
            b"dynamic-profile-scope".to_vec(),
        )
        .expect("bounded request");
        assert_eq!(
            dynamic_peer.call(dynamic_request).await,
            Err(SessionConsensusPeerError::ScopeMismatch)
        );
        assert_eq!(handler.0.load(Ordering::Relaxed), 0);
        handle.abort_and_wait().await;
    }

    #[cfg(feature = "insecure-test")]
    #[tokio::test]
    async fn live_server_fences_cached_predecessor_application_calls_at_joint_proof() {
        let current = membership_manifest(1, &[1, 2, 3]);
        let successor = membership_manifest(2, &[1, 2, 3, 4, 5]);
        let current_client_binding = current
            .bind_local(ReplicaId::new("replica-1").expect("client ID"))
            .expect("current client binding")
            .bind_remote(ReplicaId::new("replica-3").expect("server ID"))
            .expect("current remote binding");
        let successor_client_binding = successor
            .bind_local(ReplicaId::new("replica-4").expect("learner ID"))
            .expect("successor client binding")
            .bind_remote(ReplicaId::new("replica-3").expect("server ID"))
            .expect("successor remote binding");
        let current_server_binding = current
            .bind_local(ReplicaId::new("replica-3").expect("server ID"))
            .expect("current server binding");
        let membership = SessionMembershipAdmission::from_current_binding(current_server_binding);
        let transition_id = SessionTopologyTransitionId::from_bytes([31; 16]);
        let request = membership_transition_request(transition_id, 1, 2, &[1, 2, 3, 4, 5]);
        membership
            .stage_successor(&request, Arc::clone(&successor))
            .await
            .expect("stage successor");

        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let server = SessionConsensusServer::new_insecure_with_membership_admission(
            handler.clone(),
            membership.clone(),
        );
        let (handle, addr) = server
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("listen");
        let current_peer = RemoteSessionConsensusPeer::new_insecure(
            current_client_binding.clone(),
            addr,
            Some(Duration::from_secs(2)),
        );
        let successor_peer = RemoteSessionConsensusPeer::new_insecure(
            successor_client_binding.clone(),
            addr,
            Some(Duration::from_secs(2)),
        );
        let wire_request = |binding: &RemoteReplicaBinding,
                            family: SessionConsensusRpcFamily,
                            payload: &'static [u8]| {
            SessionConsensusWireRequest::try_new(
                binding.consensus_identity(),
                binding.local_consensus_node_id(),
                family,
                payload.to_vec(),
            )
            .expect("bounded request")
        };

        assert_eq!(
            current_peer
                .call(wire_request(
                    &current_client_binding,
                    SessionConsensusRpcFamily::ForwardMutation,
                    b"current-authority",
                ))
                .await,
            Ok(SessionConsensusWireResponse {
                result: Ok(b"current-authority".to_vec()),
            })
        );
        assert_eq!(
            successor_peer
                .call(wire_request(
                    &successor_client_binding,
                    SessionConsensusRpcFamily::AppendEntries,
                    b"learner-catchup",
                ))
                .await,
            Ok(SessionConsensusWireResponse {
                result: Ok(b"learner-catchup".to_vec()),
            })
        );
        assert_eq!(
            successor_peer
                .call(wire_request(
                    &successor_client_binding,
                    SessionConsensusRpcFamily::Vote,
                    b"premature-vote",
                ))
                .await,
            Ok(SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::ScopeMismatch),
            })
        );
        membership
            .admit_successor_voting_after_catch_up_for_test(&request)
            .await
            .expect("admit successor voting after catch-up");
        assert_eq!(
            successor_peer
                .call(wire_request(
                    &successor_client_binding,
                    SessionConsensusRpcFamily::Vote,
                    b"caught-up-vote",
                ))
                .await,
            Ok(SessionConsensusWireResponse {
                result: Ok(b"caught-up-vote".to_vec()),
            })
        );
        assert_eq!(
            successor_peer
                .call(wire_request(
                    &successor_client_binding,
                    SessionConsensusRpcFamily::ForwardMutation,
                    b"premature-authority",
                ))
                .await,
            Ok(SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::ScopeMismatch),
            })
        );
        for family in [
            SessionConsensusRpcFamily::ForwardMutation,
            SessionConsensusRpcFamily::ReadBarrier,
        ] {
            assert_eq!(
                current_peer
                    .call(wire_request(
                        &current_client_binding,
                        family,
                        b"joint-fenced-application-authority",
                    ))
                    .await,
                Ok(SessionConsensusWireResponse {
                    result: Err(SessionConsensusPeerError::ScopeMismatch),
                }),
                "the cached predecessor connection must lose application authority at joint proof"
            );
        }
        assert_eq!(
            current_peer
                .call(wire_request(
                    &current_client_binding,
                    SessionConsensusRpcFamily::AppendEntries,
                    b"joint-engine-traffic",
                ))
                .await,
            Ok(SessionConsensusWireResponse {
                result: Ok(b"joint-engine-traffic".to_vec()),
            }),
            "joint membership must keep predecessor engine traffic admitted"
        );

        membership
            .finalize_successor_for_test(&request)
            .await
            .expect("finalize successor");
        assert_eq!(
            current_peer
                .call(wire_request(
                    &current_client_binding,
                    SessionConsensusRpcFamily::AppendEntries,
                    b"stale-cached-connection",
                ))
                .await,
            Ok(SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::ScopeMismatch),
            }),
            "the cached current-epoch connection must be revalidated per call"
        );
        assert_eq!(
            successor_peer
                .call(wire_request(
                    &successor_client_binding,
                    SessionConsensusRpcFamily::ForwardMutation,
                    b"successor-authority",
                ))
                .await,
            Ok(SessionConsensusWireResponse {
                result: Ok(b"successor-authority".to_vec()),
            })
        );
        assert_eq!(handler.0.load(Ordering::Relaxed), 5);
        handle.abort_and_wait().await;
    }

    #[cfg(feature = "insecure-test")]
    #[tokio::test]
    async fn timed_out_cancellation_unsafe_handler_keeps_old_scope_leased_until_core_completion() {
        let current = membership_manifest(1, &[1, 2, 3]);
        let successor = membership_manifest(2, &[1, 2, 3, 4, 5]);
        let client_binding = current
            .bind_local(ReplicaId::new("replica-1").expect("client ID"))
            .expect("client binding")
            .bind_remote(ReplicaId::new("replica-3").expect("server ID"))
            .expect("remote binding");
        let server_binding = current
            .bind_local(ReplicaId::new("replica-3").expect("server ID"))
            .expect("server binding");
        let membership = SessionMembershipAdmission::from_current_binding(server_binding);
        let request = membership_transition_request(
            SessionTopologyTransitionId::from_bytes([32; 16]),
            1,
            2,
            &[1, 2, 3, 4, 5],
        );
        membership
            .stage_successor(&request, successor)
            .await
            .expect("stage successor");
        membership
            .admit_successor_voting_after_catch_up_for_test(&request)
            .await
            .expect("admit successor voting");

        let handler = Arc::new(CancellationUnsafeQueuedHandler::new());
        let server = SessionConsensusServer::new_insecure_with_membership_admission(
            handler.clone(),
            membership.clone(),
        )
        .with_rpc_timeout(Duration::from_millis(20));
        let (handle, addr) = server
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("listen");
        let peer = RemoteSessionConsensusPeer::new_insecure(
            client_binding.clone(),
            addr,
            Some(Duration::from_secs(1)),
        );
        let wire_request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::AppendEntries,
            b"queued-old-scope-call".to_vec(),
        )
        .expect("wire request");
        let call = tokio::spawn(async move { peer.call(wire_request).await });
        tokio::time::timeout(Duration::from_secs(1), handler.queued.notified())
            .await
            .expect("handler must queue its cancellation-unsafe core operation");
        assert_eq!(
            call.await.expect("call task"),
            Ok(SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::Timeout),
            })
        );

        let finalizer_membership = membership.clone();
        let finalizer_request = request.clone();
        let finalizer = tokio::spawn(async move {
            finalizer_membership
                .finalize_successor_for_test(&finalizer_request)
                .await
        });
        tokio::task::yield_now().await;
        assert!(
            !finalizer.is_finished(),
            "transport timeout must not release the old-scope lease while queued core work runs"
        );

        let core_completed = handler.core_completed.notified();
        handler.release_core.notify_waiters();
        tokio::time::timeout(Duration::from_secs(1), core_completed)
            .await
            .expect("queued core operation must complete after release");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), finalizer)
                .await
                .expect("finalization must resume after actual core completion")
                .expect("finalizer task"),
            Ok(crate::membership::SessionMembershipTransitionResult::Finalized)
        );
        handle.abort_and_wait().await;
    }

    #[tokio::test]
    async fn consensus_mode_rejects_raw_mutation_rebuild_and_malformed_frames() {
        let (server_binding, client_binding) = bindings();
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let server = SessionConsensusServer::from_transport(
            handler.clone(),
            None,
            SessionMembershipAdmission::from_current_binding(server_binding),
        );
        let (handle, addr) = server
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("listen");

        let mut raw_mutation = raw_consensus_connection(addr, &client_binding).await;
        write_frame(
            &mut raw_mutation,
            &Request::Batch {
                ops: Vec::<SessionOp>::new(),
            },
        )
        .await
        .expect("write raw mutation");
        assert!(read_frame::<_, SessionConsensusTransportResponse>(
            &mut raw_mutation,
            MAX_NEGOTIATED_FRAME_SIZE
        )
        .await
        .is_err());

        let mut raw_rebuild = raw_consensus_connection(addr, &client_binding).await;
        write_frame(
            &mut raw_rebuild,
            &Request::RebuildReplicationState {
                entries: Vec::new(),
            },
        )
        .await
        .expect("write raw rebuild");
        assert!(read_frame::<_, SessionConsensusTransportResponse>(
            &mut raw_rebuild,
            MAX_NEGOTIATED_FRAME_SIZE
        )
        .await
        .is_err());

        let mut malformed = raw_consensus_connection(addr, &client_binding).await;
        malformed
            .write_all(&1_u32.to_be_bytes())
            .await
            .expect("write malformed length");
        malformed
            .write_all(b"{")
            .await
            .expect("write malformed payload");
        malformed.flush().await.expect("flush malformed payload");
        assert!(read_frame::<_, SessionConsensusTransportResponse>(
            &mut malformed,
            MAX_NEGOTIATED_FRAME_SIZE
        )
        .await
        .is_err());

        let mut oversized = raw_consensus_connection(addr, &client_binding).await;
        oversized
            .write_all(
                &u32::try_from(MAX_NEGOTIATED_FRAME_SIZE + 1)
                    .expect("bounded oversize length")
                    .to_be_bytes(),
            )
            .await
            .expect("write oversized length");
        oversized.flush().await.expect("flush oversized length");
        assert!(read_frame::<_, SessionConsensusTransportResponse>(
            &mut oversized,
            MAX_NEGOTIATED_FRAME_SIZE
        )
        .await
        .is_err());

        assert_eq!(handler.0.load(Ordering::Relaxed), 0);
        handle.abort_and_wait().await;
    }

    #[test]
    fn remote_consensus_peer_is_accepted_only_as_the_consensus_port() {
        fn accepts_consensus_port<T: SessionConsensusPeer>() {}
        accepts_consensus_port::<RemoteSessionConsensusPeer>();

        let (server_binding, client_binding) = bindings();
        let _ = server_binding;
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(
                &client_binding,
                Arc::new(|| {
                    Box::pin(async {
                        Err(io::Error::new(io::ErrorKind::NotFound, "test resolver"))
                    })
                }),
            ),
            None,
            client_binding,
            None,
        );
        let _: &dyn SessionConsensusPeer = &peer;
        let request = SessionConsensusWireRequest::try_new(
            peer.binding.consensus_identity(),
            peer.binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::Vote,
            Vec::new(),
        )
        .expect("request");
        assert!(request.validate().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_cached_consensus_connection_is_reaped_at_its_soft_lifecycle_bound() {
        let _guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(40),
            Duration::from_secs(10),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::ZERO,
        )
        .expect("cached connection lifecycle policy");
        let established_at = tokio::time::Instant::now();
        let lifecycle = ConnectionLifecycle::new(policy, established_at, None, None, 0, None)
            .expect("cached connection lifecycle");
        let (stream, _remote) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(stream);
        let pool = Arc::new(ConsensusConnectionPool::new(
            ConnectionLifecyclePolicy::default(),
        ));
        {
            let mut primary = pool.primary.connection.lock().await;
            *primary = Some(ConsensusConnection {
                reader: Box::new(reader),
                writer: Box::new(writer),
                response_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
                request_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
                admission_attempt_id: None,
                lifecycle,
                last_successful_correlated_use: None,
                idle_deadline_origin: established_at,
            });
        }
        pool.ensure_cached_connection_reaper(
            ConsensusConnectionLane::Primary,
            None,
            SessionReauthenticationControl::new(),
            [0; 32],
            test_cold_epoch(),
        );
        pool.primary.changed.notify_one();
        tokio::task::yield_now().await;
        assert!(pool.primary.connection.lock().await.is_some());

        tokio::time::advance(DURABLE_CONSENSUS_TIMING_PROFILE.client_connection_reuse_limit())
            .await;
        tokio::task::yield_now().await;
        assert!(
            pool.primary.connection.lock().await.is_none(),
            "an idle cached connection must not survive its soft lifecycle bound"
        );
    }

    fn cached_consensus_connection(lifecycle: ConnectionLifecycle) -> ConsensusConnection {
        let (stream, _remote) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(stream);
        ConsensusConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            response_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            request_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            admission_attempt_id: None,
            lifecycle,
            last_successful_correlated_use: None,
            idle_deadline_origin: tokio::time::Instant::now(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn consensus_idle_reuse_limit_is_enforced_independently_for_both_lanes() {
        let _guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let policy = ConnectionLifecyclePolicy::default();
        let now = tokio::time::Instant::now();
        let lifecycle = || {
            ConnectionLifecycle::new(policy, now, None, None, 0, None)
                .expect("cached connection lifecycle")
        };
        let (_server_binding, client_binding) = bindings();
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(
                &client_binding,
                Arc::new(|| {
                    Box::pin(async {
                        Err(io::Error::new(io::ErrorKind::NotFound, "test resolver"))
                    })
                }),
            ),
            None,
            client_binding,
            None,
        );
        let mut primary = cached_consensus_connection(lifecycle());
        let mut overflow = cached_consensus_connection(lifecycle());
        primary.last_successful_correlated_use = Some(now);
        overflow.last_successful_correlated_use = Some(now);

        let reuse_limit = DURABLE_CONSENSUS_TIMING_PROFILE.client_connection_reuse_limit();
        tokio::time::advance(reuse_limit - Duration::from_millis(1)).await;
        let just_inside = tokio::time::Instant::now();
        assert!(!peer.connection_idle_reuse_expired(&primary, just_inside));
        assert!(!peer.connection_idle_reuse_expired(&overflow, just_inside));

        tokio::time::advance(Duration::from_millis(1)).await;
        let at_limit = tokio::time::Instant::now();
        assert!(peer.connection_idle_reuse_expired(&primary, at_limit));
        assert!(peer.connection_idle_reuse_expired(&overflow, at_limit));
    }

    #[tokio::test(start_paused = true)]
    async fn cached_lane_reapers_retire_both_idle_lanes_at_the_exact_reuse_boundary() {
        let _guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let now = tokio::time::Instant::now();
        let policy = ConnectionLifecyclePolicy::default();
        let primary_lifecycle =
            ConnectionLifecycle::new(policy, now, None, None, 0, None).expect("primary lifecycle");
        let overflow_lifecycle =
            ConnectionLifecycle::new(policy, now, None, None, 0, None).expect("overflow lifecycle");
        let primary_probe = primary_lifecycle.clone();
        let overflow_probe = overflow_lifecycle.clone();
        let pool = Arc::new(ConsensusConnectionPool::new(policy));
        let mut primary = cached_consensus_connection(primary_lifecycle);
        let mut overflow = cached_consensus_connection(overflow_lifecycle);
        primary.last_successful_correlated_use = Some(now);
        overflow.last_successful_correlated_use = Some(now);
        *pool.primary.connection.lock().await = Some(primary);
        *pool.overflow.connection.lock().await = Some(overflow);
        let reauthentication = SessionReauthenticationControl::new();
        pool.ensure_cached_connection_reaper(
            ConsensusConnectionLane::Primary,
            None,
            reauthentication.clone(),
            [6; 32],
            test_cold_epoch(),
        );
        pool.ensure_cached_connection_reaper(
            ConsensusConnectionLane::Overflow,
            None,
            reauthentication,
            [7; 32],
            test_cold_epoch(),
        );
        pool.primary.changed.notify_one();
        pool.overflow.changed.notify_one();
        tokio::task::yield_now().await;

        let reuse_limit = DURABLE_CONSENSUS_TIMING_PROFILE.client_connection_reuse_limit();
        tokio::time::advance(reuse_limit - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(pool.primary.connection.lock().await.is_some());
        assert!(pool.overflow.connection.lock().await.is_some());

        tokio::time::advance(Duration::from_millis(1)).await;
        wait_for_cached_lane_to_empty(&pool, ConsensusConnectionLane::Primary).await;
        wait_for_cached_lane_to_empty(&pool, ConsensusConnectionLane::Overflow).await;
        for probe in [primary_probe, overflow_probe] {
            assert_eq!(probe.recorded_retirement_count(), 1);
            assert_eq!(
                probe.recorded_retirement_reason(),
                Some(RetirementReason::IdleTimeout)
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn two_cached_credential_retirements_seed_one_immediate_peer_probe_gate() {
        let now = tokio::time::Instant::now();
        let policy = ConnectionLifecyclePolicy::default();
        let expired = opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::now_utc() - time::Duration::seconds(1),
        );
        let peer_expiry = CertificateExpiryEvidence::capture(expired, expired, now);
        let lifecycle = || {
            ConnectionLifecycle::new(policy, now, None, Some(peer_expiry), 0, None)
                .expect("peer-expired cached lifecycle")
        };
        let pool = Arc::new(ConsensusConnectionPool::new(policy));
        *pool.primary.connection.lock().await = Some(cached_consensus_connection(lifecycle()));
        *pool.overflow.connection.lock().await = Some(cached_consensus_connection(lifecycle()));
        let reauthentication = SessionReauthenticationControl::new();
        let epoch = test_cold_epoch();
        pool.ensure_cached_connection_reaper(
            ConsensusConnectionLane::Primary,
            None,
            reauthentication.clone(),
            [8; 32],
            epoch,
        );
        pool.ensure_cached_connection_reaper(
            ConsensusConnectionLane::Overflow,
            None,
            reauthentication,
            [9; 32],
            epoch,
        );
        pool.primary.changed.notify_one();
        pool.overflow.changed.notify_one();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(pool.primary.connection.lock().await.is_none());
        assert!(pool.overflow.connection.lock().await.is_none());
        assert!(
            pool.cold_connection
                .state
                .lock()
                .await
                .remote_retirement_probe_gate
                .is_some_and(|gate| gate.probe_is_due(epoch, tokio::time::Instant::now())),
            "concurrent primary/overflow credential retirements publish one due-now exact-peer gate"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cached_successor_credential_retirement_seeds_its_own_exact_probe_epoch() {
        let _guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let material = crate::test_support::RotatableClientMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/client",
        );
        let tls_config = material.config();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_millis(5),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::ZERO,
        )
        .expect("successor credential retirement lifecycle policy");
        let now = tokio::time::Instant::now();
        let material_epoch = Some(tls_config.material_status().epoch());
        let first_epoch = ConsensusColdConnectionEpoch {
            material_epoch,
            ..test_cold_epoch()
        };
        let successor_epoch = ConsensusColdConnectionEpoch {
            reauthentication_generation: 1,
            ..first_epoch
        };
        let first_lifecycle = ConnectionLifecycle::new(
            policy,
            now,
            None,
            None,
            first_epoch.reauthentication_generation,
            first_epoch.material_epoch,
        )
        .expect("first cached lifecycle");
        let pool = Arc::new(ConsensusConnectionPool::new(policy));
        *pool.primary.connection.lock().await = Some(cached_consensus_connection(first_lifecycle));
        let reauthentication = SessionReauthenticationControl::new();
        pool.ensure_cached_connection_reaper(
            ConsensusConnectionLane::Primary,
            Some(tls_config.clone()),
            reauthentication.clone(),
            [10; 32],
            first_epoch,
        );
        pool.primary.changed.notify_one();
        tokio::task::yield_now().await;

        let expires_at = opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::now_utc() + time::Duration::seconds(2),
        );
        let peer_expiry = CertificateExpiryEvidence::capture(expires_at, expires_at, now);
        let successor_lifecycle = ConnectionLifecycle::new(
            policy,
            now,
            None,
            Some(peer_expiry),
            successor_epoch.reauthentication_generation,
            successor_epoch.material_epoch,
        )
        .expect("successor cached lifecycle");
        let successor_retirement = successor_lifecycle.clone();
        *pool.primary.connection.lock().await =
            Some(cached_consensus_connection(successor_lifecycle));
        pool.primary.changed.notify_one();
        reauthentication
            .request_reauthentication()
            .expect("advance to the successor generation");
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(2)).await;
        wait_for_cached_lane_to_empty(&pool, ConsensusConnectionLane::Primary).await;
        assert_eq!(
            successor_retirement.recorded_retirement_reason(),
            Some(RetirementReason::PeerLeafExpiry),
            "the successor must retire at its credential lifecycle boundary"
        );

        let gate = pool
            .cold_connection
            .state
            .lock()
            .await
            .remote_retirement_probe_gate
            .expect("credential retirement must seed a probe gate");
        let now = tokio::time::Instant::now();
        assert_eq!(
            gate.epoch, successor_epoch,
            "the gate follows the successor admission"
        );
        assert_eq!(
            gate.epoch.consensus_identity,
            first_epoch.consensus_identity
        );
        assert_eq!(gate.epoch.remote_node_id, first_epoch.remote_node_id);
        assert!(gate.probe_is_due(successor_epoch, now));
        assert!(
            !gate.probe_is_due(first_epoch, now),
            "the stale first-reaper epoch must bypass the successor gate"
        );
        let pending_gate = ConsensusRemoteRetirementProbeGate {
            next_probe_at: Some(now + Duration::from_secs(1)),
            ..gate
        };
        assert!(pending_gate.blocks(successor_epoch, now));
        assert!(
            !pending_gate.blocks(first_epoch, now),
            "the stale first-reaper epoch must not block a successor admission"
        );

        material.rotate();
        let current_different_epoch = ConsensusColdConnectionEpoch {
            material_epoch: Some(tls_config.material_status().epoch()),
            ..successor_epoch
        };
        assert_ne!(
            current_different_epoch.material_epoch,
            successor_epoch.material_epoch
        );
        assert!(
            !gate.probe_is_due(current_different_epoch, now),
            "a current, different material epoch must bypass the old exact-epoch gate"
        );
        assert!(
            !pending_gate.blocks(current_different_epoch, now),
            "a new material epoch must not be blocked by the old exact-epoch gate"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn staged_ready_connection_retires_at_its_bootstrap_age_idle_boundary() {
        let _guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let (_server_binding, client_binding) = bindings();
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(
                &client_binding,
                Arc::new(|| Box::pin(std::future::pending::<io::Result<SocketAddr>>())),
            ),
            None,
            client_binding,
            Some(Duration::from_secs(1)),
        );
        let epoch = peer.cold_connector().epoch();
        let attempt_id = uuid::Uuid::new_v4();
        let now = tokio::time::Instant::now();
        let lifecycle = ConnectionLifecycle::new(
            peer.lifecycle_policy,
            now,
            None,
            None,
            epoch.reauthentication_generation,
            epoch.material_epoch,
        )
        .expect("staged lifecycle");
        let retirement_probe = lifecycle.clone();
        let mut connection = cached_consensus_connection(lifecycle);
        connection.idle_deadline_origin = now;
        peer.connection_pool
            .cold_connection
            .state
            .lock()
            .await
            .phase = ConsensusColdConnectionPhase::Ready {
            attempt_id,
            epoch,
            connection: Box::new(connection),
        };

        let connector = peer.cold_connector();
        let coordinator = Arc::clone(&peer.connection_pool.cold_connection);
        let reconnect_gate = Arc::clone(&peer.connection_pool.reconnect_gate);
        let mut shutdown = peer.connection_pool.shutdown.subscribe();
        let monitor = tokio::spawn(async move {
            monitor_staged_consensus_connection(
                &connector,
                &coordinator,
                &reconnect_gate,
                &mut shutdown,
                attempt_id,
                epoch,
            )
            .await;
        });
        tokio::task::yield_now().await;
        tokio::time::advance(DURABLE_CONSENSUS_TIMING_PROFILE.client_connection_reuse_limit())
            .await;
        monitor.await.expect("staged idle monitor join");
        assert!(matches!(
            peer.connection_pool
                .cold_connection
                .state
                .lock()
                .await
                .phase,
            ConsensusColdConnectionPhase::Idle
        ));
        assert_eq!(retirement_probe.recorded_retirement_count(), 1);
        assert_eq!(
            retirement_probe.recorded_retirement_reason(),
            Some(RetirementReason::IdleTimeout)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn claimant_drops_an_idle_staged_ready_connection_before_dispatch() {
        let _guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let (_server_binding, client_binding) = bindings();
        let resolver: RemoteAddrResolver =
            Arc::new(|| Box::pin(std::future::pending::<io::Result<SocketAddr>>()));
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding,
            Some(Duration::from_secs(1)),
        );
        let epoch = peer.cold_connector().epoch();
        let attempt_id = uuid::Uuid::new_v4();
        let now = tokio::time::Instant::now();
        let lifecycle = ConnectionLifecycle::new(
            peer.lifecycle_policy,
            now,
            None,
            None,
            epoch.reauthentication_generation,
            epoch.material_epoch,
        )
        .expect("staged lifecycle");
        let retirement_probe = lifecycle.clone();
        let mut connection = cached_consensus_connection(lifecycle);
        connection.idle_deadline_origin = now;
        peer.connection_pool
            .cold_connection
            .state
            .lock()
            .await
            .phase = ConsensusColdConnectionPhase::Ready {
            attempt_id,
            epoch,
            connection: Box::new(connection),
        };

        tokio::time::advance(DURABLE_CONSENSUS_TIMING_PROFILE.client_connection_reuse_limit())
            .await;
        let claim_peer = peer.clone();
        let claimant = tokio::spawn(async move {
            claim_peer
                .claim_or_start_cold_connection(
                    tokio::time::Instant::now() + Duration::from_millis(1),
                )
                .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(matches!(
            claimant.await.expect("idle staged claimant join"),
            Err(SessionConsensusPeerError::Unavailable)
        ));
        assert_eq!(retirement_probe.recorded_retirement_count(), 1);
        assert_eq!(
            retirement_probe.recorded_retirement_reason(),
            Some(RetirementReason::IdleTimeout)
        );
    }

    async fn wait_for_cached_lane_to_empty(
        pool: &ConsensusConnectionPool,
        lane: ConsensusConnectionLane,
    ) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if pool.lane(lane).connection.lock().await.is_none() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cached consensus lane retirement");
    }

    #[tokio::test]
    async fn idle_cached_consensus_connection_reacts_to_explicit_reauthentication() {
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(40),
            Duration::from_secs(10),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::ZERO,
        )
        .expect("explicit reauthentication lifecycle policy");
        let lifecycle =
            ConnectionLifecycle::new(policy, tokio::time::Instant::now(), None, None, 0, None)
                .expect("explicit reauthentication lifecycle");
        let pool = Arc::new(ConsensusConnectionPool::new(
            ConnectionLifecyclePolicy::default(),
        ));
        *pool.primary.connection.lock().await = Some(cached_consensus_connection(lifecycle));
        let reauthentication = SessionReauthenticationControl::new();
        pool.ensure_cached_connection_reaper(
            ConsensusConnectionLane::Primary,
            None,
            reauthentication.clone(),
            [1; 32],
            test_cold_epoch(),
        );
        pool.primary.changed.notify_one();
        tokio::task::yield_now().await;

        reauthentication
            .request_reauthentication()
            .expect("request cached consensus reauthentication");
        wait_for_cached_lane_to_empty(&pool, ConsensusConnectionLane::Primary).await;
    }

    #[tokio::test]
    async fn idle_cached_consensus_connection_reacts_to_material_epoch_change() {
        let material = crate::test_support::RotatableClientMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/client",
        );
        let tls_config = material.config();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(40),
            Duration::from_secs(10),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::ZERO,
        )
        .expect("material epoch lifecycle policy");
        let lifecycle = ConnectionLifecycle::new(
            policy,
            tokio::time::Instant::now(),
            None,
            None,
            0,
            Some(tls_config.material_status().epoch()),
        )
        .expect("material epoch lifecycle");
        let pool = Arc::new(ConsensusConnectionPool::new(
            ConnectionLifecyclePolicy::default(),
        ));
        *pool.primary.connection.lock().await = Some(cached_consensus_connection(lifecycle));
        pool.ensure_cached_connection_reaper(
            ConsensusConnectionLane::Primary,
            Some(tls_config),
            SessionReauthenticationControl::new(),
            [2; 32],
            test_cold_epoch(),
        );
        pool.primary.changed.notify_one();
        tokio::task::yield_now().await;

        material.rotate();
        wait_for_cached_lane_to_empty(&pool, ConsensusConnectionLane::Primary).await;
    }

    #[tokio::test(start_paused = true)]
    async fn cached_consensus_reaper_never_races_an_in_flight_lane() {
        let _guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(40),
            Duration::from_secs(10),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::ZERO,
        )
        .expect("in-flight exclusion lifecycle policy");
        let lifecycle =
            ConnectionLifecycle::new(policy, tokio::time::Instant::now(), None, None, 0, None)
                .expect("in-flight exclusion lifecycle");
        let retirement_probe = lifecycle.clone();
        let pool = Arc::new(ConsensusConnectionPool::new(
            ConnectionLifecyclePolicy::default(),
        ));
        *pool.primary.connection.lock().await = Some(cached_consensus_connection(lifecycle));
        let in_flight = pool.primary.connection.lock().await;
        pool.ensure_cached_connection_reaper(
            ConsensusConnectionLane::Primary,
            None,
            SessionReauthenticationControl::new(),
            [3; 32],
            test_cold_epoch(),
        );
        pool.primary.changed.notify_one();
        tokio::time::advance(DURABLE_CONSENSUS_TIMING_PROFILE.client_connection_reuse_limit())
            .await;
        tokio::task::yield_now().await;
        assert!(
            in_flight.is_some(),
            "the reaper must wait for the in-flight lane owner"
        );
        drop(in_flight);
        wait_for_cached_lane_to_empty(&pool, ConsensusConnectionLane::Primary).await;
        assert_eq!(retirement_probe.recorded_retirement_count(), 1);
        assert_eq!(
            retirement_probe.recorded_retirement_reason(),
            Some(RetirementReason::IdleTimeout)
        );
    }

    #[tokio::test]
    async fn reaper_inspection_never_redirects_sequential_work_to_overflow() {
        let pool = Arc::new(ConsensusConnectionPool::new(
            ConnectionLifecyclePolicy::default(),
        ));
        let inspection = pool.primary.connection.lock().await;
        assert_eq!(pool.primary.in_flight.available_permits(), 1);

        let waiting_pool = Arc::clone(&pool);
        let waiter = tokio::spawn(async move { waiting_pool.acquire().await.lane });
        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "an idle-lane inspection must make sequential work wait for primary"
        );
        assert_eq!(pool.primary.in_flight.available_permits(), 0);
        assert_eq!(pool.overflow.in_flight.available_permits(), 1);

        drop(inspection);
        assert!(matches!(
            waiter.await.expect("sequential lane acquisition"),
            ConsensusConnectionLane::Primary
        ));
        assert_eq!(pool.primary.in_flight.available_permits(), 1);
    }

    #[tokio::test]
    async fn concurrent_work_uses_overflow_while_reaper_inspects_primary() {
        let pool = Arc::new(ConsensusConnectionPool::new(
            ConnectionLifecyclePolicy::default(),
        ));
        let inspection = pool.primary.connection.lock().await;

        let primary_pool = Arc::clone(&pool);
        let primary = tokio::spawn(async move { primary_pool.acquire().await.lane });
        tokio::time::timeout(Duration::from_secs(1), async {
            while pool.primary.in_flight.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first caller reserves the inspected primary lane");

        let overflow_pool = Arc::clone(&pool);
        let overflow = tokio::spawn(async move { overflow_pool.acquire().await.lane });
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), overflow)
                .await
                .expect("concurrent caller must not queue behind inspected primary")
                .expect("overflow lane acquisition"),
            ConsensusConnectionLane::Overflow
        ));

        drop(inspection);
        assert!(matches!(
            primary.await.expect("primary lane acquisition"),
            ConsensusConnectionLane::Primary
        ));
        assert_eq!(pool.primary.in_flight.available_permits(), 1);
        assert_eq!(pool.overflow.in_flight.available_permits(), 1);
    }

    #[tokio::test]
    async fn cached_consensus_reapers_are_fixed_to_two_and_do_not_retain_the_pool() {
        let pool = Arc::new(ConsensusConnectionPool::new(
            ConnectionLifecyclePolicy::default(),
        ));
        let reauthentication = SessionReauthenticationControl::new();
        for _ in 0..16 {
            pool.ensure_cached_connection_reaper(
                ConsensusConnectionLane::Primary,
                None,
                reauthentication.clone(),
                [4; 32],
                test_cold_epoch(),
            );
            pool.ensure_cached_connection_reaper(
                ConsensusConnectionLane::Overflow,
                None,
                reauthentication.clone(),
                [5; 32],
                test_cold_epoch(),
            );
        }
        assert!(pool.primary.reaper_started.load(Ordering::Acquire));
        assert!(pool.overflow.reaper_started.load(Ordering::Acquire));
        assert_eq!(
            pool.shutdown.receiver_count(),
            2,
            "one and only one reaper may exist for each fixed lane"
        );

        let weak = Arc::downgrade(&pool);
        drop(pool);
        tokio::task::yield_now().await;
        assert!(
            weak.upgrade().is_none(),
            "reaper tasks must hold only weak pool ownership"
        );
    }

    #[test]
    fn clone_local_consensus_builders_detach_incompatible_connection_state() {
        let (_server_binding, client_binding) = bindings();
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(
                &client_binding,
                Arc::new(|| {
                    Box::pin(async {
                        Err(io::Error::new(io::ErrorKind::NotFound, "test resolver"))
                    })
                }),
            ),
            None,
            client_binding,
            None,
        );
        let shared = peer.clone();
        assert!(Arc::ptr_eq(&peer.connection_pool, &shared.connection_pool));

        let different_frame = peer
            .clone()
            .with_max_frame_size(MIN_SESSION_CONSENSUS_FRAME_SIZE);
        assert!(!Arc::ptr_eq(
            &peer.connection_pool,
            &different_frame.connection_pool
        ));

        let different_lifecycle = peer
            .clone()
            .with_connection_lifecycle(ConnectionLifecyclePolicy::default());
        assert!(!Arc::ptr_eq(
            &peer.connection_pool,
            &different_lifecycle.connection_pool
        ));

        let different_control = peer
            .clone()
            .with_reauthentication_control(SessionReauthenticationControl::new());
        assert!(!Arc::ptr_eq(
            &peer.connection_pool,
            &different_control.connection_pool
        ));
    }
}
