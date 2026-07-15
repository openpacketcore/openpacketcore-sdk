use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use futures_util::Stream;
use opc_redaction::metrics::METRICS;
use opc_session_store::backend::{
    next_replication_sequence, validate_replication_log_page, validate_replication_log_page_owned,
    validate_replication_page_owned, validate_replication_prefix_owned,
    validate_session_ops_profile, BackendInstanceIdentity, BackendPeerBinding, CompareAndSet,
    CompareAndSetResult, ReplicationEntry, ReplicationLogRange, ReplicationOp,
    ReplicationWatchCursor, SessionBackend, SessionOp, SessionOpResult, WATCH_CHANNEL_CAPACITY,
};
use opc_session_store::capability::BackendCapabilities;
use opc_session_store::error::{LeaseError, StoreError};
use opc_session_store::lease::{LeaseGuard, SessionLeaseManager};
use opc_session_store::model::{OwnerId, SessionKey};

use opc_session_store::record::StoredSessionRecord;
use opc_session_store::{
    validate_record_expiry_preflights_profile, validate_session_ttl,
    validate_stored_record_expiry_profile, RecordExpiryPreflight, ReplicaId,
    ReplicaReadinessFailure, RestoreScanCursorProfile, RestoreScanPage, RestoreScanRequest,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

pub use crate::consensus::RemoteAddrResolver;
use crate::error::{classify_tls_io_error, ProtocolError};
use crate::identity::RemoteReplicaBinding;
use crate::lifecycle::{
    directed_connection_key, CertificateExpiryEvidence, ConnectionAttemptMetricGuard,
    ConnectionLifecycle, ConnectionLifecyclePolicy, ReconnectGate, SessionReauthenticationControl,
};
use crate::protocol::{
    bounded_session_op_expectations, checked_frame_size, checked_wire_frame_size,
    compare_and_set_result_matches_key, conservative_payload_budget, get_result_matches_key,
    read_frame, read_response_frame, session_op_results_match_expectations,
    validate_request_payload_limit, validate_request_profile, write_frame_bounded_until,
    BootstrapHello, BootstrapRequest, BootstrapResponse, ContractProfile, Request, Response,
    RestoreScanWireRequest, CONTRACT_VERSION, CURRENT_CONTRACT_PROFILE, DEFAULT_MAX_FRAME_SIZE,
    MAX_HANDSHAKE_FRAME_SIZE, MAX_SESSION_NET_BATCH_OPERATIONS, MAX_SESSION_NET_REBUILD_ENTRIES,
    MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE, SESSION_NET_ALPN,
};

/// Persistent transport connection to a remote session backend.
///
/// The client keeps a single connection and allows one in-flight request at
/// a time; clones of [`RemoteSessionBackend`] share this connection.
struct Connection {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    authenticated_peer: Option<ReplicaId>,
    contract_profile: ContractProfile,
    frame_limits: NegotiatedFrameLimits,
    cas_idempotency_epoch: uuid::Uuid,
    lifecycle: ConnectionLifecycle,
}

#[derive(Clone, Copy)]
struct ObservedGenerationChange {
    value: u64,
    observed_at: tokio::time::Instant,
}

#[derive(Clone, Copy)]
struct ObservedMaterialChange {
    value: Option<opc_tls::TlsMaterialEpoch>,
    observed_at: tokio::time::Instant,
}

#[derive(Default)]
struct PoolLifecycleEvents {
    generation: Option<ObservedGenerationChange>,
    material: Option<ObservedMaterialChange>,
}

#[derive(Default)]
struct PoolLifecycleMonitor {
    task: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    events: StdMutex<PoolLifecycleEvents>,
}

impl PoolLifecycleMonitor {
    fn publish_generation(&self, value: u64, observed_at: tokio::time::Instant) {
        let mut events = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match events.generation.as_mut() {
            Some(event) => event.value = value,
            None => {
                events.generation = Some(ObservedGenerationChange { value, observed_at });
            }
        }
    }

    fn publish_material(
        &self,
        value: Option<opc_tls::TlsMaterialEpoch>,
        observed_at: tokio::time::Instant,
    ) {
        let mut events = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match events.material.as_mut() {
            Some(event) => event.value = value,
            None => {
                events.material = Some(ObservedMaterialChange { value, observed_at });
            }
        }
    }

    fn apply_to(
        &self,
        lifecycle: &mut ConnectionLifecycle,
        current_generation: u64,
        current_material_epoch: Option<opc_tls::TlsMaterialEpoch>,
        observed_now: tokio::time::Instant,
        edge_key: &[u8],
    ) {
        let (generation, material) = {
            let events = self
                .events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (events.generation, events.material)
        };
        if current_generation != lifecycle.admitted_generation() {
            let observed_at = generation
                .filter(|event| event.value == current_generation)
                .map_or(observed_now, |event| event.observed_at);
            lifecycle.observe_rotation(
                observed_at,
                current_generation,
                lifecycle.admitted_material_epoch(),
                edge_key,
            );
        }
        if current_material_epoch != lifecycle.admitted_material_epoch() {
            let observed_at = material
                .filter(|event| event.value == current_material_epoch)
                .map_or(observed_now, |event| event.observed_at);
            lifecycle.observe_rotation(
                observed_at,
                lifecycle.admitted_generation(),
                current_material_epoch,
                edge_key,
            );
        }
        // Catch a publication observed directly at checkout before the
        // monitor task has processed its subscribed event.
        lifecycle.observe_rotation(
            observed_now,
            current_generation,
            current_material_epoch,
            edge_key,
        );
    }

    fn acknowledge_admission(
        &self,
        generation: u64,
        material_epoch: Option<opc_tls::TlsMaterialEpoch>,
    ) {
        let mut events = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if events
            .generation
            .is_some_and(|event| event.value == generation)
        {
            events.generation = None;
        }
        if events
            .material
            .is_some_and(|event| event.value == material_epoch)
        {
            events.material = None;
        }
    }
}

impl Drop for PoolLifecycleMonitor {
    fn drop(&mut self) {
        let task = self
            .task
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(task) = task.take() {
            task.abort();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NegotiatedFrameLimits {
    response_frame_size: usize,
    request_frame_size: usize,
}

#[derive(Debug)]
struct NegotiatedResponse {
    response: Response,
    contract_profile: ContractProfile,
    frame_limits: NegotiatedFrameLimits,
}

#[derive(Debug, thiserror::Error)]
enum ConnectionOpenError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("connection retired before application admission")]
    /// Authenticated proof that the server retired before admitting any
    /// application request or transmitting its bootstrap acknowledgement.
    Retired,
    #[error("connection attempt superseded by a local authentication epoch")]
    /// Local material or explicit reauthentication changed while a cold
    /// connection was still pre-dispatch.
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteRequestFailure {
    Transport,
    Authentication,
    Timeout,
    ConnectionRetiring,
    Protocol,
    ResponseContract,
    ReplicationLogResponseContract,
    Backend,
    PayloadTooLarge { actual: usize, max: usize },
}

#[derive(Debug)]
struct RemoteRequestAttemptFailure {
    failure: RemoteRequestFailure,
    request_may_have_reached_server: bool,
    invalidates_contract: bool,
}

impl RemoteRequestAttemptFailure {
    fn before_connection(error: &ConnectionOpenError) -> Self {
        match error {
            ConnectionOpenError::Protocol(error) => Self::before_transmission(error),
            ConnectionOpenError::Retired | ConnectionOpenError::Superseded => {
                Self::connection_retiring()
            }
        }
    }

    fn before_transmission(error: &ProtocolError) -> Self {
        Self {
            failure: RemoteRequestFailure::from_protocol_error(error),
            request_may_have_reached_server: false,
            invalidates_contract: invalidates_negotiated_contract(error),
        }
    }

    fn after_transmission_started(error: &ProtocolError) -> Self {
        Self {
            failure: RemoteRequestFailure::from_protocol_error(error),
            // A failed `write_all` cannot prove that the peer did not receive
            // the complete frame. Once the first write is attempted, a
            // mutation transport failure is conservatively ambiguous.
            request_may_have_reached_server: true,
            invalidates_contract: invalidates_negotiated_contract(error),
        }
    }

    fn from_store_preflight(error: StoreError) -> Self {
        Self {
            failure: RemoteRequestFailure::from_store_preflight(error),
            request_may_have_reached_server: false,
            invalidates_contract: false,
        }
    }

    fn response_contract_violation(failure: RemoteRequestFailure) -> Self {
        Self {
            failure,
            request_may_have_reached_server: true,
            invalidates_contract: true,
        }
    }

    fn connection_retiring() -> Self {
        Self {
            failure: RemoteRequestFailure::ConnectionRetiring,
            // A complete authenticated control frame is proof that the
            // server correlated this request but did not dispatch it.
            request_may_have_reached_server: false,
            invalidates_contract: false,
        }
    }
}

impl RemoteRequestFailure {
    fn from_connection_error(error: &ConnectionOpenError) -> Self {
        match error {
            ConnectionOpenError::Protocol(error) => Self::from_protocol_error(error),
            ConnectionOpenError::Retired | ConnectionOpenError::Superseded => {
                Self::ConnectionRetiring
            }
        }
    }

    fn from_protocol_error(error: &ProtocolError) -> Self {
        match error {
            ProtocolError::Io(error) if error.kind() == io::ErrorKind::TimedOut => Self::Timeout,
            ProtocolError::Io(_) => Self::Transport,
            ProtocolError::Authentication => Self::Authentication,
            ProtocolError::BackendUnavailable(_) => Self::Backend,
            ProtocolError::FrameTooLarge(_)
            | ProtocolError::VersionMismatch { .. }
            | ProtocolError::ContractMismatch
            | ProtocolError::InvalidWireValue
            | ProtocolError::UnexpectedResponse
            | ProtocolError::Serialization(_) => Self::Protocol,
        }
    }

    const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Transport | Self::Timeout | Self::ConnectionRetiring | Self::Backend
        )
    }

    const fn reason_code(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Authentication => "authentication",
            Self::Timeout => "timeout",
            Self::ConnectionRetiring => "connection_retiring",
            Self::Protocol => "protocol",
            Self::ResponseContract | Self::ReplicationLogResponseContract => "protocol",
            Self::Backend => "backend",
            Self::PayloadTooLarge { .. } => "payload_too_large",
        }
    }

    fn from_store_preflight(error: StoreError) -> Self {
        match error {
            StoreError::PayloadTooLarge { actual, max } => Self::PayloadTooLarge { actual, max },
            _ => Self::Protocol,
        }
    }
}

fn invalidates_negotiated_contract(error: &ProtocolError) -> bool {
    matches!(
        error,
        ProtocolError::Authentication
            | ProtocolError::VersionMismatch { .. }
            | ProtocolError::ContractMismatch
            | ProtocolError::InvalidWireValue
            | ProtocolError::UnexpectedResponse
            | ProtocolError::FrameTooLarge(_)
            | ProtocolError::Serialization(_)
    )
}

const fn unavailable_capabilities() -> BackendCapabilities {
    BackendCapabilities {
        atomic_compare_and_set: false,
        monotonic_fencing_token: false,
        per_key_ttl: false,
        server_side_lease_expiry: false,
        ordered_replication_log: false,
        batch_write: false,
        watch: false,
        restore_scan: false,
        max_value_bytes: 0,
    }
}

const REMOTE_PROTOCOL_VIOLATION: &str =
    "remote session backend response violated the protocol contract";

impl From<RemoteRequestFailure> for ReplicaReadinessFailure {
    fn from(failure: RemoteRequestFailure) -> Self {
        match failure {
            RemoteRequestFailure::Transport => Self::Transport,
            RemoteRequestFailure::Authentication => Self::Authentication,
            RemoteRequestFailure::Timeout => Self::Timeout,
            RemoteRequestFailure::ConnectionRetiring => Self::Backend,
            RemoteRequestFailure::Protocol => Self::Protocol,
            RemoteRequestFailure::ResponseContract
            | RemoteRequestFailure::ReplicationLogResponseContract => Self::Protocol,
            RemoteRequestFailure::Backend => Self::Backend,
            RemoteRequestFailure::PayloadTooLarge { .. } => Self::Protocol,
        }
    }
}

#[derive(Clone)]
enum RemoteTarget {
    #[cfg(feature = "insecure-test")]
    Pinned(SocketAddr),
    Resolved {
        server_name: Option<Arc<str>>,
        resolve: RemoteAddrResolver,
    },
}

impl RemoteTarget {
    #[cfg(feature = "insecure-test")]
    fn pinned(addr: SocketAddr) -> Self {
        Self::Pinned(addr)
    }

    fn resolved(server_name: Option<String>, resolve: RemoteAddrResolver) -> Self {
        Self::Resolved {
            server_name: server_name.map(Arc::<str>::from),
            resolve,
        }
    }

    fn configured(binding: &RemoteReplicaBinding) -> Self {
        let endpoint = binding.remote_endpoint();
        let server_name = endpoint.host().to_string();
        let host = Arc::<str>::from(endpoint.host());
        let port = endpoint.port();
        let resolve: RemoteAddrResolver = Arc::new(move || {
            let host = host.clone();
            Box::pin(async move {
                let mut addresses = tokio::net::lookup_host((host.as_ref(), port)).await?;
                addresses.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "replica endpoint did not resolve")
                })
            })
        });
        Self::resolved(Some(server_name), resolve)
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
    ) -> Result<rustls_pki_types::ServerName<'static>, ProtocolError> {
        match self {
            #[cfg(feature = "insecure-test")]
            Self::Pinned(_) => Ok(rustls_pki_types::ServerName::IpAddress(
                resolved_addr.ip().into(),
            )),
            Self::Resolved {
                server_name: Some(server_name),
                ..
            } => rustls_pki_types::ServerName::try_from(server_name.to_string())
                .map_err(|_| ProtocolError::Authentication),
            Self::Resolved {
                server_name: None, ..
            } => Ok(rustls_pki_types::ServerName::IpAddress(
                resolved_addr.ip().into(),
            )),
        }
    }
}

impl std::fmt::Debug for RemoteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RemoteTarget(<redacted>)")
    }
}

impl std::fmt::Display for RemoteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted-target>")
    }
}

fn session_client_tls_config(config: Arc<opc_tls::ClientConfig>) -> Arc<opc_tls::ClientConfig> {
    let mut config = config.as_ref().clone();
    config.alpn_protocols = vec![SESSION_NET_ALPN.to_vec()];
    // Session identity is defined by the certificate presented on this exact
    // connection. A resumed TLS session can carry cached peer certificates and
    // skip verification of a rotated SVID, so replication deliberately pays
    // for a full mutually authenticated handshake on every reconnect.
    config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Arc::new(config)
}

#[derive(Clone)]
struct OutboundConnectionLifecycle {
    policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
    reconnect_gate: Arc<ReconnectGate>,
}

async fn open_connection(
    target: RemoteTarget,
    tls_config: Option<opc_tls::AuthenticatedClientConfig>,
    binding: RemoteReplicaBinding,
    requested_response_frame_size: usize,
    operation_deadline: tokio::time::Instant,
    lifecycle: OutboundConnectionLifecycle,
) -> Result<Connection, ConnectionOpenError> {
    // Local configuration rejection is not a connection attempt.
    checked_wire_frame_size(requested_response_frame_size).map_err(ConnectionOpenError::from)?;
    let mut reauthentication_rx = lifecycle.reauthentication.subscribe();
    let mut admitted_generation = lifecycle.reauthentication.generation();
    let mut material_rx = tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedClientConfig::subscribe_material_changes);
    let mut admitted_material_epoch = material_rx.as_ref().map(|status| status.status().epoch());
    let reconnect_attempt = loop {
        let acquire = lifecycle.reconnect_gate.acquire(
            operation_deadline,
            admitted_generation,
            admitted_material_epoch,
        );
        tokio::pin!(acquire);
        tokio::select! {
            biased;
            changed = reauthentication_rx.changed() => {
                if changed.is_err() {
                    return Err(ConnectionOpenError::Protocol(ProtocolError::Io(
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "session reauthentication control closed during reconnect",
                        ),
                    )));
                }
                admitted_generation = lifecycle.reauthentication.generation();
                lifecycle
                    .reconnect_gate
                    .observe_epoch(admitted_generation, admitted_material_epoch);
            },
            current_material_epoch = wait_for_material_epoch_change(
                &mut material_rx,
                admitted_material_epoch,
            ) => {
                admitted_material_epoch = current_material_epoch;
                lifecycle
                    .reconnect_gate
                    .observe_epoch(admitted_generation, admitted_material_epoch);
            },
            attempt = &mut acquire => {
                break attempt.ok_or_else(|| {
                    ConnectionOpenError::Protocol(ProtocolError::Io(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "session reconnect cooldown exceeded the operation deadline",
                    )))
                })?;
            },
        }
    };
    let mut attempt_metrics = ConnectionAttemptMetricGuard::started();
    let open = open_connection_attempt(
        target,
        tls_config.clone(),
        binding.clone(),
        requested_response_frame_size,
        operation_deadline,
        lifecycle.policy,
        lifecycle.reauthentication.clone(),
    );
    tokio::pin!(open);
    let mut result = tokio::select! {
        biased;
        () = reconnect_attempt.superseded() => {
            Err(ConnectionOpenError::Superseded)
        },
        changed = reauthentication_rx.changed() => {
            if changed.is_ok() {
                lifecycle.reconnect_gate.observe_epoch(
                    lifecycle.reauthentication.generation(),
                    tls_config
                        .as_ref()
                        .map(|config| config.material_status().epoch()),
                );
            }
            Err(ConnectionOpenError::Superseded)
        },
        current_material_epoch = wait_for_material_epoch_change(
            &mut material_rx,
            admitted_material_epoch,
        ) => {
            lifecycle.reconnect_gate.observe_epoch(
                lifecycle.reauthentication.generation(),
                current_material_epoch,
            );
            Err(ConnectionOpenError::Superseded)
        },
        result = &mut open => result,
    };
    if let Ok(connection) = result.as_mut() {
        let now = tokio::time::Instant::now();
        let current_generation = lifecycle.reauthentication.generation();
        let current_material_epoch = tls_config
            .as_ref()
            .map(|config| config.material_status().epoch());
        connection.lifecycle.observe_rotation(
            now,
            current_generation,
            current_material_epoch,
            &directed_connection_key(
                b"direct",
                binding.local_replica_id().as_str(),
                binding.remote_replica_id().as_str(),
            ),
        );
        let mismatch = connection
            .lifecycle
            .evidence_mismatch_reason(current_generation, current_material_epoch);
        if mismatch.is_some() || connection.lifecycle.retirement(now).is_some() {
            if let Some(reason) = mismatch {
                connection.lifecycle.record_forced_retirement(reason);
            }
            result = Err(ConnectionOpenError::Retired);
        }
    }
    if result.is_ok() {
        reconnect_attempt.succeeded();
    } else {
        reconnect_attempt.failed();
    }
    match &result {
        Ok(_) => &METRICS.session_net_connection_successes,
        // A complete authenticated retirement control is a successful
        // transport/control exchange, but not an admitted application
        // connection. Account for the attempt without misclassifying the
        // expected local-rotation race as a failure; the caller reconnects
        // before transmitting any application request.
        Err(ConnectionOpenError::Retired) => &METRICS.session_net_connection_successes,
        Err(ConnectionOpenError::Superseded) => &METRICS.session_net_connection_failure_timeout,
        Err(ConnectionOpenError::Protocol(ProtocolError::Io(error)))
            if error.kind() == io::ErrorKind::TimedOut =>
        {
            &METRICS.session_net_connection_failure_timeout
        }
        Err(ConnectionOpenError::Protocol(ProtocolError::Io(_))) => {
            &METRICS.session_net_connection_failure_transport
        }
        Err(ConnectionOpenError::Protocol(ProtocolError::Authentication)) => {
            &METRICS.session_net_connection_failure_authentication
        }
        Err(ConnectionOpenError::Protocol(ProtocolError::BackendUnavailable(_))) => {
            &METRICS.session_net_connection_failure_backend
        }
        Err(_) => &METRICS.session_net_connection_failure_protocol,
    }
    .fetch_add(1, Ordering::Relaxed);
    attempt_metrics.finish();
    result
}

async fn open_connection_attempt(
    target: RemoteTarget,
    tls_config: Option<opc_tls::AuthenticatedClientConfig>,
    binding: RemoteReplicaBinding,
    requested_response_frame_size: usize,
    operation_deadline: tokio::time::Instant,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
) -> Result<Connection, ConnectionOpenError> {
    // Reject unrepresentable or unusably small local budgets before DNS or a
    // socket allocation. The handshake repeats this conversion when building
    // the fixed-width field, keeping direct callers fail closed as well.
    let admitted_generation = reauthentication.generation();
    if let Some(tls_config) = tls_config {
        let outcome = tls_config
            .run_handshake(|attempt| {
                let target = target.clone();
                let binding = binding.clone();
                async move {
                    let addr = target.resolve().await.map_err(ProtocolError::Io)?;
                    let tcp = TcpStream::connect(addr).await.map_err(ProtocolError::Io)?;
                    let connector = tokio_rustls::TlsConnector::from(session_client_tls_config(
                        attempt.rustls_config(),
                    ));
                    let server_name = target.tls_server_name(addr)?;
                    let tls_stream = connector
                        .connect(server_name, tcp)
                        .await
                        .map_err(classify_tls_io_error)?;
                    if tls_stream.get_ref().1.alpn_protocol() != Some(SESSION_NET_ALPN) {
                        return Err(ProtocolError::UnexpectedResponse.into());
                    }
                    let peer =
                        opc_tls::peer_tls_identity_from_client_connection(tls_stream.get_ref().1)
                            .map_err(|_| ProtocolError::Authentication)?;
                    if peer.spiffe_id().as_str() != binding.remote_spiffe_id().as_str() {
                        return Err(ProtocolError::Authentication.into());
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

                    let (mut reader, mut writer) = tokio::io::split(tls_stream);
                    let (contract_profile, frame_limits, cas_idempotency_epoch) =
                        perform_client_handshake(
                            &mut reader,
                            &mut writer,
                            &binding,
                            requested_response_frame_size,
                            operation_deadline,
                        )
                        .await?;
                    Ok::<_, ConnectionOpenError>((
                        reader,
                        writer,
                        tls_completed_at,
                        local_expiry,
                        peer_expiry,
                        contract_profile,
                        frame_limits,
                        cas_idempotency_epoch,
                    ))
                }
            })
            .await
            .map_err(|error| match error {
                opc_tls::TlsHandshakeRunError::Material(_) => {
                    ConnectionOpenError::Protocol(ProtocolError::Authentication)
                }
                opc_tls::TlsHandshakeRunError::Operation(error) => error,
            })?;
        let admission = outcome.admission();
        let (parts, _) = outcome.into_parts();
        let (
            reader,
            writer,
            established_at,
            local_expiry,
            peer_expiry,
            contract_profile,
            frame_limits,
            cas_idempotency_epoch,
        ) = parts;
        let lifecycle = ConnectionLifecycle::new(
            lifecycle_policy,
            established_at,
            Some(local_expiry),
            Some(peer_expiry),
            admitted_generation,
            Some(admission.epoch()),
        )
        .map_err(|_| ProtocolError::InvalidWireValue)?;
        Ok(Connection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            authenticated_peer: Some(binding.remote_replica_id().clone()),
            contract_profile,
            frame_limits,
            cas_idempotency_epoch,
            lifecycle,
        })
    } else {
        let addr = target.resolve().await.map_err(ProtocolError::Io)?;
        let tcp = TcpStream::connect(addr).await.map_err(ProtocolError::Io)?;
        let (mut reader, mut writer) = tokio::io::split(tcp);
        let (contract_profile, frame_limits, cas_idempotency_epoch) = perform_client_handshake(
            &mut reader,
            &mut writer,
            &binding,
            requested_response_frame_size,
            operation_deadline,
        )
        .await?;
        let established_at = tokio::time::Instant::now();
        let lifecycle = ConnectionLifecycle::new(
            lifecycle_policy,
            established_at,
            None,
            None,
            admitted_generation,
            None,
        )
        .map_err(|_| ProtocolError::InvalidWireValue)?;
        Ok(Connection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            authenticated_peer: None,
            contract_profile,
            frame_limits,
            cas_idempotency_epoch,
            lifecycle,
        })
    }
}

async fn perform_client_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    binding: &RemoteReplicaBinding,
    requested_response_frame_size: usize,
    operation_deadline: tokio::time::Instant,
) -> Result<(ContractProfile, NegotiatedFrameLimits, uuid::Uuid), ConnectionOpenError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let handshake_nonce = uuid::Uuid::new_v4();
    let configuration_id = binding.configuration_id().to_hex();
    let requested_response_frame_size = checked_wire_frame_size(requested_response_frame_size)?;
    write_frame_bounded_until(
        writer,
        &BootstrapRequest::Hello(BootstrapHello {
            contract_version: CONTRACT_VERSION,
            node_id: binding.local_replica_id().as_str().to_string(),
            expected_server_replica_id: Some(binding.remote_replica_id().as_str().to_string()),
            cluster_id: Some(binding.cluster_id().as_str().to_string()),
            configuration_id: Some(configuration_id.clone()),
            configuration_epoch: Some(binding.configuration_epoch().get()),
            handshake_nonce: Some(handshake_nonce),
            contract_profile: Some(CURRENT_CONTRACT_PROFILE),
            requested_response_frame_size: Some(requested_response_frame_size),
        }),
        MAX_HANDSHAKE_FRAME_SIZE,
        operation_deadline,
    )
    .await?;

    let ack: BootstrapResponse = read_frame(reader, MAX_HANDSHAKE_FRAME_SIZE).await?;
    match ack {
        BootstrapResponse::HelloAck(ack) => {
            if ack.contract_version != CONTRACT_VERSION {
                return Err(ProtocolError::VersionMismatch {
                    local: CONTRACT_VERSION,
                    remote: ack.contract_version,
                }
                .into());
            }
            if ack.contract_profile != Some(CURRENT_CONTRACT_PROFILE) {
                return Err(ProtocolError::ContractMismatch.into());
            }
            let identity_matches = ack.server_replica_id.as_deref()
                == Some(binding.remote_replica_id().as_str())
                && ack.accepted_client_replica_id.as_deref()
                    == Some(binding.local_replica_id().as_str())
                && ack.cluster_id.as_deref() == Some(binding.cluster_id().as_str())
                && ack.configuration_id.as_deref() == Some(configuration_id.as_str())
                && ack.configuration_epoch == Some(binding.configuration_epoch().get());
            if !identity_matches {
                return Err(ProtocolError::Authentication.into());
            }
            if ack.handshake_nonce != Some(handshake_nonce) {
                return Err(ProtocolError::UnexpectedResponse.into());
            }
            let accepted_response_frame_size = checked_frame_size(
                ack.accepted_response_frame_size
                    .ok_or(ProtocolError::ContractMismatch)?,
            )?;
            if accepted_response_frame_size > checked_frame_size(requested_response_frame_size)? {
                return Err(ProtocolError::ContractMismatch.into());
            }
            let request_frame_size = checked_frame_size(
                ack.server_request_frame_size
                    .ok_or(ProtocolError::ContractMismatch)?,
            )?
            .min(checked_frame_size(requested_response_frame_size)?);
            let cas_idempotency_epoch = ack
                .cas_idempotency_epoch
                .ok_or(ProtocolError::ContractMismatch)?;
            Ok((
                CURRENT_CONTRACT_PROFILE,
                NegotiatedFrameLimits {
                    response_frame_size: accepted_response_frame_size,
                    request_frame_size,
                },
                cas_idempotency_epoch,
            ))
        }
        BootstrapResponse::HelloRejected { .. } => {
            Err(ConnectionOpenError::Protocol(ProtocolError::Authentication))
        }
        BootstrapResponse::ConnectionRetiring => Err(ConnectionOpenError::Retired),
    }
}

fn discard_replication_payloads_from_response(response: Response) {
    match response {
        Response::GetReplicationLog(Ok(entries)) => {
            entries
                .into_iter()
                .for_each(discard_replication_entry_iteratively);
        }
        Response::WatchEntry(Ok(entry)) => {
            discard_replication_entry_iteratively(entry);
        }
        _ => {}
    }
}

#[derive(Clone, Copy)]
enum StoreResponseClass {
    Read,
    CompareAndSet,
    Mutation,
    RecordExpiryPreflight,
}

fn store_error_matches_class(error: &StoreError, class: StoreResponseClass) -> bool {
    match error {
        StoreError::CasIdempotencyOutcomeUnavailable => {
            matches!(class, StoreResponseClass::CompareAndSet)
        }
        StoreError::BackendOperationOutcomeUnavailable => {
            matches!(class, StoreResponseClass::Mutation)
        }
        _ => true,
    }
}

fn store_result_matches_class<T>(
    result: &Result<T, StoreError>,
    class: StoreResponseClass,
) -> bool {
    result
        .as_ref()
        .err()
        .is_none_or(|error| store_error_matches_class(error, class))
}

fn batch_response_matches_request(ops: &[SessionOp], results: &[SessionOpResult]) -> bool {
    if !bounded_session_op_expectations(ops)
        .as_ref()
        .is_ok_and(|expected| session_op_results_match_expectations(expected, results))
    {
        return false;
    }
    ops.iter()
        .zip(results)
        .all(|(operation, result)| match (operation, result) {
            (SessionOp::Get { .. }, SessionOpResult::Get(result)) => {
                store_result_matches_class(result, StoreResponseClass::Read)
            }
            (SessionOp::CompareAndSet(_), SessionOpResult::CompareAndSet(result)) => {
                store_result_matches_class(result, StoreResponseClass::CompareAndSet)
            }
            (SessionOp::DeleteFenced { .. }, SessionOpResult::DeleteFenced(result))
            | (SessionOp::RefreshTtl { .. }, SessionOpResult::RefreshTtl(result)) => {
                store_result_matches_class(result, StoreResponseClass::Mutation)
            }
            _ => false,
        })
}

fn response_matches_request(request: &Request, response: &Response) -> bool {
    match (request, response) {
        (Request::Capabilities, Response::Capabilities(_)) => true,
        (Request::Get { key }, Response::Get(result)) => {
            get_result_matches_key(key, result)
                && store_result_matches_class(result, StoreResponseClass::Read)
        }
        (Request::CompareAndSet { op, .. }, Response::CompareAndSet(result)) => {
            compare_and_set_result_matches_key(&op.key, result)
                && store_result_matches_class(result, StoreResponseClass::CompareAndSet)
        }
        (Request::DeleteFenced { .. }, Response::DeleteFenced(result))
        | (Request::RefreshTtl { .. }, Response::RefreshTtl(result)) => {
            store_result_matches_class(result, StoreResponseClass::Mutation)
        }
        (Request::RecordExpiryPreflight { .. }, Response::RecordExpiryPreflight(result)) => {
            store_result_matches_class(result, StoreResponseClass::RecordExpiryPreflight)
        }
        (Request::Batch { ops }, Response::Batch(Ok(results))) => {
            batch_response_matches_request(ops, results)
        }
        (Request::Batch { ops }, Response::Batch(Err(error))) => {
            let class = if ops.iter().any(|op| !matches!(op, SessionOp::Get { .. })) {
                StoreResponseClass::Mutation
            } else {
                StoreResponseClass::Read
            };
            store_error_matches_class(error, class)
        }
        (
            Request::ScanRestoreRecords {
                request: wire_request,
                ..
            },
            Response::ScanRestoreRecords(Ok(page)),
        ) => RestoreScanRequest::try_from(wire_request.clone()).is_ok_and(|request| {
            page.cursor_profile == RestoreScanCursorProfile::DurableOpaqueV1
                && page.validate_for_request(&request).is_ok()
        }),
        (Request::ScanRestoreRecords { .. }, Response::ScanRestoreRecords(Err(error))) => {
            store_error_matches_class(error, StoreResponseClass::Read)
        }
        (Request::MaxReplicationSequence, Response::MaxReplicationSequence(result)) => {
            store_result_matches_class(result, StoreResponseClass::Read)
        }
        (Request::GetReplicationLog { start, limit }, Response::GetReplicationLog(Ok(entries))) => {
            validate_replication_log_page(*start, *limit, entries).is_ok()
        }
        (Request::GetReplicationLog { .. }, Response::GetReplicationLog(Err(error))) => {
            store_error_matches_class(error, StoreResponseClass::Read)
        }
        (Request::ReplicateEntry { .. }, Response::ReplicateEntry(result))
        | (Request::RebuildReplicationState { .. }, Response::RebuildReplicationState(result)) => {
            store_result_matches_class(result, StoreResponseClass::Mutation)
        }
        (Request::Watch { .. }, Response::WatchStream) => true,
        (Request::Watch { .. }, Response::WatchEntry(Err(error))) => {
            store_error_matches_class(error, StoreResponseClass::Read)
        }
        (Request::NextLeaseInfo, Response::NextLeaseInfo(result)) => {
            store_result_matches_class(result, StoreResponseClass::Read)
        }
        (Request::AcquireLease { key, owner, .. }, Response::AcquireLease(Ok(lease))) => {
            lease.key() == key && lease.owner() == owner
        }
        (Request::AcquireLease { .. }, Response::AcquireLease(Err(_))) => true,
        (Request::RenewLease { lease, .. }, Response::RenewLease(Ok(renewed))) => {
            renewed.key() == lease.key()
                && renewed.owner() == lease.owner()
                && renewed.fence() == lease.fence()
                && renewed.credential_id() == lease.credential_id()
        }
        (Request::RenewLease { .. }, Response::RenewLease(Err(_)))
        | (Request::ReleaseLease { .. }, Response::ReleaseLease(_)) => true,
        (Request::Hello { .. }, _) => false,
        _ => false,
    }
}

fn response_contract_failure(
    request: &Request,
    response: &Response,
) -> Option<RemoteRequestFailure> {
    if response_matches_request(request, response) {
        return None;
    }
    if let (Request::GetReplicationLog { start, limit }, Response::GetReplicationLog(Ok(entries))) =
        (request, response)
    {
        if entries.len() <= *limit
            && matches!(
                validate_replication_log_page(*start, *limit, entries),
                Err(StoreError::InvalidReplicationSequence)
            )
        {
            return Some(RemoteRequestFailure::ReplicationLogResponseContract);
        }
    }
    Some(RemoteRequestFailure::ResponseContract)
}

fn response_requires_fresh_connection(response: &Response) -> bool {
    matches!(
        response,
        Response::CompareAndSet(Err(StoreError::CasIdempotencyOutcomeUnavailable))
    )
}

fn discard_replication_entry_iteratively(entry: ReplicationEntry) {
    let ReplicationEntry { op, .. } = entry;
    let mut pending = vec![vec![op].into_iter()];
    while let Some(current) = pending.last_mut() {
        match current.next() {
            Some(ReplicationOp::Batch { ops }) => pending.push(ops.into_iter()),
            Some(_) => {}
            None => {
                pending.pop();
            }
        }
    }
}

/// Remote session backend client.
#[derive(Clone)]
pub struct RemoteSessionBackend {
    target: RemoteTarget,
    tls_config: Option<opc_tls::AuthenticatedClientConfig>,
    binding: RemoteReplicaBinding,
    deadline: Duration,
    max_frame_size: usize,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
    reconnect_gate: Arc<ReconnectGate>,
    conn: Arc<Mutex<Option<Connection>>>,
    pool_lifecycle_monitor: Arc<PoolLifecycleMonitor>,
    negotiated_frame_limits: Arc<RwLock<Option<NegotiatedFrameLimits>>>,
    cached_capabilities:
        Arc<RwLock<Option<(ContractProfile, NegotiatedFrameLimits, BackendCapabilities)>>>,
}

impl std::fmt::Debug for RemoteSessionBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteSessionBackend")
            .field("target", &self.target)
            .field("tls_config", &self.tls_config.is_some())
            .field("deadline", &self.deadline)
            .field("max_frame_size", &self.max_frame_size)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

impl RemoteSessionBackend {
    /// Create a new mTLS remote backend client.
    ///
    /// `binding` supplies the exact local and remote replica IDs, expected peer
    /// SPIFFE identity, dial endpoint, and cluster/configuration scope. The
    /// endpoint may resolve to different addresses across reconnects, but every
    /// new connection revalidates the same authenticated member identity.
    /// Session resumption and early data are disabled so a reconnect must
    /// present and verify the peer's current certificate.
    ///
    /// `deadline` bounds every backend method end-to-end (default 2s when
    /// `None`). Reads and failures proven before transmission may reconnect with
    /// bounded backoff and return availability failure on expiry. A transmitted
    /// CAS, non-CAS mutation, or lease mutation is never automatically replayed;
    /// expiry after that boundary returns its typed non-retryable ambiguity.
    pub fn new(
        binding: RemoteReplicaBinding,
        tls_config: opc_tls::AuthenticatedClientConfig,
        deadline: Option<Duration>,
    ) -> Self {
        let target = RemoteTarget::configured(&binding);
        Self::from_transport(target, Some(tls_config), binding, deadline)
    }

    /// Create a new mTLS remote backend client that re-resolves before each
    /// new connection.
    ///
    /// Existing live connections are reused. When a connection is dropped,
    /// the next retry calls `resolve` and connects to the returned address.
    /// TLS routing keeps using the binding endpoint as `server_name`; neither
    /// that name nor the resolved IP can replace the binding's expected
    /// `ReplicaId` and certificate SPIFFE identity.
    pub fn new_with_resolver(
        binding: RemoteReplicaBinding,
        resolve: RemoteAddrResolver,
        tls_config: opc_tls::AuthenticatedClientConfig,
        deadline: Option<Duration>,
    ) -> Self {
        let server_name = binding.remote_endpoint().host().to_string();
        Self::from_transport(
            RemoteTarget::resolved(Some(server_name), resolve),
            Some(tls_config),
            binding,
            deadline,
        )
    }

    /// Create a plaintext remote backend client for tests.
    ///
    /// Production replication clients must use [`RemoteSessionBackend::new`].
    #[cfg(feature = "insecure-test")]
    pub fn new_insecure(addr: SocketAddr, deadline: Option<Duration>) -> Self {
        Self::from_transport(
            RemoteTarget::pinned(addr),
            None,
            crate::identity::insecure_test_client_binding(),
            deadline,
        )
    }

    /// Create a plaintext remote backend client with re-resolution for tests.
    #[cfg(feature = "insecure-test")]
    pub fn new_insecure_with_resolver(
        resolve: RemoteAddrResolver,
        deadline: Option<Duration>,
    ) -> Self {
        Self::from_transport(
            RemoteTarget::resolved(None, resolve),
            None,
            crate::identity::insecure_test_client_binding(),
            deadline,
        )
    }

    fn from_transport(
        target: RemoteTarget,
        tls_config: Option<opc_tls::AuthenticatedClientConfig>,
        binding: RemoteReplicaBinding,
        deadline: Option<Duration>,
    ) -> Self {
        let lifecycle_policy = ConnectionLifecyclePolicy::default();
        Self {
            target,
            tls_config,
            binding,
            deadline: deadline.unwrap_or(Duration::from_secs(2)),
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            lifecycle_policy,
            reauthentication: SessionReauthenticationControl::new(),
            reconnect_gate: ReconnectGate::new(lifecycle_policy),
            conn: Arc::new(Mutex::new(None)),
            pool_lifecycle_monitor: Arc::new(PoolLifecycleMonitor::default()),
            negotiated_frame_limits: Arc::new(RwLock::new(None)),
            cached_capabilities: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the local request bound and requested response-frame budget.
    ///
    /// The effective request limit is the smaller of this value and the
    /// server's acknowledged request budget. Values below
    /// [`crate::MIN_NEGOTIATED_FRAME_SIZE`] or above
    /// [`crate::MAX_NEGOTIATED_FRAME_SIZE`] fail before DNS or socket
    /// allocation.
    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        // `max_frame_size` is clone-local, so this configured value must not
        // reuse connection or negotiation state created by another clone.
        self.conn = Arc::new(Mutex::new(None));
        self.pool_lifecycle_monitor = Arc::new(PoolLifecycleMonitor::default());
        self.reconnect_gate = ReconnectGate::new(self.lifecycle_policy);
        self.negotiated_frame_limits = Arc::new(RwLock::new(None));
        self.cached_capabilities = Arc::new(RwLock::new(None));
        self
    }

    /// Set the finite authentication, drain, and reconnect policy.
    #[must_use]
    pub fn with_connection_lifecycle(mut self, policy: ConnectionLifecyclePolicy) -> Self {
        self.lifecycle_policy = policy;
        self.conn = Arc::new(Mutex::new(None));
        self.pool_lifecycle_monitor = Arc::new(PoolLifecycleMonitor::default());
        self.reconnect_gate = ReconnectGate::new(policy);
        self
    }

    /// Share an orchestration control that gracefully retires live requests
    /// and reconnects watches without enabling plaintext or aborting tasks.
    #[must_use]
    pub fn with_reauthentication_control(
        mut self,
        control: SessionReauthenticationControl,
    ) -> Self {
        self.reauthentication = control;
        self.conn = Arc::new(Mutex::new(None));
        self.pool_lifecycle_monitor = Arc::new(PoolLifecycleMonitor::default());
        self.reconnect_gate = ReconnectGate::new(self.lifecycle_policy);
        self
    }

    /// Control used by this client for explicit graceful reauthentication.
    pub fn reauthentication_control(&self) -> SessionReauthenticationControl {
        self.reauthentication.clone()
    }

    async fn send_request_classified(
        &self,
        req: Request,
    ) -> Result<NegotiatedResponse, RemoteRequestFailure> {
        validate_request_profile(&req).map_err(|_| RemoteRequestFailure::Protocol)?;
        validate_request_payload_limit(&req, conservative_payload_budget(self.max_frame_size))
            .map_err(RemoteRequestFailure::from_store_preflight)?;
        let operation_deadline = tokio::time::Instant::now()
            .checked_add(self.deadline)
            .ok_or(RemoteRequestFailure::Protocol)?;
        let mut last_failure = None;
        let transmission_started = AtomicBool::new(false);
        let pretransmission_failure = StdMutex::new(None);
        let attempts = async {
            let mut backoff = self.lifecycle_policy.reconnect_backoff_min();
            loop {
                transmission_started.store(false, Ordering::Release);
                match self
                    .do_request(
                        &req,
                        operation_deadline,
                        Some(&transmission_started),
                        &pretransmission_failure,
                    )
                    .await
                {
                    Ok(resp) => return Ok(resp),
                    Err(attempt) => {
                        let failure = attempt.failure;
                        if !failure.is_retryable() {
                            return Err(failure);
                        }
                        METRICS
                            .session_net_reconnect_attempts
                            .fetch_add(1, Ordering::Relaxed);
                        if failure != RemoteRequestFailure::ConnectionRetiring {
                            METRICS
                                .session_net_reconnect_failures
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        last_failure = Some(failure);
                        if !attempt.request_may_have_reached_server {
                            transmission_started.store(false, Ordering::Release);
                        }
                        tokio::time::sleep(backoff).await;
                        backoff = self.lifecycle_policy.next_backoff(backoff);
                    }
                }
            }
        };
        match tokio::time::timeout_at(operation_deadline, attempts).await {
            Ok(res) => res,
            Err(_) if transmission_started.load(Ordering::Acquire) => {
                Err(RemoteRequestFailure::Timeout)
            }
            Err(_) => Err(pretransmission_failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .or(last_failure)
                .unwrap_or(RemoteRequestFailure::Timeout)),
        }
    }

    async fn send_request_with_retry(&self, req: Request) -> Result<Response, StoreError> {
        self.send_request_with_retry_negotiated(req)
            .await
            .map(|response| response.response)
    }

    /// Dispatch one mutation exactly once from the client's point of view.
    ///
    /// A transport failure may occur after the server crossed its mutation
    /// boundary. Automatically reconnecting and resubmitting would be unsafe
    /// once the server's bounded outcome window is unavailable (for example
    /// after restart or pressure). The caller receives a typed unavailable
    /// result and must re-read authoritative state before deriving a new CAS.
    async fn send_mutation_once(&self, req: Request) -> Result<Response, StoreError> {
        validate_request_profile(&req).map_err(|_| {
            StoreError::BackendUnavailable(
                "session mutation violates the transport profile".to_string(),
            )
        })?;
        validate_request_payload_limit(&req, conservative_payload_budget(self.max_frame_size))?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.deadline)
            .ok_or_else(|| {
                StoreError::BackendUnavailable(
                    "remote session mutation deadline is not representable".to_string(),
                )
            })?;
        self.do_request_once_until(&req, deadline)
            .await
            .map(|response| response.response)
            .map_err(|attempt| match attempt.failure {
                RemoteRequestFailure::PayloadTooLarge { actual, max } => {
                    StoreError::PayloadTooLarge { actual, max }
                }
                _ if !attempt.request_may_have_reached_server => StoreError::BackendUnavailable(
                    "remote session mutation failed before transmission".to_string(),
                ),
                _ => {
                    METRICS
                        .session_net_backend_ambiguous_outcomes
                        .fetch_add(1, Ordering::Relaxed);
                    StoreError::CasIdempotencyOutcomeUnavailable
                }
            })
    }

    /// Dispatch one non-CAS mutation exactly once. A transport or deadline
    /// failure after request transmission is an ambiguous outcome, never an
    /// invitation to reconnect and repeat the effect.
    async fn send_backend_mutation_once(&self, req: Request) -> Result<Response, StoreError> {
        validate_request_profile(&req).map_err(|_| {
            StoreError::BackendUnavailable(
                "session mutation violates the transport profile".to_string(),
            )
        })?;
        validate_request_payload_limit(&req, conservative_payload_budget(self.max_frame_size))?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.deadline)
            .ok_or_else(|| {
                StoreError::BackendUnavailable(
                    "remote session mutation deadline is not representable".to_string(),
                )
            })?;
        self.do_request_once_until(&req, deadline)
            .await
            .map(|response| response.response)
            .map_err(|attempt| match attempt.failure {
                RemoteRequestFailure::PayloadTooLarge { actual, max } => {
                    StoreError::PayloadTooLarge { actual, max }
                }
                _ if !attempt.request_may_have_reached_server => StoreError::BackendUnavailable(
                    "remote session mutation failed before transmission".to_string(),
                ),
                _ => {
                    METRICS
                        .session_net_backend_ambiguous_outcomes
                        .fetch_add(1, Ordering::Relaxed);
                    StoreError::BackendOperationOutcomeUnavailable
                }
            })
    }

    /// Dispatch one lease mutation exactly once. Unknown transport outcomes
    /// invalidate the caller's lease authority and cannot be retried safely.
    async fn send_lease_mutation_once(&self, req: Request) -> Result<Response, LeaseError> {
        validate_request_profile(&req).map_err(|_| {
            LeaseError::Backend("lease mutation violates the transport profile".to_string())
        })?;
        validate_request_payload_limit(&req, conservative_payload_budget(self.max_frame_size))
            .map_err(LeaseError::from)?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.deadline)
            .ok_or_else(|| {
                LeaseError::Backend(
                    "remote lease mutation deadline is not representable".to_string(),
                )
            })?;
        self.do_request_once_until(&req, deadline)
            .await
            .map(|response| response.response)
            .map_err(|attempt| {
                if attempt.request_may_have_reached_server {
                    METRICS
                        .session_net_backend_ambiguous_outcomes
                        .fetch_add(1, Ordering::Relaxed);
                    LeaseError::OperationOutcomeUnavailable
                } else {
                    LeaseError::Backend(
                        "remote lease mutation failed before transmission".to_string(),
                    )
                }
            })
    }

    async fn do_request_once_until(
        &self,
        req: &Request,
        deadline: tokio::time::Instant,
    ) -> Result<NegotiatedResponse, RemoteRequestAttemptFailure> {
        let transmission_started = AtomicBool::new(false);
        let pretransmission_failure = StdMutex::new(None);
        let attempts = async {
            let mut backoff = self.lifecycle_policy.reconnect_backoff_min();
            loop {
                transmission_started.store(false, Ordering::Release);
                match self
                    .do_request(
                        req,
                        deadline,
                        Some(&transmission_started),
                        &pretransmission_failure,
                    )
                    .await
                {
                    Err(attempt) if attempt.failure == RemoteRequestFailure::ConnectionRetiring => {
                        // Only this complete authenticated frame proves that
                        // repeating a mutation cannot duplicate an effect.
                        transmission_started.store(false, Ordering::Release);
                        METRICS
                            .session_net_reconnect_attempts
                            .fetch_add(1, Ordering::Relaxed);
                        let now = tokio::time::Instant::now();
                        let retry_at = now.checked_add(backoff).unwrap_or(deadline).min(deadline);
                        tokio::time::sleep_until(retry_at).await;
                        backoff = self.lifecycle_policy.next_backoff(backoff);
                    }
                    result => return result,
                }
            }
        };
        match tokio::time::timeout_at(deadline, attempts).await {
            Ok(result) => result,
            Err(_) => Err(RemoteRequestAttemptFailure {
                failure: if transmission_started.load(Ordering::Acquire) {
                    RemoteRequestFailure::Timeout
                } else {
                    pretransmission_failure
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .unwrap_or(RemoteRequestFailure::Timeout)
                },
                request_may_have_reached_server: transmission_started.load(Ordering::Acquire),
                invalidates_contract: false,
            }),
        }
    }

    async fn send_request_with_retry_negotiated(
        &self,
        req: Request,
    ) -> Result<NegotiatedResponse, StoreError> {
        self.send_request_classified(req)
            .await
            .map_err(|failure| match failure {
                RemoteRequestFailure::PayloadTooLarge { actual, max } => {
                    StoreError::PayloadTooLarge { actual, max }
                }
                RemoteRequestFailure::ResponseContract => {
                    StoreError::BackendUnavailable(REMOTE_PROTOCOL_VIOLATION.to_string())
                }
                RemoteRequestFailure::ReplicationLogResponseContract => {
                    StoreError::InvalidReplicationSequence
                }
                _ => StoreError::BackendUnavailable(format!(
                    "remote session backend request failed: {}",
                    failure.reason_code()
                )),
            })
    }

    async fn do_request(
        &self,
        req: &Request,
        operation_deadline: tokio::time::Instant,
        transmission_started: Option<&AtomicBool>,
        pretransmission_failure: &StdMutex<Option<RemoteRequestFailure>>,
    ) -> Result<NegotiatedResponse, RemoteRequestAttemptFailure> {
        self.ensure_pool_lifecycle_monitor();
        let mut guard = self.conn.lock().await;

        // Take the connection out of the slot for the duration of the
        // exchange. If this future is cancelled mid-exchange (the per-call
        // deadline can fire between writing a request and reading its
        // response), a connection left in the slot would deliver the stale
        // response of the cancelled request to the next caller; taking it
        // means cancellation drops the connection and the next request
        // reconnects cleanly. Errors drop it for the same reason.
        let mut candidate = guard.take();
        let mut backoff = self.lifecycle_policy.reconnect_backoff_min();
        let mut conn = loop {
            if tokio::time::Instant::now() >= operation_deadline {
                return Err(RemoteRequestAttemptFailure {
                    failure: pretransmission_failure
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .unwrap_or(RemoteRequestFailure::Timeout),
                    request_may_have_reached_server: false,
                    invalidates_contract: false,
                });
            }
            let from_pool = candidate.is_some();
            let mut candidate_connection = match candidate.take() {
                Some(connection) => connection,
                None => match self.connect(operation_deadline).await {
                    Ok(connection) => connection,
                    Err(error) => {
                        let attempt = RemoteRequestAttemptFailure::before_connection(&error);
                        *pretransmission_failure
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some(attempt.failure);
                        if !attempt.failure.is_retryable() {
                            return Err(attempt);
                        }
                        METRICS
                            .session_net_reconnect_attempts
                            .fetch_add(1, Ordering::Relaxed);
                        if attempt.failure != RemoteRequestFailure::ConnectionRetiring {
                            METRICS
                                .session_net_reconnect_failures
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        let now = tokio::time::Instant::now();
                        let retry_at = now
                            .checked_add(backoff)
                            .unwrap_or(operation_deadline)
                            .min(operation_deadline);
                        tokio::time::sleep_until(retry_at).await;
                        backoff = self.lifecycle_policy.next_backoff(backoff);
                        continue;
                    }
                },
            };
            // Capture time only after connection and application bootstrap
            // complete. A slow bootstrap must not admit work using an Instant
            // from before this connection existed.
            let now = tokio::time::Instant::now();
            let current_generation = self.reauthentication.generation();
            let current_material_epoch = self
                .tls_config
                .as_ref()
                .map(|config| config.material_status().epoch());
            self.pool_lifecycle_monitor.apply_to(
                &mut candidate_connection.lifecycle,
                current_generation,
                current_material_epoch,
                now,
                &directed_connection_key(
                    b"direct",
                    self.binding.local_replica_id().as_str(),
                    self.binding.remote_replica_id().as_str(),
                ),
            );
            let mismatch = candidate_connection
                .lifecycle
                .evidence_mismatch_reason(current_generation, current_material_epoch);
            let scheduled_pool_rotation = from_pool
                && candidate_connection.lifecycle.rotation_was_observed()
                && mismatch.is_some();
            if (mismatch.is_none() || scheduled_pool_rotation)
                && candidate_connection.lifecycle.retirement(now).is_none()
            {
                if mismatch.is_none() {
                    self.reconnect_gate
                        .mark_usable(current_generation, current_material_epoch);
                }
                *pretransmission_failure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                self.pool_lifecycle_monitor.acknowledge_admission(
                    candidate_connection.lifecycle.admitted_generation(),
                    candidate_connection.lifecycle.admitted_material_epoch(),
                );
                break candidate_connection;
            }
            if let Some(reason) = mismatch.filter(|_| !scheduled_pool_rotation) {
                candidate_connection
                    .lifecycle
                    .record_forced_retirement(reason);
            }
            tracing::debug!(
                reason = "retired",
                "session connection retired before dispatch"
            );
            METRICS
                .session_net_reconnect_attempts
                .fetch_add(1, Ordering::Relaxed);
            *pretransmission_failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(RemoteRequestFailure::Timeout);
            let retry_at = now
                .checked_add(backoff)
                .unwrap_or(operation_deadline)
                .min(operation_deadline);
            tokio::time::sleep_until(retry_at).await;
            backoff = self.lifecycle_policy.next_backoff(backoff);
        };
        let request = match req {
            Request::CompareAndSet { op, request_id, .. } => Request::CompareAndSet {
                op: op.clone(),
                request_id: request_id.clone(),
                idempotency_epoch: Some(conn.cas_idempotency_epoch.hyphenated().to_string()),
            },
            _ => req.clone(),
        };
        let transport_limit = conservative_payload_budget(conn.frame_limits.request_frame_size)
            .min(conservative_payload_budget(
                conn.frame_limits.response_frame_size,
            ));
        if let Err(error) = validate_request_payload_limit(&request, transport_limit) {
            // No bytes were emitted, so the authenticated connection remains
            // clean and can safely serve a later bounded request.
            *guard = Some(conn);
            return Err(RemoteRequestAttemptFailure::from_store_preflight(error));
        }

        let mut lifecycle = conn.lifecycle.clone();
        let mut reauthentication_rx = self.reauthentication.subscribe();
        let mut material_rx = self
            .tls_config
            .as_ref()
            .map(opc_tls::AuthenticatedClientConfig::subscribe_material_changes);
        let exchange_result = {
            let exchange = self.exchange(
                &request,
                &mut conn,
                operation_deadline,
                transmission_started,
            );
            tokio::pin!(exchange);
            loop {
                let now = tokio::time::Instant::now();
                self.pool_lifecycle_monitor.apply_to(
                    &mut lifecycle,
                    self.reauthentication.generation(),
                    self.tls_config
                        .as_ref()
                        .map(|config| config.material_status().epoch()),
                    now,
                    &directed_connection_key(
                        b"direct",
                        self.binding.local_replica_id().as_str(),
                        self.binding.remote_replica_id().as_str(),
                    ),
                );
                let lifecycle_hard_deadline = lifecycle.hard_deadline().map_err(|_| {
                    RemoteRequestAttemptFailure::before_transmission(
                        &ProtocolError::InvalidWireValue,
                    )
                })?;
                let hard_deadline = lifecycle_hard_deadline.min(operation_deadline);
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(hard_deadline) => {
                        let now = tokio::time::Instant::now();
                        if now >= lifecycle_hard_deadline {
                            let _ = lifecycle.retirement(now);
                            lifecycle.record_hard_overrun();
                        }
                        break Err(RemoteRequestAttemptFailure {
                            failure: RemoteRequestFailure::Timeout,
                            request_may_have_reached_server: transmission_started
                                .is_none_or(|started| started.load(Ordering::Acquire)),
                            invalidates_contract: false,
                        });
                    }
                    result = &mut exchange => break result,
                    _ = reauthentication_rx.changed() => {}
                    _ = wait_for_material_change(&mut material_rx) => {}
                }
            }
        };
        conn.lifecycle = lifecycle;

        match exchange_result {
            Ok(resp) => {
                if matches!(resp, Response::ConnectionRetiring) {
                    return Err(RemoteRequestAttemptFailure::connection_retiring());
                }
                if let Some(failure) = response_contract_failure(&request, &resp) {
                    discard_replication_payloads_from_response(resp);
                    self.clear_cached_capabilities();
                    return Err(RemoteRequestAttemptFailure::response_contract_violation(
                        failure,
                    ));
                }
                let requires_fresh_connection = response_requires_fresh_connection(&resp);
                let response = NegotiatedResponse {
                    response: resp,
                    contract_profile: conn.contract_profile,
                    frame_limits: conn.frame_limits,
                };
                let now = tokio::time::Instant::now();
                self.pool_lifecycle_monitor.apply_to(
                    &mut conn.lifecycle,
                    self.reauthentication.generation(),
                    self.tls_config
                        .as_ref()
                        .map(|config| config.material_status().epoch()),
                    now,
                    &directed_connection_key(
                        b"direct",
                        self.binding.local_replica_id().as_str(),
                        self.binding.remote_replica_id().as_str(),
                    ),
                );
                if !requires_fresh_connection && conn.lifecycle.retirement(now).is_none() {
                    *guard = Some(conn);
                }
                Ok(response)
            }
            Err(attempt) => {
                if attempt.invalidates_contract {
                    self.clear_cached_capabilities();
                }
                Err(attempt)
            }
        }
    }

    fn ensure_pool_lifecycle_monitor(&self) {
        let mut task = self
            .pool_lifecycle_monitor
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if task.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        let weak_connection = Arc::downgrade(&self.conn);
        let tls_config = self.tls_config.clone();
        let reauthentication = self.reauthentication.clone();
        let reconnect_gate = Arc::clone(&self.reconnect_gate);
        // Subscribe before spawning so a publication between this function
        // returning and the task's first poll is still observed.
        let mut reauthentication_rx = reauthentication.subscribe();
        let mut material_rx = tls_config
            .as_ref()
            .map(opc_tls::AuthenticatedClientConfig::subscribe_material_changes);
        let weak_monitor = Arc::downgrade(&self.pool_lifecycle_monitor);
        let edge_key = directed_connection_key(
            b"direct",
            self.binding.local_replica_id().as_str(),
            self.binding.remote_replica_id().as_str(),
        );
        *task = Some(tokio::spawn(async move {
            loop {
                enum Change {
                    Generation,
                    Material,
                }
                let change = tokio::select! {
                    biased;
                    changed = reauthentication_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        Change::Generation
                    }
                    _ = wait_for_material_change(&mut material_rx) => Change::Material,
                };
                // Preserve publication time across a busy connection: the
                // monitor may wait for the one-in-flight mutex, but the stable
                // jitter remains anchored to this event rather than checkout.
                let observed_at = tokio::time::Instant::now();
                let generation = reauthentication.generation();
                let material_epoch = tls_config
                    .as_ref()
                    .map(|config| config.material_status().epoch());
                reconnect_gate.observe_epoch(generation, material_epoch);
                let Some(monitor) = weak_monitor.upgrade() else {
                    return;
                };
                match change {
                    Change::Generation => monitor.publish_generation(generation, observed_at),
                    Change::Material => monitor.publish_material(material_epoch, observed_at),
                }
                drop(monitor);
                let Some(connection) = weak_connection.upgrade() else {
                    return;
                };
                let mut connection = connection.lock().await;
                if let Some(connection) = connection.as_mut() {
                    let Some(monitor) = weak_monitor.upgrade() else {
                        return;
                    };
                    monitor.apply_to(
                        &mut connection.lifecycle,
                        generation,
                        material_epoch,
                        observed_at,
                        &edge_key,
                    );
                }
            }
        }));
    }

    async fn connect(
        &self,
        operation_deadline: tokio::time::Instant,
    ) -> Result<Connection, ConnectionOpenError> {
        let result = open_connection(
            self.target.clone(),
            self.tls_config.clone(),
            self.binding.clone(),
            self.max_frame_size,
            operation_deadline,
            OutboundConnectionLifecycle {
                policy: self.lifecycle_policy,
                reauthentication: self.reauthentication.clone(),
                reconnect_gate: Arc::clone(&self.reconnect_gate),
            },
        )
        .await;
        if let Ok(connection) = &result {
            let changed = self
                .negotiated_frame_limits()
                .is_some_and(|limits| limits != connection.frame_limits);
            if changed {
                self.clear_cached_capabilities();
            }
            if let Ok(mut limits) = self.negotiated_frame_limits.write() {
                *limits = Some(connection.frame_limits);
            }
        }
        if result.as_ref().is_err_and(|error| {
            matches!(error, ConnectionOpenError::Protocol(error) if invalidates_negotiated_contract(error))
        }) {
            self.clear_cached_capabilities();
        }
        result
    }

    async fn exchange(
        &self,
        req: &Request,
        conn: &mut Connection,
        operation_deadline: tokio::time::Instant,
        transmission_started: Option<&AtomicBool>,
    ) -> Result<Response, RemoteRequestAttemptFailure> {
        if self.tls_config.is_some()
            && conn.authenticated_peer.as_ref() != Some(self.binding.remote_replica_id())
        {
            return Err(RemoteRequestAttemptFailure::before_transmission(
                &ProtocolError::Authentication,
            ));
        }
        if conn.contract_profile != CURRENT_CONTRACT_PROFILE {
            return Err(RemoteRequestAttemptFailure::before_transmission(
                &ProtocolError::ContractMismatch,
            ));
        }
        if let Some(transmission_started) = transmission_started {
            transmission_started.store(true, Ordering::Release);
        }
        let write_result = write_frame_bounded_until(
            &mut conn.writer,
            req,
            conn.frame_limits.request_frame_size,
            operation_deadline,
        )
        .await;
        if let Err(write_error) = write_result {
            // A server can win the retirement/request race and return the
            // authenticated no-dispatch proof while this half observes a
            // write failure. Only a fully decoded fixed control changes the
            // conservative ambiguous classification; partial frames, EOF,
            // and every other response retain the original write failure.
            return match read_response_frame(
                &mut conn.reader,
                conn.frame_limits.response_frame_size,
            )
            .await
            {
                Ok(Response::ConnectionRetiring) => {
                    Err(RemoteRequestAttemptFailure::connection_retiring())
                }
                Ok(other) => {
                    discard_replication_payloads_from_response(other);
                    Err(RemoteRequestAttemptFailure::after_transmission_started(
                        &write_error,
                    ))
                }
                Err(_) => Err(RemoteRequestAttemptFailure::after_transmission_started(
                    &write_error,
                )),
            };
        }
        read_response_frame(&mut conn.reader, conn.frame_limits.response_frame_size)
            .await
            .map_err(|error| RemoteRequestAttemptFailure::after_transmission_started(&error))
    }

    fn remember_capabilities(
        &self,
        contract_profile: ContractProfile,
        frame_limits: NegotiatedFrameLimits,
        caps: BackendCapabilities,
    ) {
        if let Ok(mut cached) = self.cached_capabilities.write() {
            *cached = Some((contract_profile, frame_limits, caps));
        }
    }

    fn clear_cached_capabilities(&self) {
        if let Ok(mut cached) = self.cached_capabilities.write() {
            *cached = None;
        }
    }

    fn negotiated_frame_limits(&self) -> Option<NegotiatedFrameLimits> {
        self.negotiated_frame_limits
            .read()
            .ok()
            .and_then(|limits| *limits)
    }

    fn cached_capabilities(
        &self,
    ) -> Option<(ContractProfile, NegotiatedFrameLimits, BackendCapabilities)> {
        let frame_limits = self.negotiated_frame_limits()?;
        self.cached_capabilities
            .read()
            .ok()
            .and_then(|cached| *cached)
            .filter(|(profile, cached_limits, _)| {
                *profile == CURRENT_CONTRACT_PROFILE && *cached_limits == frame_limits
            })
    }

    fn capabilities_for_transport(
        mut caps: BackendCapabilities,
        fresh_v5_negotiation: bool,
        contract_profile: ContractProfile,
        frame_limits: NegotiatedFrameLimits,
    ) -> BackendCapabilities {
        if contract_profile != CURRENT_CONTRACT_PROFILE {
            return unavailable_capabilities();
        }
        let response_frame_size = frame_limits.response_frame_size;
        caps.max_value_bytes = caps
            .max_value_bytes
            .min(conservative_payload_budget(response_frame_size));
        let request_frame_size = frame_limits.request_frame_size;
        caps.max_value_bytes = caps
            .max_value_bytes
            .min(conservative_payload_budget(request_frame_size));
        if !fresh_v5_negotiation || response_frame_size < MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE {
            caps.restore_scan = false;
        }
        caps
    }

    fn capabilities_after_probe_failure(&self, reason: &str) -> BackendCapabilities {
        if let Some((contract_profile, frame_limits, caps)) = self.cached_capabilities() {
            tracing::warn!(
                target = %self.target,
                reason,
                "remote capabilities probe failed; using cached capabilities with negotiated operations masked"
            );
            Self::capabilities_for_transport(caps, false, contract_profile, frame_limits)
        } else {
            tracing::warn!(
                target = %self.target,
                reason,
                "remote capabilities probe failed before any cached success; returning unavailable capabilities"
            );
            unavailable_capabilities()
        }
    }

    async fn discard_connection(&self) {
        self.conn.lock().await.take();
    }

    async fn store_protocol_violation(&self, response: Response) -> StoreError {
        discard_replication_payloads_from_response(response);
        self.discard_connection().await;
        self.clear_cached_capabilities();
        StoreError::BackendUnavailable(REMOTE_PROTOCOL_VIOLATION.to_string())
    }

    async fn cas_mutation_protocol_violation(&self, response: Response) -> StoreError {
        discard_replication_payloads_from_response(response);
        self.discard_connection().await;
        self.clear_cached_capabilities();
        METRICS
            .session_net_backend_ambiguous_outcomes
            .fetch_add(1, Ordering::Relaxed);
        StoreError::CasIdempotencyOutcomeUnavailable
    }

    async fn backend_mutation_protocol_violation(&self, response: Response) -> StoreError {
        discard_replication_payloads_from_response(response);
        self.discard_connection().await;
        self.clear_cached_capabilities();
        METRICS
            .session_net_backend_ambiguous_outcomes
            .fetch_add(1, Ordering::Relaxed);
        StoreError::BackendOperationOutcomeUnavailable
    }

    async fn lease_mutation_protocol_violation(&self, response: Response) -> LeaseError {
        discard_replication_payloads_from_response(response);
        self.discard_connection().await;
        self.clear_cached_capabilities();
        METRICS
            .session_net_backend_ambiguous_outcomes
            .fetch_add(1, Ordering::Relaxed);
        LeaseError::OperationOutcomeUnavailable
    }

    async fn readiness_protocol_violation(&self, response: Response) -> ReplicaReadinessFailure {
        discard_replication_payloads_from_response(response);
        self.discard_connection().await;
        self.clear_cached_capabilities();
        ReplicaReadinessFailure::Protocol
    }
}

#[async_trait]
impl SessionBackend for RemoteSessionBackend {
    fn restore_scan_cursor_profile(&self) -> Option<RestoreScanCursorProfile> {
        Some(RestoreScanCursorProfile::DurableOpaqueV1)
    }

    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        Some(BackendInstanceIdentity::for_shared(&self.conn))
    }

    fn peer_binding(&self) -> Option<BackendPeerBinding> {
        self.tls_config
            .as_ref()
            .map(|_| self.binding.backend_peer_binding())
    }

    async fn capabilities(&self) -> BackendCapabilities {
        match self
            .send_request_with_retry_negotiated(Request::Capabilities)
            .await
        {
            Ok(NegotiatedResponse {
                response: Response::Capabilities(caps),
                contract_profile,
                frame_limits,
            }) => {
                let caps =
                    Self::capabilities_for_transport(caps, true, contract_profile, frame_limits);
                self.remember_capabilities(contract_profile, frame_limits, caps);
                caps
            }
            Ok(NegotiatedResponse { response, .. }) => {
                discard_replication_payloads_from_response(response);
                self.discard_connection().await;
                self.clear_cached_capabilities();
                tracing::warn!(
                    target = %self.target,
                    reason = "unexpected_response",
                    "remote capabilities probe violated the negotiated contract; returning unavailable capabilities"
                );
                unavailable_capabilities()
            }
            Err(err) => {
                let reason = store_error_kind(&err);
                self.capabilities_after_probe_failure(reason)
            }
        }
    }

    async fn preflight_record_expiry(
        &self,
        preflights: &[RecordExpiryPreflight],
    ) -> Result<(), StoreError> {
        validate_record_expiry_preflights_profile(preflights)?;
        if !preflights
            .iter()
            .copied()
            .any(RecordExpiryPreflight::is_finite)
        {
            return Ok(());
        }
        match self
            .send_request_with_retry(Request::RecordExpiryPreflight {
                preflights: preflights.to_vec(),
            })
            .await?
        {
            Response::RecordExpiryPreflight(result) => result,
            response => Err(self.backend_mutation_protocol_violation(response).await),
        }
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        match self
            .send_request_with_retry(Request::Get { key: key.clone() })
            .await?
        {
            Response::Get(res) if get_result_matches_key(key, &res) => res,
            Response::Get(res) => Err(self.store_protocol_violation(Response::Get(res)).await),
            response => Err(self.store_protocol_violation(response).await),
        }
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        validate_stored_record_expiry_profile(&op.new_record)?;
        let expected_key = op.key.clone();
        let response = self
            .send_mutation_once(Request::CompareAndSet {
                op,
                request_id: Some(uuid::Uuid::new_v4().to_string()),
                idempotency_epoch: None,
            })
            .await?;
        if matches!(
            response,
            Response::CompareAndSet(Err(StoreError::CasIdempotencyOutcomeUnavailable))
        ) {
            // The server rotated or lost the bounded retry epoch. Drop this
            // connection so a separately derived future CAS must complete a
            // new authenticated handshake and cannot carry the stale epoch.
            self.conn.lock().await.take();
        }
        match response {
            Response::CompareAndSet(res)
                if compare_and_set_result_matches_key(&expected_key, &res) =>
            {
                res
            }
            Response::CompareAndSet(res) => Err(self
                .cas_mutation_protocol_violation(Response::CompareAndSet(res))
                .await),
            response => Err(self.cas_mutation_protocol_violation(response).await),
        }
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        match self
            .send_backend_mutation_once(Request::DeleteFenced {
                lease: lease.clone(),
            })
            .await?
        {
            Response::DeleteFenced(res) => res,
            response => Err(self.backend_mutation_protocol_violation(response).await),
        }
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        validate_session_ttl(ttl)?;
        match self
            .send_backend_mutation_once(Request::RefreshTtl {
                lease: lease.clone(),
                ttl,
            })
            .await?
        {
            Response::RefreshTtl(res) => res,
            response => Err(self.backend_mutation_protocol_violation(response).await),
        }
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        if ops.len() > MAX_SESSION_NET_BATCH_OPERATIONS {
            return Err(StoreError::ReplicationOperationLimitExceeded);
        }
        validate_session_ops_profile(&ops)?;
        let expected = bounded_session_op_expectations(&ops)?;
        let contains_mutation = ops.iter().any(|op| !matches!(op, SessionOp::Get { .. }));
        let response = if contains_mutation {
            self.send_backend_mutation_once(Request::Batch { ops })
                .await?
        } else {
            self.send_request_with_retry(Request::Batch { ops }).await?
        };
        match response {
            Response::Batch(Ok(results))
                if session_op_results_match_expectations(&expected, &results) =>
            {
                Ok(results)
            }
            Response::Batch(Ok(results)) => {
                drop(results);
                self.discard_connection().await;
                self.clear_cached_capabilities();
                if contains_mutation {
                    METRICS
                        .session_net_backend_ambiguous_outcomes
                        .fetch_add(1, Ordering::Relaxed);
                    Err(StoreError::BackendOperationOutcomeUnavailable)
                } else {
                    Err(StoreError::BackendUnavailable(
                        "remote batch response violated the protocol contract".to_string(),
                    ))
                }
            }
            Response::Batch(Err(error)) => Err(error),
            response if contains_mutation => {
                Err(self.backend_mutation_protocol_violation(response).await)
            }
            response => Err(self.store_protocol_violation(response).await),
        }
    }

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        request.validate()?;
        if request
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_legacy_compatibility())
        {
            return Err(StoreError::CapabilityNotSupported(
                "legacy_remote_restore_scan".to_string(),
            ));
        }
        if self.max_frame_size < MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE {
            return Err(StoreError::RestoreScanResponseTooLarge {
                max_bytes: self.max_frame_size,
            });
        }
        let wire_request = RestoreScanWireRequest::try_from(&request)?;
        let max_response_frame_size =
            checked_wire_frame_size(self.max_frame_size).map_err(|_| {
                StoreError::InvalidRestoreScanRequest(
                    "configured response frame size is outside the negotiated range".to_string(),
                )
            })?;
        let outbound = Request::ScanRestoreRecords {
            request: wire_request,
            max_response_frame_size,
        };
        let response = match self.send_request_with_retry(outbound).await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(
                    target = %self.target,
                    failure = store_error_kind(&error),
                    "remote restore scan failed"
                );
                return Err(error);
            }
        };

        match response {
            Response::ScanRestoreRecords(Ok(page)) => {
                if page.cursor_profile != RestoreScanCursorProfile::DurableOpaqueV1 {
                    self.discard_connection().await;
                    self.clear_cached_capabilities();
                    return Err(StoreError::CapabilityNotSupported(
                        "legacy_remote_restore_scan".to_string(),
                    ));
                }
                if let Err(error) = page.validate_for_request(&request) {
                    self.discard_connection().await;
                    self.clear_cached_capabilities();
                    tracing::warn!(
                        target = %self.target,
                        failure = store_error_kind(&error),
                        "remote restore scan response was rejected"
                    );
                    return Err(error);
                }
                Ok(page)
            }
            Response::ScanRestoreRecords(Err(error)) => {
                tracing::warn!(
                    target = %self.target,
                    failure = store_error_kind(&error),
                    "remote restore scan failed"
                );
                Err(error)
            }
            response => {
                tracing::warn!(
                    target = %self.target,
                    failure = "unexpected_response",
                    "remote restore scan response was rejected"
                );
                Err(self.store_protocol_violation(response).await)
            }
        }
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        match self
            .send_request_with_retry(Request::MaxReplicationSequence)
            .await?
        {
            Response::MaxReplicationSequence(res) => res,
            response => Err(self.store_protocol_violation(response).await),
        }
    }

    async fn probe_replication_head(&self) -> Result<u64, ReplicaReadinessFailure> {
        let response = self
            .send_request_classified(Request::MaxReplicationSequence)
            .await
            .map_err(ReplicaReadinessFailure::from)?;
        match response.response {
            Response::MaxReplicationSequence(Ok(sequence)) => Ok(sequence),
            Response::MaxReplicationSequence(Err(_)) => Err(ReplicaReadinessFailure::Backend),
            response => Err(self.readiness_protocol_violation(response).await),
        }
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let range = ReplicationLogRange::try_new(start, limit)?;
        if range.is_empty() {
            return Ok(Vec::new());
        }
        match self
            .send_request_with_retry(Request::GetReplicationLog { start, limit })
            .await?
        {
            Response::GetReplicationLog(res) => {
                let entries = res?;
                if entries.len() > limit {
                    drop(validate_replication_page_owned(entries));
                    self.discard_connection().await;
                    self.clear_cached_capabilities();
                    return Err(StoreError::BackendUnavailable(
                        "remote replication page violated the protocol contract".to_string(),
                    ));
                }
                match validate_replication_log_page_owned(start, limit, entries) {
                    Ok(entries) => Ok(entries),
                    Err(error) => {
                        self.discard_connection().await;
                        self.clear_cached_capabilities();
                        Err(error)
                    }
                }
            }
            response => Err(self.store_protocol_violation(response).await),
        }
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let entry = entry.into_validated()?;
        match self
            .send_backend_mutation_once(Request::ReplicateEntry { entry })
            .await?
        {
            Response::ReplicateEntry(res) => res,
            response => Err(self.backend_mutation_protocol_violation(response).await),
        }
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        if entries.len() > MAX_SESSION_NET_REBUILD_ENTRIES {
            return Err(StoreError::ReplicationOperationLimitExceeded);
        }
        let entries = validate_replication_prefix_owned(entries)?;
        match self
            .send_backend_mutation_once(Request::RebuildReplicationState { entries })
            .await?
        {
            Response::RebuildReplicationState(res) => res,
            response => Err(self.backend_mutation_protocol_violation(response).await),
        }
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<BoxStream<'static, Result<ReplicationEntry, StoreError>>, StoreError> {
        checked_wire_frame_size(self.max_frame_size).map_err(|_| {
            StoreError::BackendUnavailable(
                "remote watch frame size is outside the negotiated range".to_string(),
            )
        })?;
        let operation_deadline = tokio::time::Instant::now()
            .checked_add(self.deadline)
            .ok_or_else(|| {
                StoreError::BackendUnavailable(
                    "remote watch deadline is not representable".to_string(),
                )
            })?;
        let cursor = ReplicationWatchCursor::new(start_sequence);
        let config = WatchConnectionConfig {
            target: self.target.clone(),
            tls_config: self.tls_config.clone(),
            binding: self.binding.clone(),
            max_frame_size: self.max_frame_size,
            lifecycle_policy: self.lifecycle_policy,
            reauthentication: self.reauthentication.clone(),
            reconnect_gate: Arc::clone(&self.reconnect_gate),
        };
        let mut backoff = self.lifecycle_policy.reconnect_backoff_min();
        let connection = loop {
            match open_watch_connection(&config, cursor, operation_deadline).await {
                Ok(connection) => break connection,
                Err(WatchOpenFailure::Remote(failure)) if failure.is_retryable() => {
                    METRICS
                        .session_net_reconnect_attempts
                        .fetch_add(1, Ordering::Relaxed);
                    if failure != RemoteRequestFailure::ConnectionRetiring {
                        METRICS
                            .session_net_reconnect_failures
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    let now = tokio::time::Instant::now();
                    if now >= operation_deadline {
                        return Err(watch_open_store_error(WatchOpenFailure::Remote(failure)));
                    }
                    let retry_at = now
                        .checked_add(backoff)
                        .unwrap_or(operation_deadline)
                        .min(operation_deadline);
                    tokio::time::sleep_until(retry_at).await;
                    backoff = self.lifecycle_policy.next_backoff(backoff);
                }
                Err(failure) => return Err(watch_open_store_error(failure)),
            }
        };

        let (tx, rx) = tokio::sync::mpsc::channel(WATCH_CHANNEL_CAPACITY);
        let terminal = Arc::new(std::sync::Mutex::new(None));
        let task_terminal = terminal.clone();
        let deadline = self.deadline;
        // Subscribe before spawning so a rotation publication cannot land in
        // the gap between returning the caller-visible stream and first poll.
        let reauthentication_rx = config.reauthentication.subscribe();
        let material_rx = config
            .tls_config
            .as_ref()
            .map(opc_tls::AuthenticatedClientConfig::subscribe_material_changes);
        tokio::spawn(async move {
            let result = read_watch_stream(
                connection,
                cursor,
                tx,
                WatchStreamContext {
                    config,
                    deadline,
                    terminal_error: task_terminal,
                    reauthentication_rx,
                    material_rx,
                },
            )
            .await;
            if let Err(e) = result {
                tracing::debug!(
                    failure = RemoteRequestFailure::from_protocol_error(&e).reason_code(),
                    "watch stream ended"
                );
            }
        });

        Ok(Box::pin(WatchStream {
            rx,
            terminal,
            terminal_delivered: false,
        }))
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        match self.send_request_with_retry(Request::NextLeaseInfo).await? {
            Response::NextLeaseInfo(res) => res,
            response => Err(self.store_protocol_violation(response).await),
        }
    }
}

#[async_trait]
impl SessionLeaseManager for RemoteSessionBackend {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        let expected_owner = owner.clone();
        match self
            .send_lease_mutation_once(Request::AcquireLease {
                key: key.clone(),
                owner,
                ttl,
            })
            .await?
        {
            Response::AcquireLease(Ok(lease))
                if lease.key() == key && lease.owner() == &expected_owner =>
            {
                Ok(lease)
            }
            Response::AcquireLease(Err(error)) => Err(error),
            Response::AcquireLease(Ok(lease)) => Err(self
                .lease_mutation_protocol_violation(Response::AcquireLease(Ok(lease)))
                .await),
            response => Err(self.lease_mutation_protocol_violation(response).await),
        }
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        match self
            .send_lease_mutation_once(Request::RenewLease {
                lease: lease.clone(),
                ttl,
            })
            .await?
        {
            Response::RenewLease(Ok(renewed))
                if renewed.key() == lease.key()
                    && renewed.owner() == lease.owner()
                    && renewed.fence() == lease.fence()
                    && renewed.credential_id() == lease.credential_id() =>
            {
                Ok(renewed)
            }
            Response::RenewLease(Err(error)) => Err(error),
            Response::RenewLease(Ok(renewed)) => Err(self
                .lease_mutation_protocol_violation(Response::RenewLease(Ok(renewed)))
                .await),
            response => Err(self.lease_mutation_protocol_violation(response).await),
        }
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        match self
            .send_lease_mutation_once(Request::ReleaseLease { lease })
            .await?
        {
            Response::ReleaseLease(res) => res,
            response => Err(self.lease_mutation_protocol_violation(response).await),
        }
    }
}

#[derive(Clone)]
struct WatchConnectionConfig {
    target: RemoteTarget,
    tls_config: Option<opc_tls::AuthenticatedClientConfig>,
    binding: RemoteReplicaBinding,
    max_frame_size: usize,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
    reconnect_gate: Arc<ReconnectGate>,
}

async fn open_watch_connection(
    config: &WatchConnectionConfig,
    cursor: ReplicationWatchCursor,
    operation_deadline: tokio::time::Instant,
) -> Result<Connection, WatchOpenFailure> {
    // Complete the dedicated watch handshake before returning a stream so a
    // typed backend rejection cannot be confused with a later disconnect.
    let open = async {
        let mut backoff = config.lifecycle_policy.reconnect_backoff_min();
        let mut connection = loop {
            let mut connection = open_connection(
                config.target.clone(),
                config.tls_config.clone(),
                config.binding.clone(),
                config.max_frame_size,
                operation_deadline,
                OutboundConnectionLifecycle {
                    policy: config.lifecycle_policy,
                    reauthentication: config.reauthentication.clone(),
                    reconnect_gate: Arc::clone(&config.reconnect_gate),
                },
            )
            .await?;
            let now = tokio::time::Instant::now();
            let current_generation = config.reauthentication.generation();
            let current_material_epoch = config
                .tls_config
                .as_ref()
                .map(|tls| tls.material_status().epoch());
            connection.lifecycle.observe_rotation(
                now,
                current_generation,
                current_material_epoch,
                &directed_connection_key(
                    b"direct",
                    config.binding.local_replica_id().as_str(),
                    config.binding.remote_replica_id().as_str(),
                ),
            );
            let mismatch = connection
                .lifecycle
                .evidence_mismatch_reason(current_generation, current_material_epoch);
            if mismatch.is_none() && connection.lifecycle.retirement(now).is_none() {
                break connection;
            }
            if let Some(reason) = mismatch {
                connection.lifecycle.record_forced_retirement(reason);
            }
            let retry_at = now
                .checked_add(backoff)
                .unwrap_or(operation_deadline)
                .min(operation_deadline);
            tokio::time::sleep_until(retry_at).await;
            backoff = config.lifecycle_policy.next_backoff(backoff);
            if tokio::time::Instant::now() >= operation_deadline {
                return Err(ProtocolError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "watch connection admission deadline expired",
                ))
                .into());
            }
        };
        let watch = Request::Watch {
            start_sequence: cursor.first_sequence(),
        };
        let mut lifecycle = connection.lifecycle.clone();
        let mut reauthentication_rx = config.reauthentication.subscribe();
        let mut material_rx = config
            .tls_config
            .as_ref()
            .map(opc_tls::AuthenticatedClientConfig::subscribe_material_changes);
        let response = {
            let transmission_started = AtomicBool::new(false);
            let setup = async {
                transmission_started.store(true, Ordering::Release);
                write_frame_bounded_until(
                    &mut connection.writer,
                    &watch,
                    connection.frame_limits.request_frame_size,
                    operation_deadline,
                )
                .await?;
                read_response_frame(
                    &mut connection.reader,
                    connection.frame_limits.response_frame_size,
                )
                .await
            };
            tokio::pin!(setup);
            loop {
                let now = tokio::time::Instant::now();
                let current_generation = config.reauthentication.generation();
                let current_material_epoch = config
                    .tls_config
                    .as_ref()
                    .map(|tls| tls.material_status().epoch());
                lifecycle.observe_rotation(
                    now,
                    current_generation,
                    current_material_epoch,
                    &directed_connection_key(
                        b"direct",
                        config.binding.local_replica_id().as_str(),
                        config.binding.remote_replica_id().as_str(),
                    ),
                );
                let mismatch =
                    lifecycle.evidence_mismatch_reason(current_generation, current_material_epoch);
                let retired = lifecycle.retirement(now);
                if !transmission_started.load(Ordering::Acquire)
                    && (mismatch.is_some() || retired.is_some())
                {
                    if let Some(reason) = mismatch {
                        lifecycle.record_forced_retirement(reason);
                    }
                    return Err(ProtocolError::Io(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "watch connection retired before setup",
                    ))
                    .into());
                }
                let lifecycle_hard_deadline = lifecycle
                    .hard_deadline()
                    .map_err(|_| ProtocolError::InvalidWireValue)?;
                let hard_deadline = lifecycle_hard_deadline.min(operation_deadline);
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(hard_deadline) => {
                        let now = tokio::time::Instant::now();
                        if now >= lifecycle_hard_deadline {
                            let _ = lifecycle.retirement(now);
                            lifecycle.record_hard_overrun();
                        }
                        return Err(ProtocolError::Io(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "watch setup exceeded the authentication hard deadline",
                        ))
                        .into());
                    }
                    changed = reauthentication_rx.changed() => {
                        if changed.is_err() {
                            return Err(ProtocolError::Authentication.into());
                        }
                    }
                    _ = wait_for_material_change(&mut material_rx) => {}
                    result = &mut setup => break result?,
                }
            }
        };
        connection.lifecycle = lifecycle;
        match response {
            Response::WatchStream => Ok::<_, ConnectionOpenError>(Ok(connection)),
            Response::ConnectionRetiring => Err(ConnectionOpenError::Retired),
            Response::WatchEntry(Err(error))
                if store_error_matches_class(&error, StoreResponseClass::Read) =>
            {
                Ok(Err(error))
            }
            Response::Error { .. } => {
                Err(ProtocolError::BackendUnavailable("watch request rejected".to_string()).into())
            }
            response => {
                discard_replication_payloads_from_response(response);
                Err(ProtocolError::UnexpectedResponse.into())
            }
        }
    };
    match tokio::time::timeout_at(operation_deadline, open).await {
        Ok(Ok(Ok(connection))) => Ok(connection),
        Ok(Ok(Err(error))) => Err(WatchOpenFailure::Backend(error)),
        Ok(Err(error)) => Err(WatchOpenFailure::Remote(
            RemoteRequestFailure::from_connection_error(&error),
        )),
        Err(_) => Err(WatchOpenFailure::Remote(RemoteRequestFailure::Timeout)),
    }
}

#[derive(Debug)]
enum WatchOpenFailure {
    Backend(StoreError),
    Remote(RemoteRequestFailure),
}

fn watch_open_store_error(failure: WatchOpenFailure) -> StoreError {
    match failure {
        WatchOpenFailure::Backend(error) => error,
        WatchOpenFailure::Remote(failure) => StoreError::BackendUnavailable(format!(
            "remote session watch handshake failed: {}",
            failure.reason_code()
        )),
    }
}

async fn wait_for_material_change(receiver: &mut Option<opc_tls::TlsMaterialStatusReceiver>) {
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

async fn wait_for_material_epoch_change(
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
        wait_for_material_change(receiver).await;
    }
}

async fn reconnect_watch(
    config: &WatchConnectionConfig,
    deadline: Duration,
    cursor: ReplicationWatchCursor,
    tx: &tokio::sync::mpsc::Sender<Result<ReplicationEntry, StoreError>>,
) -> Result<Option<Connection>, StoreError> {
    let mut backoff = config.lifecycle_policy.reconnect_backoff_min();
    loop {
        let Some(operation_deadline) = tokio::time::Instant::now().checked_add(deadline) else {
            return Err(StoreError::BackendUnavailable(
                "remote session watch deadline is not representable".to_string(),
            ));
        };
        METRICS
            .session_net_reconnect_attempts
            .fetch_add(1, Ordering::Relaxed);
        let open = open_watch_connection(config, cursor, operation_deadline);
        tokio::pin!(open);
        let result = tokio::select! {
            biased;
            _ = tx.closed() => return Ok(None),
            result = &mut open => result,
        };
        match result {
            Ok(connection) => return Ok(Some(connection)),
            Err(WatchOpenFailure::Remote(failure)) if failure.is_retryable() => {
                if failure != RemoteRequestFailure::ConnectionRetiring {
                    METRICS
                        .session_net_reconnect_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
                tokio::select! {
                    _ = tx.closed() => return Ok(None),
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = config.lifecycle_policy.next_backoff(backoff);
            }
            Err(WatchOpenFailure::Remote(failure)) => {
                return Err(watch_open_store_error(WatchOpenFailure::Remote(failure)));
            }
            Err(WatchOpenFailure::Backend(error)) => return Err(error),
        }
    }
}

struct WatchStreamContext {
    config: WatchConnectionConfig,
    deadline: Duration,
    terminal_error: Arc<std::sync::Mutex<Option<StoreError>>>,
    reauthentication_rx: tokio::sync::watch::Receiver<u64>,
    material_rx: Option<opc_tls::TlsMaterialStatusReceiver>,
}

async fn read_watch_stream(
    connection: Connection,
    cursor: ReplicationWatchCursor,
    tx: tokio::sync::mpsc::Sender<Result<ReplicationEntry, StoreError>>,
    context: WatchStreamContext,
) -> Result<(), ProtocolError> {
    let WatchStreamContext {
        config,
        deadline,
        terminal_error,
        mut reauthentication_rx,
        mut material_rx,
    } = context;
    let mut connection = Some(connection);
    let mut expected_sequence = cursor.first_sequence();

    loop {
        // Lifecycle publications must never cancel and recreate a partially
        // consumed frame read on the same socket. Preserve the exact future
        // until a full frame arrives or soft retirement drops the connection.
        let frame = {
            let connection = connection
                .as_mut()
                .expect("watch connection is present while reading");
            let frame_read = read_response_frame(
                &mut connection.reader,
                connection.frame_limits.response_frame_size,
            );
            tokio::pin!(frame_read);
            loop {
                let now = tokio::time::Instant::now();
                connection.lifecycle.observe_rotation(
                    now,
                    config.reauthentication.generation(),
                    config
                        .tls_config
                        .as_ref()
                        .map(|config| config.material_status().epoch()),
                    &directed_connection_key(
                        b"direct",
                        config.binding.local_replica_id().as_str(),
                        config.binding.remote_replica_id().as_str(),
                    ),
                );
                if connection.lifecycle.retirement(now).is_some() {
                    break Err(ProtocolError::Io(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "watch connection retired",
                    )));
                }
                let retire_at = connection.lifecycle.retire_at();
                tokio::select! {
                    biased;
                    _ = tx.closed() => return Ok(()),
                    _ = reauthentication_rx.changed() => {}
                    _ = wait_for_material_change(&mut material_rx) => {}
                    _ = tokio::time::sleep_until(retire_at) => {}
                    frame = &mut frame_read => break frame,
                }
            }
        };
        match frame {
            Ok(Response::WatchEntry(Ok(entry))) => {
                let entry = match entry.into_validated() {
                    Ok(entry) if entry.sequence == expected_sequence => entry,
                    Ok(entry) => {
                        discard_replication_payloads_from_response(Response::WatchEntry(Ok(entry)));
                        set_watch_terminal(
                            &terminal_error,
                            StoreError::BackendUnavailable(
                                "remote session watch failed: protocol".to_string(),
                            ),
                        );
                        break;
                    }
                    Err(_) => {
                        set_watch_terminal(
                            &terminal_error,
                            StoreError::BackendUnavailable(
                                "remote session watch failed: protocol".to_string(),
                            ),
                        );
                        break;
                    }
                };
                let terminal_sequence = expected_sequence == u64::MAX;
                match tx.try_send(Ok(entry)) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(item)) => {
                        if let Ok(entry) = item {
                            discard_replication_entry_iteratively(entry);
                        }
                        break;
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(item)) => {
                        if let Ok(entry) = item {
                            discard_replication_entry_iteratively(entry);
                        }
                        METRICS
                            .session_net_watch_slow_consumers
                            .fetch_add(1, Ordering::Relaxed);
                        set_watch_terminal(
                            &terminal_error,
                            StoreError::BackendUnavailable(
                                "remote session watch consumer is too slow".to_string(),
                            ),
                        );
                        break;
                    }
                }
                if terminal_sequence {
                    break;
                }
                // Resume only after the item crossed the caller-visible
                // delivery boundary. A disconnect before this point replays
                // the item; one after it resumes at the checked successor.
                expected_sequence = next_replication_sequence(expected_sequence)
                    .map_err(|_| ProtocolError::InvalidWireValue)?;
            }
            Ok(Response::WatchEntry(Err(error))) => {
                let error = if store_error_matches_class(&error, StoreResponseClass::Read) {
                    error
                } else {
                    StoreError::BackendUnavailable(
                        "remote session watch failed: protocol".to_string(),
                    )
                };
                set_watch_terminal(&terminal_error, error);
                break;
            }
            Ok(response) => {
                discard_replication_payloads_from_response(response);
                set_watch_terminal(
                    &terminal_error,
                    StoreError::BackendUnavailable("unexpected watch frame".into()),
                );
                break;
            }
            Err(ProtocolError::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                // Close the retired/broken socket before dialing. Keeping it
                // alive until the replacement handshake completes can
                // deadlock a one-connection peer waiting for this EOF.
                drop(connection.take());
                let cursor = ReplicationWatchCursor::new(expected_sequence);
                match reconnect_watch(&config, deadline, cursor, &tx).await {
                    Ok(Some(reconnected)) => connection = Some(reconnected),
                    Ok(None) => break,
                    Err(error) => {
                        set_watch_terminal(&terminal_error, error);
                        break;
                    }
                }
            }
            Err(e) => {
                let reason = RemoteRequestFailure::from_protocol_error(&e).reason_code();
                set_watch_terminal(
                    &terminal_error,
                    StoreError::BackendUnavailable(format!(
                        "remote session watch failed: {reason}"
                    )),
                );
                break;
            }
        }
    }

    Ok(())
}

fn store_error_kind(err: &StoreError) -> &'static str {
    match err {
        StoreError::NotFound => "not_found",
        StoreError::StaleFence => "stale_fence",
        StoreError::CasConflict => "cas_conflict",
        StoreError::CasIdempotencyConflict => "cas_idempotency_conflict",
        StoreError::CasIdempotencyOutcomeUnavailable => "cas_idempotency_outcome_unavailable",
        StoreError::BackendOperationOutcomeUnavailable => "backend_operation_outcome_unavailable",
        StoreError::CapabilityNotSupported(_) => "capability_not_supported",
        StoreError::BackendUnavailable(_) => "backend_unavailable",
        StoreError::InvalidKey(_) => "invalid_key",
        StoreError::InvalidReplicationSequence => "invalid_replication_sequence",
        StoreError::InvalidReplicationLogRange => "invalid_replication_log_range",
        StoreError::ReplicationLogPageTooLarge { .. } => "replication_log_page_too_large",
        StoreError::ReplicationLogCursorCompacted { .. } => "replication_log_cursor_compacted",
        StoreError::ReplicationWatchCatchUpRequired => "replication_watch_catch_up_required",
        StoreError::ReplicationOperationLimitExceeded => "replication_operation_limit_exceeded",
        StoreError::InvalidSessionTtl => "invalid_session_ttl",
        StoreError::InvalidRecordExpiry => "invalid_record_expiry",
        StoreError::RecordExpiryPreflightLimitExceeded => "record_expiry_preflight_limit_exceeded",
        StoreError::LeaseHeld => "lease_held",
        StoreError::LeaseExpired => "lease_expired",
        StoreError::Crypto(_) => "crypto",
        StoreError::Serialization(_) => "serialization",
        StoreError::PayloadTooLarge { .. } => "payload_too_large",
        StoreError::InvalidRestoreScanRequest(_) => "invalid_restore_scan_request",
        StoreError::InvalidRestoreScanResponse(_) => "invalid_restore_scan_response",
        StoreError::RestoreScanPageTooLarge { .. } => "restore_scan_page_too_large",
        StoreError::RestoreScanCursorStale => "restore_scan_cursor_stale",
        StoreError::RestoreScanWorkBudgetExceeded => "restore_scan_work_budget_exceeded",
        StoreError::RestoreScanResponseTooLarge { .. } => "restore_scan_response_too_large",
    }
}

struct WatchStream {
    rx: tokio::sync::mpsc::Receiver<Result<ReplicationEntry, StoreError>>,
    terminal: Arc<std::sync::Mutex<Option<StoreError>>>,
    terminal_delivered: bool,
}

impl Stream for WatchStream {
    type Item = Result<ReplicationEntry, StoreError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(None) if !self.terminal_delivered => {
                let terminal = self
                    .terminal
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                self.terminal_delivered = terminal.is_some();
                terminal.map_or(Poll::Ready(None), |error| Poll::Ready(Some(Err(error))))
            }
            result => result,
        }
    }
}

fn set_watch_terminal(terminal: &Arc<std::sync::Mutex<Option<StoreError>>>, error: StoreError) {
    let mut slot = terminal
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if slot.is_none() {
        *slot = Some(error);
    }
}

#[cfg(all(test, feature = "insecure-test"))]
mod tests {
    use super::*;
    use crate::protocol::write_frame;
    use futures_util::{FutureExt, StreamExt};
    use opc_session_store::{
        BackendCapabilities, EncryptedSessionPayload, FakeSessionBackend, FenceToken, Generation,
        StateClass, StateType, MAX_REPLICATION_OPERATIONS_PER_ENTRY,
        MAX_REPLICATION_OPERATION_DEPTH,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn successful_hello_ack(hello: &Request) -> Response {
        let requested = match hello {
            Request::Hello {
                requested_response_frame_size: Some(requested),
                ..
            } => *requested,
            _ => DEFAULT_MAX_FRAME_SIZE as u32,
        };
        hello_ack_with_limits(hello, requested, DEFAULT_MAX_FRAME_SIZE as u32)
    }

    fn hello_ack_with_limits(
        hello: &Request,
        accepted_response_frame_size: u32,
        server_request_frame_size: u32,
    ) -> Response {
        let Request::Hello {
            node_id,
            expected_server_replica_id,
            cluster_id,
            configuration_id,
            configuration_epoch,
            handshake_nonce,
            ..
        } = hello
        else {
            panic!("expected Hello request");
        };
        Response::HelloAck {
            contract_version: CONTRACT_VERSION,
            contract_profile: Some(CURRENT_CONTRACT_PROFILE),
            server_replica_id: expected_server_replica_id.clone(),
            accepted_client_replica_id: Some(node_id.clone()),
            cluster_id: cluster_id.clone(),
            configuration_id: configuration_id.clone(),
            configuration_epoch: *configuration_epoch,
            handshake_nonce: *handshake_nonce,
            cas_idempotency_epoch: Some(uuid::Uuid::from_u128(1)),
            accepted_response_frame_size: Some(accepted_response_frame_size),
            server_request_frame_size: Some(server_request_frame_size),
        }
    }

    fn valid_deadline_entry() -> ReplicationEntry {
        let timestamp =
            opc_types::Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let expires_at = opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH
                .checked_add(time::Duration::seconds(60))
                .expect("representable test deadline"),
        );
        ReplicationEntry {
            sequence: 1,
            tx_id: "forged-response-deadline"
                .try_into()
                .expect("valid transaction ID"),
            op: opc_session_store::ReplicationOp::RefreshTtl {
                key: SessionKey {
                    tenant: opc_types::TenantId::new("tenant-a").expect("test tenant"),
                    nf_kind: opc_types::NetworkFunctionKind::from_static("smf"),
                    key_type: opc_session_store::SessionKeyType::PduSession,
                    stable_id: bytes::Bytes::from_static(b"forged-response")
                        .try_into()
                        .expect("valid stable ID"),
                },
                owner: OwnerId::new("forged-response-owner").expect("test owner"),
                fence: opc_session_store::FenceToken::new(1),
                ttl: Duration::from_secs(60),
                expires_at,
            },
            timestamp,
        }
    }

    async fn valid_compare_and_set(payload_len: usize) -> CompareAndSet {
        let backend = FakeSessionBackend::new();
        let key = match valid_deadline_entry().op {
            ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };
        let owner = OwnerId::new("client-preflight-owner").expect("test owner");
        let lease = backend
            .acquire(&key, owner.clone(), Duration::from_secs(60))
            .await
            .expect("test lease");
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner,
            fence: FenceToken::new(lease.fence().get()),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("client-preflight").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(vec![7; payload_len]),
        };
        CompareAndSet {
            key,
            lease,
            expected_generation: None,
            new_record: record,
        }
    }

    fn forge_deadline_in_wire_response(
        mut response: serde_json::Value,
        entry_pointer: &str,
    ) -> serde_json::Value {
        let forged_expires_at = opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH
                .checked_add(time::Duration::seconds(61))
                .expect("representable forged deadline"),
        );
        response
            .pointer_mut(entry_pointer)
            .expect("wire response entry")["operation_nodes"][0]["RefreshTtl"]["expires_at"] =
            serde_json::to_value(forged_expires_at).expect("serialize forged deadline");
        response
    }

    fn operation_tree_at_depth(depth: usize) -> opc_session_store::ReplicationOp {
        let mut op = opc_session_store::ReplicationOp::Batch { ops: Vec::new() };
        for _ in 1..depth {
            op = opc_session_store::ReplicationOp::Batch { ops: vec![op] };
        }
        op
    }

    fn replication_entry_at_depth(depth: usize) -> ReplicationEntry {
        ReplicationEntry {
            sequence: 1,
            tx_id: "over-depth-response"
                .try_into()
                .expect("valid transaction ID"),
            op: operation_tree_at_depth(depth),
            timestamp: opc_types::Timestamp::now_utc(),
        }
    }

    fn replication_entry_at_operation_limit() -> ReplicationEntry {
        let ops = (1..MAX_REPLICATION_OPERATIONS_PER_ENTRY)
            .map(|_| opc_session_store::ReplicationOp::Batch { ops: Vec::new() })
            .collect();
        ReplicationEntry {
            sequence: 1,
            tx_id: "over-count-response"
                .try_into()
                .expect("valid transaction ID"),
            op: opc_session_store::ReplicationOp::Batch { ops },
            timestamp: opc_types::Timestamp::now_utc(),
        }
    }

    async fn capability_server(
        caps: BackendCapabilities,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        capability_server_with_limits(
            caps,
            DEFAULT_MAX_FRAME_SIZE as u32,
            DEFAULT_MAX_FRAME_SIZE as u32,
        )
        .await
    }

    async fn capability_server_with_limits(
        caps: BackendCapabilities,
        accepted_response_frame_size: u32,
        server_request_frame_size: u32,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(
                &mut stream,
                &hello_ack_with_limits(
                    &hello,
                    accepted_response_frame_size,
                    server_request_frame_size,
                ),
            )
            .await
            .expect("write hello ack");

            let req: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read request");
            assert!(matches!(req, Request::Capabilities));
            write_frame(&mut stream, &Response::Capabilities(caps))
                .await
                .expect("write capabilities");
        });
        (addr, handle)
    }

    async fn bootstrap_retirement_then_capability_server(
        caps: BackendCapabilities,
    ) -> (SocketAddr, tokio::task::JoinHandle<(usize, usize)>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind bootstrap-retirement listener");
        let addr = listener.local_addr().expect("bootstrap-retirement address");
        let handle = tokio::spawn(async move {
            let mut application_requests = 0;
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept bootstrap client");
                let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                    .await
                    .expect("read bootstrap Hello");
                if attempt == 0 {
                    write_frame(&mut stream, &BootstrapResponse::ConnectionRetiring)
                        .await
                        .expect("write authenticated pre-admission retirement control");
                    if matches!(
                        tokio::time::timeout(
                            Duration::from_millis(100),
                            read_frame::<_, Request>(&mut stream, DEFAULT_MAX_FRAME_SIZE),
                        )
                        .await,
                        Ok(Ok(_))
                    ) {
                        application_requests += 1;
                    }
                    continue;
                }
                write_frame(&mut stream, &successful_hello_ack(&hello))
                    .await
                    .expect("write replacement Hello acknowledgement");
                let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                    .await
                    .expect("read replacement request");
                assert!(matches!(request, Request::Capabilities));
                application_requests += 1;
                write_frame(&mut stream, &Response::Capabilities(caps))
                    .await
                    .expect("write replacement capabilities");
            }
            (2, application_requests)
        });
        (addr, handle)
    }

    async fn response_loss_server() -> (SocketAddr, tokio::task::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind response-loss listener");
        let addr = listener.local_addr().expect("response-loss address");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept mutation client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read response-loss hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write response-loss hello ack");
            let _request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read one mutation");
            drop(stream);

            match tokio::time::timeout(Duration::from_millis(150), listener.accept()).await {
                Ok(Ok((_retry, _))) => 2,
                _ => 1,
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn authenticated_bootstrap_retirement_retries_before_any_application_dispatch() {
        let expected = BackendCapabilities {
            max_value_bytes: conservative_payload_budget(DEFAULT_MAX_FRAME_SIZE),
            ..BackendCapabilities::all_enabled()
        };
        let (addr, server) = bootstrap_retirement_then_capability_server(expected).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(2)))
            .with_connection_lifecycle(
                ConnectionLifecyclePolicy::try_new(
                    Duration::from_secs(10),
                    Duration::from_secs(1),
                    Duration::from_millis(1),
                    Duration::from_millis(5),
                    Duration::ZERO,
                )
                .expect("test lifecycle policy"),
            );

        assert_eq!(backend.capabilities().await, expected);
        assert_eq!(
            server.await.expect("bootstrap-retirement server"),
            (2, 1),
            "the retired route must receive no application request and the fresh route exactly one"
        );
    }

    #[tokio::test]
    async fn unsigned_bootstrap_eof_remains_a_transport_failure_not_a_retirement_proof() {
        let (client, mut peer) = tokio::io::duplex(16 * 1024);
        let (mut reader, mut writer) = tokio::io::split(client);
        let peer_task = tokio::spawn(async move {
            let _: BootstrapRequest = read_frame(&mut peer, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read bootstrap Hello");
            // A legacy server or broken route can close here. Without the
            // complete explicit control this is never safe-retry proof.
        });
        let result = perform_client_handshake(
            &mut reader,
            &mut writer,
            &crate::identity::insecure_test_client_binding(),
            DEFAULT_MAX_FRAME_SIZE,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await;
        assert!(matches!(
            result,
            Err(ConnectionOpenError::Protocol(ProtocolError::Io(_)))
        ));
        peer_task.await.expect("legacy-close peer");
    }

    async fn retirement_then_response_server(
        response: Response,
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<serde_json::Value>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind retirement test listener");
        let addr = listener.local_addr().expect("retirement test address");
        let handle = tokio::spawn(async move {
            let mut requests = Vec::with_capacity(2);
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept mutation client");
                let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                    .await
                    .expect("read retirement hello");
                write_frame(&mut stream, &successful_hello_ack(&hello))
                    .await
                    .expect("write retirement hello ack");
                let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                    .await
                    .expect("read retirement mutation");
                requests.push(serde_json::to_value(request).expect("mutation wire value"));
                if attempt == 0 {
                    write_frame(&mut stream, &Response::ConnectionRetiring)
                        .await
                        .expect("write authenticated no-dispatch proof");
                } else {
                    write_frame(&mut stream, &response)
                        .await
                        .expect("write replacement response");
                }
            }
            requests
        });
        (addr, handle)
    }

    async fn partial_retirement_server() -> (SocketAddr, tokio::task::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind partial-retirement listener");
        let addr = listener.local_addr().expect("partial-retirement address");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept mutation client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read partial-retirement hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write partial-retirement hello ack");
            let _request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read partial-retirement mutation");
            let encoded =
                serde_json::to_vec(&Response::ConnectionRetiring).expect("encode retirement proof");
            stream
                .write_all(
                    &u32::try_from(encoded.len())
                        .expect("bounded test frame")
                        .to_be_bytes(),
                )
                .await
                .expect("write retirement prefix");
            stream
                .write_all(&encoded[..encoded.len() / 2])
                .await
                .expect("write partial retirement proof");
            drop(stream);
            match tokio::time::timeout(Duration::from_millis(250), listener.accept()).await {
                Ok(Ok((_retry, _))) => 2,
                _ => 1,
            }
        });
        (addr, handle)
    }

    struct FailingWriter;

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected write failure",
            )))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct CountingBackend {
        compare_and_set_calls: AtomicUsize,
        compare_and_set_completed: AtomicUsize,
        batch_calls: AtomicUsize,
        lease_calls: AtomicUsize,
        block_compare_and_set: AtomicBool,
        compare_and_set_started: tokio::sync::Notify,
        compare_and_set_release: tokio::sync::Notify,
    }

    #[derive(Default)]
    struct SupervisedLateMutationBackend {
        compare_and_set_calls: AtomicUsize,
        compare_and_set_completed: Arc<AtomicUsize>,
        compare_and_set_started: tokio::sync::Notify,
        compare_and_set_release: Arc<tokio::sync::Notify>,
        committed_record: Arc<StdMutex<Option<StoredSessionRecord>>>,
    }

    #[async_trait]
    impl SessionBackend for CountingBackend {
        async fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities::all_enabled()
        }

        async fn get(&self, _key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
            Ok(None)
        }

        async fn compare_and_set(
            &self,
            _operation: CompareAndSet,
        ) -> Result<CompareAndSetResult, StoreError> {
            self.compare_and_set_calls.fetch_add(1, Ordering::SeqCst);
            if self.block_compare_and_set.load(Ordering::Acquire) {
                self.compare_and_set_started.notify_one();
                self.compare_and_set_release.notified().await;
            }
            self.compare_and_set_completed
                .fetch_add(1, Ordering::SeqCst);
            Ok(CompareAndSetResult::Success)
        }

        async fn delete_fenced(&self, _lease: &LeaseGuard) -> Result<(), StoreError> {
            Ok(())
        }

        async fn refresh_ttl(&self, _lease: &LeaseGuard, _ttl: Duration) -> Result<(), StoreError> {
            Ok(())
        }

        async fn batch(
            &self,
            operations: Vec<SessionOp>,
        ) -> Result<Vec<SessionOpResult>, StoreError> {
            self.batch_calls.fetch_add(1, Ordering::SeqCst);
            Ok(operations
                .into_iter()
                .map(|operation| match operation {
                    SessionOp::Get { .. } => SessionOpResult::Get(Ok(None)),
                    SessionOp::CompareAndSet(_) => {
                        SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Success))
                    }
                    SessionOp::DeleteFenced { .. } => SessionOpResult::DeleteFenced(Ok(())),
                    SessionOp::RefreshTtl { .. } => SessionOpResult::RefreshTtl(Ok(())),
                })
                .collect())
        }
    }

    #[async_trait]
    impl SessionLeaseManager for CountingBackend {
        async fn acquire(
            &self,
            _key: &SessionKey,
            _owner: OwnerId,
            _ttl: Duration,
        ) -> Result<LeaseGuard, LeaseError> {
            self.lease_calls.fetch_add(1, Ordering::SeqCst);
            Err(LeaseError::Backend("counted acquire".to_string()))
        }

        async fn renew(
            &self,
            _lease: &LeaseGuard,
            _ttl: Duration,
        ) -> Result<LeaseGuard, LeaseError> {
            self.lease_calls.fetch_add(1, Ordering::SeqCst);
            Err(LeaseError::Backend("counted renew".to_string()))
        }

        async fn release(&self, _lease: LeaseGuard) -> Result<(), LeaseError> {
            self.lease_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[async_trait]
    impl SessionBackend for SupervisedLateMutationBackend {
        async fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities::all_enabled()
        }

        async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
            Ok(self
                .committed_record
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .filter(|record| &record.key == key)
                .cloned())
        }

        async fn compare_and_set(
            &self,
            operation: CompareAndSet,
        ) -> Result<CompareAndSetResult, StoreError> {
            self.compare_and_set_calls.fetch_add(1, Ordering::SeqCst);
            self.compare_and_set_started.notify_one();
            let release = self.compare_and_set_release.clone();
            let completed = self.compare_and_set_completed.clone();
            let committed_record = self.committed_record.clone();
            // Model a bounded backend supervisor: dropping this public future
            // detaches only the already-admitted, still-supervised task. The
            // task may finish later, which is permitted by SessionBackend.
            tokio::spawn(async move {
                release.notified().await;
                *committed_record
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(operation.new_record);
                completed.fetch_add(1, Ordering::SeqCst);
                CompareAndSetResult::Success
            })
            .await
            .map_err(|_| StoreError::BackendOperationOutcomeUnavailable)
        }

        async fn delete_fenced(&self, _lease: &LeaseGuard) -> Result<(), StoreError> {
            Ok(())
        }

        async fn refresh_ttl(&self, _lease: &LeaseGuard, _ttl: Duration) -> Result<(), StoreError> {
            Ok(())
        }

        async fn batch(
            &self,
            operations: Vec<SessionOp>,
        ) -> Result<Vec<SessionOpResult>, StoreError> {
            Ok(operations
                .into_iter()
                .map(|operation| match operation {
                    SessionOp::Get { .. } => SessionOpResult::Get(Ok(None)),
                    SessionOp::CompareAndSet(_) => {
                        SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Success))
                    }
                    SessionOp::DeleteFenced { .. } => SessionOpResult::DeleteFenced(Ok(())),
                    SessionOp::RefreshTtl { .. } => SessionOpResult::RefreshTtl(Ok(())),
                })
                .collect())
        }
    }

    #[async_trait]
    impl SessionLeaseManager for SupervisedLateMutationBackend {
        async fn acquire(
            &self,
            _key: &SessionKey,
            _owner: OwnerId,
            _ttl: Duration,
        ) -> Result<LeaseGuard, LeaseError> {
            Err(LeaseError::Backend("unused supervised acquire".to_string()))
        }

        async fn renew(
            &self,
            _lease: &LeaseGuard,
            _ttl: Duration,
        ) -> Result<LeaseGuard, LeaseError> {
            Err(LeaseError::Backend("unused supervised renew".to_string()))
        }

        async fn release(&self, _lease: LeaseGuard) -> Result<(), LeaseError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn complete_retirement_proof_retries_every_mutation_family_exactly_once() {
        #[derive(Clone, Copy)]
        enum MutationClass {
            Cas,
            Backend,
            Lease,
        }

        let operation = valid_compare_and_set(0).await;
        let lease = operation.lease.clone();
        let key = operation.key.clone();
        let owner = lease.owner().clone();
        let entry = valid_deadline_entry();
        let cases = vec![
            (
                MutationClass::Cas,
                Request::CompareAndSet {
                    op: operation,
                    request_id: Some(uuid::Uuid::nil().hyphenated().to_string()),
                    idempotency_epoch: None,
                },
                Response::CompareAndSet(Ok(CompareAndSetResult::Success)),
            ),
            (
                MutationClass::Backend,
                Request::DeleteFenced {
                    lease: lease.clone(),
                },
                Response::DeleteFenced(Ok(())),
            ),
            (
                MutationClass::Backend,
                Request::RefreshTtl {
                    lease: lease.clone(),
                    ttl: Duration::from_secs(60),
                },
                Response::RefreshTtl(Ok(())),
            ),
            (
                MutationClass::Backend,
                Request::Batch {
                    ops: vec![SessionOp::DeleteFenced {
                        lease: lease.clone(),
                    }],
                },
                Response::Batch(Ok(vec![SessionOpResult::DeleteFenced(Ok(()))])),
            ),
            (
                MutationClass::Backend,
                Request::ReplicateEntry {
                    entry: entry.clone(),
                },
                Response::ReplicateEntry(Ok(())),
            ),
            (
                MutationClass::Backend,
                Request::RebuildReplicationState {
                    entries: vec![entry],
                },
                Response::RebuildReplicationState(Ok(())),
            ),
            (
                MutationClass::Lease,
                Request::AcquireLease {
                    key,
                    owner,
                    ttl: Duration::from_secs(60),
                },
                Response::AcquireLease(Err(LeaseError::Backend("replacement reached".to_string()))),
            ),
            (
                MutationClass::Lease,
                Request::RenewLease {
                    lease: lease.clone(),
                    ttl: Duration::from_secs(60),
                },
                Response::RenewLease(Err(LeaseError::Backend("replacement reached".to_string()))),
            ),
            (
                MutationClass::Lease,
                Request::ReleaseLease { lease },
                Response::ReleaseLease(Ok(())),
            ),
        ];

        for (class, request, response) in cases {
            let expected_response = serde_json::to_value(&response).expect("response wire value");
            let (addr, server) = retirement_then_response_server(response).await;
            let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(2)));
            let actual = match class {
                MutationClass::Cas => backend
                    .send_mutation_once(request)
                    .await
                    .map_err(|error| error.to_string()),
                MutationClass::Backend => backend
                    .send_backend_mutation_once(request)
                    .await
                    .map_err(|error| error.to_string()),
                MutationClass::Lease => backend
                    .send_lease_mutation_once(request)
                    .await
                    .map_err(|error| error.to_string()),
            }
            .expect("complete retirement proof must permit one safe retry");
            assert_eq!(
                serde_json::to_value(actual).expect("actual response wire value"),
                expected_response
            );
            let requests = server.await.expect("retirement server");
            assert_eq!(requests.len(), 2);
            assert_eq!(
                requests[0], requests[1],
                "the replacement must receive the exact same logical request"
            );
        }
    }

    #[tokio::test]
    async fn partial_retirement_proof_never_retries_mutations() {
        let operation = valid_compare_and_set(0).await;
        let lease = operation.lease.clone();

        let (addr, server) = partial_retirement_server().await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(matches!(
            backend
                .send_mutation_once(Request::CompareAndSet {
                    op: operation,
                    request_id: Some(uuid::Uuid::nil().hyphenated().to_string()),
                    idempotency_epoch: None,
                })
                .await,
            Err(StoreError::CasIdempotencyOutcomeUnavailable)
        ));
        assert_eq!(server.await.expect("partial CAS server"), 1);

        let (addr, server) = partial_retirement_server().await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(matches!(
            backend
                .send_backend_mutation_once(Request::DeleteFenced {
                    lease: lease.clone(),
                })
                .await,
            Err(StoreError::BackendOperationOutcomeUnavailable)
        ));
        assert_eq!(server.await.expect("partial backend server"), 1);

        let (addr, server) = partial_retirement_server().await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(matches!(
            backend
                .send_lease_mutation_once(Request::ReleaseLease { lease })
                .await,
            Err(LeaseError::OperationOutcomeUnavailable)
        ));
        assert_eq!(server.await.expect("partial lease server"), 1);
    }

    #[tokio::test]
    async fn buffered_complete_retirement_proof_overrides_a_local_write_failure() {
        let payload =
            serde_json::to_vec(&Response::ConnectionRetiring).expect("encode retirement proof");
        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("bounded test frame")
                .to_be_bytes(),
        );
        framed.extend_from_slice(&payload);
        let backend = RemoteSessionBackend::new_insecure(
            "127.0.0.1:1".parse().expect("unused address"),
            Some(Duration::from_secs(1)),
        );
        let lifecycle = ConnectionLifecycle::new(
            ConnectionLifecyclePolicy::default(),
            tokio::time::Instant::now(),
            None,
            None,
            0,
            None,
        )
        .expect("test lifecycle");
        let mut connection = Connection {
            reader: Box::new(std::io::Cursor::new(framed)),
            writer: Box::new(FailingWriter),
            authenticated_peer: None,
            contract_profile: CURRENT_CONTRACT_PROFILE,
            frame_limits: NegotiatedFrameLimits {
                response_frame_size: DEFAULT_MAX_FRAME_SIZE,
                request_frame_size: DEFAULT_MAX_FRAME_SIZE,
            },
            cas_idempotency_epoch: uuid::Uuid::nil(),
            lifecycle,
        };
        let started = AtomicBool::new(false);
        let failure = backend
            .exchange(
                &Request::MaxReplicationSequence,
                &mut connection,
                tokio::time::Instant::now() + Duration::from_secs(1),
                Some(&started),
            )
            .await
            .expect_err("buffered retirement proof is a retry classification");
        assert_eq!(failure.failure, RemoteRequestFailure::ConnectionRetiring);
        assert!(!failure.request_may_have_reached_server);
        assert!(started.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn server_only_retirement_reconnects_and_dispatches_each_mutation_once() {
        let counting = Arc::new(CountingBackend::default());
        let server_control = SessionReauthenticationControl::new();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(10),
            Duration::from_millis(500),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::ZERO,
        )
        .expect("test lifecycle policy");
        let (server, addr) =
            crate::server::SessionReplicationServer::new_insecure(counting.clone())
                .with_connection_lifecycle(policy)
                .with_reauthentication_control(server_control.clone())
                .listen("127.0.0.1:0".parse().expect("listen address"))
                .await
                .expect("start test server");
        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = resolve_calls.clone();
        let resolver: RemoteAddrResolver = Arc::new(move || {
            resolver_calls.fetch_add(1, Ordering::SeqCst);
            async move { Ok(addr) }.boxed()
        });
        let client = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(2)),
        )
        .with_connection_lifecycle(policy);
        assert!(client.capabilities().await.atomic_compare_and_set);
        assert_eq!(resolve_calls.load(Ordering::SeqCst), 1);

        let operation = valid_compare_and_set(0).await;
        let lease = operation.lease.clone();
        server_control
            .request_reauthentication()
            .expect("retire before CAS");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(matches!(
            client
                .send_mutation_once(Request::CompareAndSet {
                    op: operation,
                    request_id: Some(uuid::Uuid::nil().hyphenated().to_string()),
                    idempotency_epoch: None,
                })
                .await,
            Ok(Response::CompareAndSet(Ok(CompareAndSetResult::Success)))
        ));
        assert_eq!(counting.compare_and_set_calls.load(Ordering::SeqCst), 1);
        assert_eq!(resolve_calls.load(Ordering::SeqCst), 2);

        server_control
            .request_reauthentication()
            .expect("retire before batch");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(matches!(
            client
                .send_backend_mutation_once(Request::Batch {
                    ops: vec![SessionOp::DeleteFenced {
                        lease: lease.clone(),
                    }],
                })
                .await,
            Ok(Response::Batch(Ok(_)))
        ));
        assert_eq!(counting.batch_calls.load(Ordering::SeqCst), 1);
        assert_eq!(resolve_calls.load(Ordering::SeqCst), 3);

        server_control
            .request_reauthentication()
            .expect("retire before lease release");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(matches!(
            client
                .send_lease_mutation_once(Request::ReleaseLease { lease })
                .await,
            Ok(Response::ReleaseLease(Ok(())))
        ));
        assert_eq!(counting.lease_calls.load(Ordering::SeqCst), 1);
        assert_eq!(resolve_calls.load(Ordering::SeqCst), 4);

        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn request_admitted_before_soft_retirement_drains_once_then_socket_retires() {
        let counting = Arc::new(CountingBackend::default());
        counting
            .block_compare_and_set
            .store(true, Ordering::Release);
        let server_control = SessionReauthenticationControl::new();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(10),
            Duration::from_millis(500),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::from_millis(20),
        )
        .expect("test lifecycle policy");
        let (server, addr) =
            crate::server::SessionReplicationServer::new_insecure(counting.clone())
                .with_connection_lifecycle(policy)
                .with_reauthentication_control(server_control.clone())
                .listen("127.0.0.1:0".parse().expect("listen address"))
                .await
                .expect("start test server");
        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = resolve_calls.clone();
        let resolver: RemoteAddrResolver = Arc::new(move || {
            resolver_calls.fetch_add(1, Ordering::SeqCst);
            async move { Ok(addr) }.boxed()
        });
        let client = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(2)),
        )
        .with_connection_lifecycle(policy);
        assert!(client.capabilities().await.atomic_compare_and_set);

        let operation = valid_compare_and_set(0).await;
        let lease = operation.lease.clone();
        let mutation_client = client.clone();
        let mutation = tokio::spawn(async move {
            mutation_client
                .send_mutation_once(Request::CompareAndSet {
                    op: operation,
                    request_id: Some(uuid::Uuid::nil().hyphenated().to_string()),
                    idempotency_epoch: None,
                })
                .await
        });
        tokio::time::timeout(
            Duration::from_secs(1),
            counting.compare_and_set_started.notified(),
        )
        .await
        .expect("backend mutation must start before retirement");
        server_control
            .request_reauthentication()
            .expect("retire in-flight connection");
        // The directed jitter is bounded by 20 ms. Keep the admitted request
        // alive beyond soft retirement but release it well before hard drain.
        tokio::time::sleep(Duration::from_millis(50)).await;
        counting.compare_and_set_release.notify_one();
        assert!(matches!(
            mutation.await.expect("mutation task"),
            Ok(Response::CompareAndSet(Ok(CompareAndSetResult::Success)))
        ));
        assert_eq!(counting.compare_and_set_calls.load(Ordering::SeqCst), 1);
        assert_eq!(counting.compare_and_set_completed.load(Ordering::SeqCst), 1);
        assert_eq!(resolve_calls.load(Ordering::SeqCst), 1);

        assert!(matches!(
            client
                .send_backend_mutation_once(Request::Batch {
                    ops: vec![SessionOp::DeleteFenced { lease }],
                })
                .await,
            Ok(Response::Batch(Ok(_)))
        ));
        assert_eq!(counting.batch_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            resolve_calls.load(Ordering::SeqCst),
            2,
            "the post-soft request must receive no-dispatch proof and reconnect"
        );

        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn authentication_hard_deadline_cancels_a_cancellation_sensitive_backend_and_releases_connection_slot(
    ) {
        let counting = Arc::new(CountingBackend::default());
        counting
            .block_compare_and_set
            .store(true, Ordering::Release);
        let server_control = SessionReauthenticationControl::new();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(10),
            Duration::from_millis(100),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::ZERO,
        )
        .expect("test lifecycle policy");
        let (server, addr) =
            crate::server::SessionReplicationServer::new_insecure(counting.clone())
                .with_max_connections(1)
                .with_connection_lifecycle(policy)
                .with_reauthentication_control(server_control.clone())
                .listen("127.0.0.1:0".parse().expect("listen address"))
                .await
                .expect("start test server");
        let client = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)))
            .with_connection_lifecycle(policy);
        assert!(client.capabilities().await.atomic_compare_and_set);

        let operation = valid_compare_and_set(0).await;
        let mutation_client = client.clone();
        let mutation = tokio::spawn(async move {
            mutation_client
                .send_mutation_once(Request::CompareAndSet {
                    op: operation,
                    request_id: Some(uuid::Uuid::nil().hyphenated().to_string()),
                    idempotency_epoch: None,
                })
                .await
        });
        tokio::time::timeout(
            Duration::from_secs(1),
            counting.compare_and_set_started.notified(),
        )
        .await
        .expect("slow backend mutation must start");
        server_control
            .request_reauthentication()
            .expect("retire slow connection");
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), mutation)
                .await
                .expect("hard deadline must end mutation task")
                .expect("mutation join"),
            Err(StoreError::CasIdempotencyOutcomeUnavailable)
        ));
        assert_eq!(counting.compare_and_set_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            counting.compare_and_set_completed.load(Ordering::SeqCst),
            0,
            "this cancellation-sensitive backend must stop when its future is dropped"
        );

        counting
            .block_compare_and_set
            .store(false, Ordering::Release);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), client.capabilities())
                .await
                .expect("retired handler must release the sole connection slot")
                .atomic_compare_and_set
        );
        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn authentication_hard_deadline_reports_ambiguity_without_retrying_a_late_supervised_mutation(
    ) {
        let supervised = Arc::new(SupervisedLateMutationBackend::default());
        let server_control = SessionReauthenticationControl::new();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(10),
            Duration::from_millis(100),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::ZERO,
        )
        .expect("test lifecycle policy");
        let (server, addr) =
            crate::server::SessionReplicationServer::new_insecure(supervised.clone())
                .with_max_connections(1)
                .with_connection_lifecycle(policy)
                .with_reauthentication_control(server_control.clone())
                .listen("127.0.0.1:0".parse().expect("listen address"))
                .await
                .expect("start test server");
        let client = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)))
            .with_connection_lifecycle(policy);
        assert!(client.capabilities().await.atomic_compare_and_set);

        let operation = valid_compare_and_set(0).await;
        let operation_for_replay = operation.clone();
        let committed_key = operation.key.clone();
        let mutation_client = client.clone();
        let mutation = tokio::spawn(async move {
            mutation_client
                .send_mutation_once(Request::CompareAndSet {
                    op: operation,
                    request_id: Some(uuid::Uuid::nil().hyphenated().to_string()),
                    idempotency_epoch: None,
                })
                .await
        });
        tokio::time::timeout(
            Duration::from_secs(1),
            supervised.compare_and_set_started.notified(),
        )
        .await
        .expect("supervised backend mutation must start");
        server_control
            .request_reauthentication()
            .expect("retire supervised mutation connection");
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), mutation)
                .await
                .expect("hard deadline must close the transport wait")
                .expect("mutation join"),
            Err(StoreError::CasIdempotencyOutcomeUnavailable)
        ));
        assert_eq!(supervised.compare_and_set_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            supervised.compare_and_set_completed.load(Ordering::SeqCst),
            0,
            "transport completion must not pretend the supervised mutation rolled back"
        );

        assert!(
            tokio::time::timeout(Duration::from_secs(1), client.capabilities())
                .await
                .expect("retired handler must release the sole connection slot")
                .atomic_compare_and_set
        );
        assert_eq!(
            supervised.compare_and_set_calls.load(Ordering::SeqCst),
            1,
            "the ambiguous mutation must never be automatically retried"
        );

        supervised.compare_and_set_release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while supervised.compare_and_set_completed.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bounded supervised mutation may finish after transport retirement");
        assert_eq!(
            supervised.compare_and_set_completed.load(Ordering::SeqCst),
            1
        );
        assert_eq!(supervised.compare_and_set_calls.load(Ordering::SeqCst), 1);
        assert!(client
            .get(&committed_key)
            .await
            .expect("authoritative reread after ambiguous completion")
            .is_some());
        let replay = client
            .send_mutation_once(Request::CompareAndSet {
                op: operation_for_replay,
                request_id: Some(uuid::Uuid::nil().hyphenated().to_string()),
                idempotency_epoch: None,
            })
            .await;
        assert!(
            matches!(
                replay,
                Ok(Response::CompareAndSet(Err(
                    StoreError::CasIdempotencyOutcomeUnavailable
                )))
            ),
            "unexpected exact ambiguity replay result: {replay:?}"
        );
        assert_eq!(
            supervised.compare_and_set_calls.load(Ordering::SeqCst),
            1,
            "the exact replay must resolve from the ambiguity tombstone without redispatch"
        );

        server.abort_and_wait().await;
    }

    #[tokio::test]
    async fn dropping_the_last_client_aborts_the_pool_lifecycle_monitor() {
        let backend = RemoteSessionBackend::new_insecure(
            "127.0.0.1:1".parse().expect("unused address"),
            Some(Duration::from_secs(1)),
        );
        backend.ensure_pool_lifecycle_monitor();
        let weak_monitor = Arc::downgrade(&backend.pool_lifecycle_monitor);
        assert!(weak_monitor.upgrade().is_some());
        drop(backend);
        tokio::task::yield_now().await;
        assert!(
            weak_monitor.upgrade().is_none(),
            "the monitor task must not retain its own owner or TLS/control sources"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn queued_pool_checkout_uses_the_published_event_time_without_collapsing_jitter() {
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::from_secs(5),
        )
        .expect("test lifecycle policy");
        let mut directed = Vec::new();
        for suffix in 0_u16..=u16::MAX {
            let key = suffix.to_be_bytes();
            let jitter = policy.deterministic_jitter(&key);
            if jitter > Duration::from_millis(100)
                && directed
                    .first()
                    .is_none_or(|(_, first_jitter)| *first_jitter != jitter)
            {
                directed.push((key, jitter));
                if directed.len() == 2 {
                    break;
                }
            }
        }
        assert_eq!(directed.len(), 2, "test requires two distinct edge jitters");

        let monitor = PoolLifecycleMonitor::default();
        let observed_at = tokio::time::Instant::now();
        monitor.publish_generation(1, observed_at);
        // Model the task blocked behind the one-in-flight mutex while queued
        // checkouts observe the new generation first.
        tokio::time::advance(Duration::from_millis(50)).await;
        let checkout_at = tokio::time::Instant::now();
        let mut first = ConnectionLifecycle::new(policy, observed_at, None, None, 0, None)
            .expect("first lifecycle");
        let mut second = ConnectionLifecycle::new(policy, observed_at, None, None, 0, None)
            .expect("second lifecycle");
        monitor.apply_to(&mut first, 1, None, checkout_at, &directed[0].0);
        monitor.apply_to(&mut second, 1, None, checkout_at, &directed[1].0);
        assert_eq!(first.retire_at(), observed_at + directed[0].1);
        assert_eq!(second.retire_at(), observed_at + directed[1].1);
        assert_ne!(first.retire_at(), second.retire_at());
        assert!(first.retirement(checkout_at).is_none());
        assert!(second.retirement(checkout_at).is_none());

        tokio::time::advance(Duration::from_secs(1)).await;
        monitor.publish_generation(2, tokio::time::Instant::now());
        let mut coalesced = ConnectionLifecycle::new(policy, observed_at, None, None, 0, None)
            .expect("coalesced lifecycle");
        monitor.apply_to(
            &mut coalesced,
            2,
            None,
            tokio::time::Instant::now(),
            &directed[0].0,
        );
        assert_eq!(
            coalesced.retire_at(),
            observed_at + directed[0].1,
            "a later generation publication must not postpone an existing stale connection"
        );
    }

    #[tokio::test]
    async fn mutations_are_not_retried_after_response_loss_and_preconnect_failure_is_known_safe() {
        let fixture = FakeSessionBackend::new();
        let key = match valid_deadline_entry().op {
            ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };
        let owner = OwnerId::new("response-loss-owner").expect("owner");
        let lease = fixture
            .acquire(&key, owner, Duration::from_secs(60))
            .await
            .expect("fixture lease");

        let (addr, server) = response_loss_server().await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        let error = backend
            .send_backend_mutation_once(Request::DeleteFenced {
                lease: lease.clone(),
            })
            .await
            .expect_err("lost mutation response is ambiguous");
        assert_eq!(error, StoreError::BackendOperationOutcomeUnavailable);
        assert_eq!(server.await.expect("response-loss server"), 1);

        let (addr, server) = response_loss_server().await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        let error = backend
            .send_lease_mutation_once(Request::ReleaseLease {
                lease: lease.clone(),
            })
            .await
            .expect_err("lost lease response is ambiguous");
        assert_eq!(error, LeaseError::OperationOutcomeUnavailable);
        assert_eq!(server.await.expect("lease response-loss server"), 1);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve unreachable address");
        let unreachable = listener.local_addr().expect("unreachable address");
        drop(listener);
        let backend =
            RemoteSessionBackend::new_insecure(unreachable, Some(Duration::from_millis(250)));
        let error = backend
            .send_backend_mutation_once(Request::DeleteFenced { lease })
            .await
            .expect_err("connect failure is known not applied");
        assert!(matches!(error, StoreError::BackendUnavailable(_)));
    }

    #[tokio::test]
    async fn bounded_pretransmission_retry_preserves_the_last_transport_classification() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve unreachable address");
        let unreachable = listener.local_addr().expect("unreachable address");
        drop(listener);
        let resolver: RemoteAddrResolver = Arc::new(move || async move { Ok(unreachable) }.boxed());
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_millis(150)),
        );

        assert!(matches!(
            backend
                .send_request_classified(Request::MaxReplicationSequence)
                .await,
            Err(RemoteRequestFailure::Transport)
        ));
    }

    #[tokio::test]
    async fn a_prior_pretransmission_transport_does_not_mask_post_write_mutation_ambiguity() {
        let fixture = FakeSessionBackend::new();
        let key = match valid_deadline_entry().op {
            ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };
        let lease = fixture
            .acquire(
                &key,
                OwnerId::new("mixed-failure-owner").expect("owner"),
                Duration::from_secs(60),
            )
            .await
            .expect("fixture lease");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve unreachable address");
        let unreachable = listener.local_addr().expect("unreachable address");
        drop(listener);
        let (server_addr, server) = response_loss_server().await;
        let resolutions = Arc::new(AtomicUsize::new(0));
        let resolver: RemoteAddrResolver = {
            let resolutions = resolutions.clone();
            Arc::new(move || {
                let attempt = resolutions.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt == 0 {
                        Ok(unreachable)
                    } else {
                        Ok(server_addr)
                    }
                }
                .boxed()
            })
        };
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(1)),
        );

        assert!(matches!(
            backend
                .send_backend_mutation_once(Request::DeleteFenced { lease })
                .await,
            Err(StoreError::BackendOperationOutcomeUnavailable)
        ));
        assert!(resolutions.load(Ordering::SeqCst) >= 2);
        assert_eq!(server.await.expect("response-loss server"), 1);
    }

    async fn warmed_malicious_response_server(
        response: Response,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind malicious peer");
        let addr = listener.local_addr().expect("malicious peer address");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello acknowledgement");

            let capabilities: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read capabilities request");
            assert!(matches!(capabilities, Request::Capabilities));
            write_frame(
                &mut stream,
                &Response::Capabilities(BackendCapabilities::all_enabled()),
            )
            .await
            .expect("write capabilities response");

            let _: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read operation request");
            write_frame(&mut stream, &response)
                .await
                .expect("write malicious response");
        });
        (addr, handle)
    }

    async fn version_mismatch_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            assert!(matches!(hello, Request::Hello { .. }));
            write_frame(
                &mut stream,
                &Response::HelloAck {
                    contract_version: CONTRACT_VERSION - 1,
                    contract_profile: None,
                    server_replica_id: None,
                    accepted_client_replica_id: None,
                    cluster_id: None,
                    configuration_id: None,
                    configuration_epoch: None,
                    handshake_nonce: None,
                    cas_idempotency_epoch: None,
                    accepted_response_frame_size: None,
                    server_request_frame_size: None,
                },
            )
            .await
            .expect("write incompatible hello ack");
        });
        (addr, handle)
    }

    async fn legacy_close_without_ack_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            assert!(matches!(hello, Request::Hello { .. }));
            // Protocol v1 closed immediately when the peer version differed;
            // it did not send a HelloAck that disclosed its version.
        });
        (addr, handle)
    }

    async fn invalid_ack_server(stale_nonce: bool) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            let mut ack = successful_hello_ack(&hello);
            let Response::HelloAck {
                server_replica_id,
                handshake_nonce,
                ..
            } = &mut ack
            else {
                unreachable!("helper always returns HelloAck");
            };
            if stale_nonce {
                *handshake_nonce = Some(uuid::Uuid::nil());
            } else {
                *server_replica_id = Some("different-server".to_string());
            }
            write_frame(&mut stream, &ack)
                .await
                .expect("write invalid hello ack");
        });
        (addr, handle)
    }

    async fn contract_profile_mismatch_server(
        contract_profile: Option<ContractProfile>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            let mut ack = successful_hello_ack(&hello);
            let Response::HelloAck {
                contract_profile: accepted_profile,
                ..
            } = &mut ack
            else {
                unreachable!("helper always returns HelloAck");
            };
            *accepted_profile = contract_profile;
            write_frame(&mut stream, &ack)
                .await
                .expect("write incompatible hello ack");
        });
        (addr, handle)
    }

    async fn frame_limit_ack_server(
        accepted_response_frame_size: u32,
        server_request_frame_size: u32,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(
                &mut stream,
                &hello_ack_with_limits(
                    &hello,
                    accepted_response_frame_size,
                    server_request_frame_size,
                ),
            )
            .await
            .expect("write frame-limit acknowledgement");
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn hello_ack_enforces_profile_frame_boundaries() {
        let below_minimum = (crate::MIN_NEGOTIATED_FRAME_SIZE - 1) as u32;
        let minimum = crate::MIN_NEGOTIATED_FRAME_SIZE as u32;
        let maximum = crate::MAX_NEGOTIATED_FRAME_SIZE as u32;
        let over_ceiling = (crate::MAX_NEGOTIATED_FRAME_SIZE + 1) as u32;
        for (
            accepted_response_frame_size,
            server_request_frame_size,
            configured_frame_size,
            accepted,
        ) in [
            (
                below_minimum,
                DEFAULT_MAX_FRAME_SIZE as u32,
                DEFAULT_MAX_FRAME_SIZE,
                false,
            ),
            (
                DEFAULT_MAX_FRAME_SIZE as u32,
                below_minimum,
                DEFAULT_MAX_FRAME_SIZE,
                false,
            ),
            (minimum, minimum, crate::MIN_NEGOTIATED_FRAME_SIZE, true),
            (maximum, maximum, crate::MAX_NEGOTIATED_FRAME_SIZE, true),
            (
                over_ceiling,
                DEFAULT_MAX_FRAME_SIZE as u32,
                DEFAULT_MAX_FRAME_SIZE,
                false,
            ),
            (
                DEFAULT_MAX_FRAME_SIZE as u32,
                over_ceiling,
                DEFAULT_MAX_FRAME_SIZE,
                false,
            ),
        ] {
            let (addr, server) =
                frame_limit_ack_server(accepted_response_frame_size, server_request_frame_size)
                    .await;
            let deadline = tokio::time::Instant::now()
                .checked_add(Duration::from_secs(1))
                .expect("test deadline");
            let lifecycle_policy = ConnectionLifecyclePolicy::default();
            match open_connection(
                RemoteTarget::pinned(addr),
                None,
                crate::identity::insecure_test_client_binding(),
                configured_frame_size,
                deadline,
                OutboundConnectionLifecycle {
                    policy: lifecycle_policy,
                    reauthentication: SessionReauthenticationControl::new(),
                    reconnect_gate: ReconnectGate::new(lifecycle_policy),
                },
            )
            .await
            {
                Ok(_) if accepted => {}
                Ok(_) => panic!("an out-of-profile HelloAck frame limit must fail closed"),
                Err(error) if accepted => {
                    panic!("an in-profile HelloAck frame limit must succeed: {error}")
                }
                Err(error) => assert!(matches!(
                    error,
                    ConnectionOpenError::Protocol(ProtocolError::InvalidWireValue)
                )),
            };
            server.await.expect("frame-limit server task");
        }
    }

    #[tokio::test]
    async fn resolver_backend_reconnects_to_changed_address() {
        let caps_a = BackendCapabilities::minimal();
        let mut expected_caps_a = caps_a;
        expected_caps_a.max_value_bytes = conservative_payload_budget(DEFAULT_MAX_FRAME_SIZE);
        let caps_b = BackendCapabilities::all_enabled();
        let mut expected_caps_b = caps_b;
        expected_caps_b.max_value_bytes = conservative_payload_budget(DEFAULT_MAX_FRAME_SIZE);
        let (addr_a, handle_a) = capability_server(caps_a).await;
        let (addr_b, handle_b) = capability_server(caps_b).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let call = resolver_calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Ok(addr_a)
                } else {
                    Ok(addr_b)
                }
            }
            .boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(2)),
        );

        assert_eq!(backend.capabilities().await, expected_caps_a);
        let _ = handle_a.await;

        assert_eq!(backend.capabilities().await, expected_caps_b);
        let _ = handle_b.await;
        assert!(calls.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test(start_paused = true)]
    async fn direct_requests_and_watches_share_one_reconnect_gate() {
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
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_millis(10),
            Duration::from_millis(80),
            Duration::ZERO,
        )
        .expect("lifecycle policy");
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(1)),
        )
        .with_connection_lifecycle(policy);

        let request_backend = backend.clone();
        let request = tokio::spawn(async move { request_backend.capabilities().await });
        assert_eq!(entered_rx.recv().await, Some(0));

        let watch_backend = backend.clone();
        let watch = tokio::spawn(async move { watch_backend.watch(0).await });
        tokio::task::yield_now().await;
        assert!(entered_rx.try_recv().is_err());

        request.abort();
        assert!(request
            .await
            .expect_err("request must be cancelled")
            .is_cancelled());
        tokio::time::advance(Duration::from_millis(9)).await;
        tokio::task::yield_now().await;
        assert!(entered_rx.try_recv().is_err());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(entered_rx.recv().await, Some(1));

        watch.abort();
        match watch.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => panic!("watch must be cancelled"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn watch_only_epoch_change_wakes_reconnect_cooldown() {
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
        let control = SessionReauthenticationControl::new();
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(5)),
        )
        .with_connection_lifecycle(policy)
        .with_reauthentication_control(control.clone());
        let started_at = tokio::time::Instant::now();
        backend
            .reconnect_gate
            .acquire(
                started_at + Duration::from_secs(2),
                control.generation(),
                None,
            )
            .await
            .expect("seed reconnect attempt")
            .failed();

        let watch_backend = backend.clone();
        let watch = tokio::spawn(async move { watch_backend.watch(0).await });
        tokio::task::yield_now().await;
        assert!(
            entered_rx.try_recv().is_err(),
            "the old epoch cooldown must initially hold a watch-only caller"
        );

        control.request_reauthentication().expect("advance epoch");
        assert_eq!(entered_rx.recv().await, Some(()));
        assert_eq!(
            tokio::time::Instant::now(),
            started_at,
            "the new epoch must bypass the old cooldown without advancing time"
        );

        watch.abort();
        match watch.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => panic!("watch must be cancelled"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn material_epoch_wait_observes_status_already_current_at_subscription() {
        let material = crate::test_support::RotatableClientMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/client",
        );
        let tls_config = material.config();
        let admitted_epoch = tls_config.material_status().epoch();

        material.rotate();
        let current_epoch = tls_config.material_status().epoch();
        let mut receiver = Some(tls_config.subscribe_material_changes());
        let started_at = tokio::time::Instant::now();
        let observed = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_material_epoch_change(&mut receiver, Some(admitted_epoch)),
        )
        .await
        .expect("current subscription status must not require another publication");

        assert_eq!(observed, Some(current_epoch));
        assert_eq!(
            tokio::time::Instant::now(),
            started_at,
            "an already-current receiver must bypass the old epoch immediately"
        );
    }

    #[tokio::test]
    async fn concurrent_capability_responses_keep_their_connection_limits_when_reordered() {
        let large = DEFAULT_MAX_FRAME_SIZE as u32;
        let small = MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE as u32;
        let (first_addr, first_server) =
            capability_server_with_limits(BackendCapabilities::all_enabled(), large, large).await;
        let (second_addr, second_server) =
            capability_server_with_limits(BackendCapabilities::all_enabled(), small, small).await;
        let resolves = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&resolves);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let call = resolver_calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Ok(first_addr)
                } else {
                    Ok(second_addr)
                }
            }
            .boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(2)),
        );

        let (first, second) = tokio::join!(
            backend.send_request_classified(Request::Capabilities),
            backend.send_request_classified(Request::Capabilities)
        );
        let first = first.expect("first capability response");
        let second = second.expect("second capability response");
        let NegotiatedResponse {
            response: Response::Capabilities(first_caps),
            contract_profile: first_profile,
            frame_limits: first_limits,
        } = first
        else {
            panic!("first response family");
        };
        let NegotiatedResponse {
            response: Response::Capabilities(second_caps),
            contract_profile: second_profile,
            frame_limits: second_limits,
        } = second
        else {
            panic!("second response family");
        };

        assert_eq!(first_limits.response_frame_size, large as usize);
        assert_eq!(second_limits.response_frame_size, small as usize);
        let first_caps = RemoteSessionBackend::capabilities_for_transport(
            first_caps,
            true,
            first_profile,
            first_limits,
        );
        let second_caps = RemoteSessionBackend::capabilities_for_transport(
            second_caps,
            true,
            second_profile,
            second_limits,
        );
        assert!(first_caps.max_value_bytes > second_caps.max_value_bytes);

        // Simulate the older response being processed after the reconnect.
        backend.remember_capabilities(first_profile, first_limits, first_caps);
        assert!(
            backend.cached_capabilities().is_none(),
            "an old response tuple must not be relabelled with the current connection limits"
        );
        backend.remember_capabilities(second_profile, second_limits, second_caps);
        assert_eq!(
            backend.cached_capabilities().map(|(_, _, caps)| caps),
            Some(second_caps)
        );

        first_server.await.expect("first server");
        second_server.await.expect("second server");
    }

    #[tokio::test]
    async fn clone_before_frame_builder_detaches_transport_and_preserves_each_bound() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind capability listener");
        let addr = listener.local_addr().expect("listener address");
        let (observed_tx, mut observed_rx) = tokio::sync::mpsc::channel(2);
        let server = tokio::spawn(async move {
            let mut handlers = tokio::task::JoinSet::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept capability client");
                let observed_tx = observed_tx.clone();
                handlers.spawn(async move {
                    let hello: Request = read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                        .await
                        .expect("read hello");
                    let requested = match &hello {
                        Request::Hello {
                            requested_response_frame_size: Some(requested),
                            ..
                        } => *requested,
                        _ => panic!("requested frame size"),
                    };
                    write_frame(
                        &mut stream,
                        &hello_ack_with_limits(&hello, requested, requested),
                    )
                    .await
                    .expect("write hello acknowledgement");
                    let request: Request = read_frame(&mut stream, requested as usize)
                        .await
                        .expect("read capabilities");
                    assert!(matches!(request, Request::Capabilities));
                    write_frame(
                        &mut stream,
                        &Response::Capabilities(BackendCapabilities::all_enabled()),
                    )
                    .await
                    .expect("write capabilities");
                    observed_tx.send(requested).await.expect("record request");
                });
            }
            while handlers.join_next().await.is_some() {}
        });

        let original = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(2)));
        let configured_limit = 2 * crate::MIN_NEGOTIATED_FRAME_SIZE;
        let configured = original.clone().with_max_frame_size(configured_limit);
        assert!(!Arc::ptr_eq(&original.conn, &configured.conn));
        assert!(!Arc::ptr_eq(
            &original.negotiated_frame_limits,
            &configured.negotiated_frame_limits
        ));
        assert!(!Arc::ptr_eq(
            &original.cached_capabilities,
            &configured.cached_capabilities
        ));

        let configured_caps = configured.capabilities().await;
        let original_caps = original.capabilities().await;
        assert_eq!(
            configured_caps.max_value_bytes,
            conservative_payload_budget(configured_limit)
        );
        assert_eq!(
            original_caps.max_value_bytes,
            conservative_payload_budget(DEFAULT_MAX_FRAME_SIZE)
        );
        let mut observed = vec![
            observed_rx.recv().await.expect("configured hello"),
            observed_rx.recv().await.expect("original hello"),
        ];
        observed.sort_unstable();
        assert_eq!(
            observed,
            vec![configured_limit as u32, DEFAULT_MAX_FRAME_SIZE as u32]
        );
        server.await.expect("capability server");
    }

    #[tokio::test]
    async fn retained_profile_and_payload_failures_do_not_resolve_a_peer() {
        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&resolve_calls);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            resolver_calls.fetch_add(1, Ordering::SeqCst);
            async { Ok("127.0.0.1:1".parse().expect("address")) }.boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(1)),
        );

        assert!(opc_session_store::StableId::new(bytes::Bytes::from(vec![
            7;
            crate::MAX_SESSION_NET_STABLE_ID_BYTES
                + 1
        ]))
        .is_err());

        assert!(opc_session_store::ReplicationTxId::new(
            &"x".repeat(crate::MAX_SESSION_NET_REPLICATION_TX_ID_BYTES + 1)
        )
        .is_err());

        let op = valid_compare_and_set(0).await;
        assert!(matches!(
            backend
                .send_request_classified(Request::CompareAndSet {
                    op,
                    request_id: Some("not-a-canonical-uuid".to_string()),
                    idempotency_epoch: None,
                })
                .await,
            Err(RemoteRequestFailure::Protocol)
        ));

        assert!(matches!(
            backend
                .send_request_classified(Request::GetReplicationLog {
                    start: 1,
                    limit: crate::MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES + 1,
                })
                .await,
            Err(RemoteRequestFailure::Protocol)
        ));

        let constrained = backend
            .clone()
            .with_max_frame_size(crate::MIN_NEGOTIATED_FRAME_SIZE);
        let payload_error = constrained
            .compare_and_set(valid_compare_and_set(1).await)
            .await
            .expect_err("one byte above the clone-local limit must fail locally");
        assert_eq!(
            payload_error,
            StoreError::PayloadTooLarge { actual: 1, max: 0 }
        );
        assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn negotiated_unequal_limits_clamp_capabilities_and_preflight_requests() {
        let response_budget = (2 * MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE) as u32;
        let request_budget = MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE as u32;
        let (addr, server) = capability_server_with_limits(
            BackendCapabilities::all_enabled(),
            response_budget,
            request_budget,
        )
        .await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

        let capabilities = backend.capabilities().await;
        assert_eq!(
            capabilities.max_value_bytes,
            conservative_payload_budget(request_budget as usize),
            "payload capability must use the smaller request direction"
        );
        server.await.expect("capability server");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind preflight listener");
        let addr = listener.local_addr().expect("preflight address");
        let no_request_prefix = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(
                &mut stream,
                &hello_ack_with_limits(&hello, DEFAULT_MAX_FRAME_SIZE as u32, request_budget),
            )
            .await
            .expect("write constrained acknowledgement");
            let mut byte = [0u8; 1];
            match tokio::time::timeout(Duration::from_millis(250), stream.read(&mut byte)).await {
                Err(_) | Ok(Ok(0)) => {}
                Ok(Ok(read)) => panic!("local preflight emitted {read} operation-prefix bytes"),
                Ok(Err(error)) => panic!("preflight connection read failed: {error}"),
            }
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        let mut key = match valid_deadline_entry().op {
            opc_session_store::ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };
        key.stable_id = bytes::Bytes::from(vec![u8::MAX; crate::MAX_SESSION_NET_STABLE_ID_BYTES])
            .try_into()
            .expect("maximum stable ID");
        let error = backend
            .batch(vec![SessionOp::Get { key }; 128])
            .await
            .expect_err("request above negotiated server limit must fail locally");
        assert!(matches!(error, StoreError::BackendUnavailable(_)));
        no_request_prefix.await.expect("preflight server");
    }

    #[tokio::test]
    async fn negotiated_payload_limit_rejects_one_over_before_writing() {
        let request_budget = (2 * crate::MIN_NEGOTIATED_FRAME_SIZE) as u32;
        let negotiated_max = conservative_payload_budget(request_budget as usize);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind negotiated preflight listener");
        let addr = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(
                &mut stream,
                &hello_ack_with_limits(&hello, DEFAULT_MAX_FRAME_SIZE as u32, request_budget),
            )
            .await
            .expect("write constrained acknowledgement");
            let mut byte = [0_u8; 1];
            assert!(
                tokio::time::timeout(Duration::from_millis(250), stream.read(&mut byte))
                    .await
                    .is_err(),
                "negotiated preflight must emit no operation prefix and may retain the clean connection"
            );
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

        let error = backend
            .compare_and_set(valid_compare_and_set(negotiated_max + 1).await)
            .await
            .expect_err("one byte above the negotiated payload limit must fail locally");
        assert_eq!(
            error,
            StoreError::PayloadTooLarge {
                actual: negotiated_max + 1,
                max: negotiated_max,
            }
        );
        server.await.expect("negotiated preflight server");
    }

    #[tokio::test]
    async fn reconnect_with_changed_limits_evicts_incompatible_capability_cache() {
        let (first_addr, first_server) =
            capability_server(BackendCapabilities::all_enabled()).await;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind changed-budget listener");
        let second_addr = listener.local_addr().expect("changed-budget address");
        let second_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept reconnect");
            let hello: Request = read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read reconnect hello");
            write_frame(
                &mut stream,
                &hello_ack_with_limits(
                    &hello,
                    MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE as u32,
                    MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE as u32,
                ),
            )
            .await
            .expect("write changed-budget acknowledgement");
            let request: Request = read_frame(&mut stream, MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE)
                .await
                .expect("read capability probe");
            assert!(matches!(request, Request::Capabilities));
            // Close without a response. The client must not fall back to the
            // capability cache populated under the old frame limits.
        });

        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&resolve_calls);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Ok(first_addr)
                } else {
                    Ok(second_addr)
                }
            }
            .boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_millis(350)),
        );
        let warmed = backend.capabilities().await;
        assert!(
            warmed.max_value_bytes
                > conservative_payload_budget(MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE)
        );
        first_server.await.expect("first capability server");

        assert_eq!(
            backend.capabilities().await,
            unavailable_capabilities(),
            "a changed negotiated budget must invalidate the old cache before probe fallback"
        );
        second_server.await.expect("changed-budget server");
        assert!(resolve_calls.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn replayed_or_relabelled_hello_ack_is_rejected() {
        for stale_nonce in [true, false] {
            let (addr, handle) = invalid_ack_server(stale_nonce).await;
            let backend =
                RemoteSessionBackend::new_insecure(addr, Some(Duration::from_millis(250)));

            let expected = if stale_nonce {
                ReplicaReadinessFailure::Protocol
            } else {
                ReplicaReadinessFailure::Authentication
            };
            assert_eq!(backend.probe_replication_head().await, Err(expected));
            let _ = handle.await;
        }
    }

    #[tokio::test]
    async fn socket_addr_constructor_remains_pinned_after_disconnect() {
        let caps_a = BackendCapabilities::minimal();
        let mut expected_caps_a = caps_a;
        expected_caps_a.max_value_bytes = conservative_payload_budget(DEFAULT_MAX_FRAME_SIZE);
        let (addr_a, handle_a) = capability_server(caps_a).await;
        let (_addr_b, handle_b) = capability_server(BackendCapabilities::all_enabled()).await;
        let backend = RemoteSessionBackend::new_insecure(addr_a, Some(Duration::from_millis(250)));

        assert_eq!(backend.capabilities().await, expected_caps_a);
        let _ = handle_a.await;

        assert_eq!(backend.capabilities().await, expected_caps_a);
        handle_b.abort();
    }

    #[tokio::test]
    async fn explicit_version_mismatch_clears_all_cached_capabilities() {
        let (compatible_addr, compatible_handle) =
            capability_server(BackendCapabilities::all_enabled()).await;
        let (incompatible_addr, incompatible_handle) = version_mismatch_server().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = calls.clone();
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let call = resolver_calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Ok(compatible_addr)
                } else {
                    Ok(incompatible_addr)
                }
            }
            .boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(1)),
        );

        assert!(backend.capabilities().await.restore_scan);
        let _ = compatible_handle.await;

        assert_eq!(
            backend.capabilities().await,
            unavailable_capabilities(),
            "an explicitly incompatible protocol must clear the entire negotiated cache"
        );
        let _ = incompatible_handle.await;
    }

    #[tokio::test]
    async fn invalid_hello_ack_clears_all_cached_capabilities() {
        for stale_nonce in [true, false] {
            let (compatible_addr, compatible_handle) =
                capability_server(BackendCapabilities::all_enabled()).await;
            let (invalid_addr, invalid_handle) = invalid_ack_server(stale_nonce).await;
            let calls = Arc::new(AtomicUsize::new(0));
            let resolver_calls = calls.clone();
            let resolver: RemoteAddrResolver = Arc::new(move || {
                let call = resolver_calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if call == 0 {
                        Ok(compatible_addr)
                    } else {
                        Ok(invalid_addr)
                    }
                }
                .boxed()
            });
            let backend = RemoteSessionBackend::new_insecure_with_resolver(
                resolver,
                Some(Duration::from_secs(1)),
            );

            let mut expected = BackendCapabilities::all_enabled();
            expected.max_value_bytes = conservative_payload_budget(DEFAULT_MAX_FRAME_SIZE);
            assert_eq!(backend.capabilities().await, expected);
            let _ = compatible_handle.await;
            assert_eq!(
                backend.capabilities().await,
                unavailable_capabilities(),
                "an invalid fresh HelloAck must clear every cached capability"
            );
            let _ = invalid_handle.await;
        }
    }

    #[tokio::test]
    async fn missing_or_wrong_v5_contract_profile_clears_all_cached_capabilities() {
        let mut wrong_profile = CURRENT_CONTRACT_PROFILE;
        wrong_profile.error_set_revision = wrong_profile.error_set_revision.saturating_add(1);

        for incompatible_profile in [None, Some(wrong_profile)] {
            let (compatible_addr, compatible_handle) =
                capability_server(BackendCapabilities::all_enabled()).await;
            let (incompatible_addr, incompatible_handle) =
                contract_profile_mismatch_server(incompatible_profile).await;
            let calls = Arc::new(AtomicUsize::new(0));
            let resolver_calls = calls.clone();
            let resolver: RemoteAddrResolver = Arc::new(move || {
                let call = resolver_calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if call == 0 {
                        Ok(compatible_addr)
                    } else {
                        Ok(incompatible_addr)
                    }
                }
                .boxed()
            });
            let backend = RemoteSessionBackend::new_insecure_with_resolver(
                resolver,
                Some(Duration::from_secs(1)),
            );

            assert!(backend.capabilities().await.restore_scan);
            let _ = compatible_handle.await;
            assert_eq!(
                backend.capabilities().await,
                unavailable_capabilities(),
                "same-version peers with a missing or different contract profile must fail closed"
            );
            let _ = incompatible_handle.await;
        }
    }

    #[tokio::test]
    async fn mismatched_batch_response_count_discards_connection_and_capability_cache() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello ack");

            let capabilities: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read capabilities request");
            assert!(matches!(capabilities, Request::Capabilities));
            write_frame(
                &mut stream,
                &Response::Capabilities(BackendCapabilities::all_enabled()),
            )
            .await
            .expect("write capabilities response");

            let batch: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read batch request");
            assert!(matches!(batch, Request::Batch { ops } if ops.len() == 1));
            write_frame(&mut stream, &Response::Batch(Ok(Vec::new())))
                .await
                .expect("write wrong-cardinality batch response");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_millis(250)));

        assert!(backend.capabilities().await.restore_scan);
        let key = match valid_deadline_entry().op {
            opc_session_store::ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };
        let error = backend
            .batch(vec![SessionOp::Get { key }])
            .await
            .expect_err("wrong response cardinality must fail closed");
        assert_eq!(
            error,
            StoreError::BackendUnavailable(REMOTE_PROTOCOL_VIOLATION.to_string())
        );
        assert!(
            backend.conn.lock().await.is_none(),
            "the violating connection must not return to the pool"
        );
        let _ = server.await;
        assert_eq!(
            backend.capabilities().await,
            unavailable_capabilities(),
            "a later failed probe must not reuse capabilities negotiated on the violating connection"
        );
    }

    #[tokio::test]
    async fn wrong_response_family_drops_connection_clears_cache_and_forces_reconnect() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind violating server");
        let first_addr = listener.local_addr().expect("violating address");
        let first_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello acknowledgement");
            let capabilities: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read capabilities");
            assert!(matches!(capabilities, Request::Capabilities));
            write_frame(
                &mut stream,
                &Response::Capabilities(BackendCapabilities::all_enabled()),
            )
            .await
            .expect("write capabilities");
            let get: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read Get");
            assert!(matches!(get, Request::Get { .. }));
            write_frame(&mut stream, &Response::MaxReplicationSequence(Ok(7)))
                .await
                .expect("write wrong response family");
        });
        let (second_addr, second_server) = capability_server(BackendCapabilities::minimal()).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let call = resolver_calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Ok(first_addr)
                } else {
                    Ok(second_addr)
                }
            }
            .boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(1)),
        );
        assert!(backend.capabilities().await.restore_scan);
        let key = match valid_deadline_entry().op {
            ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };

        let error = backend
            .get(&key)
            .await
            .expect_err("wrong response family must fail closed");
        assert_eq!(
            error,
            StoreError::BackendUnavailable(REMOTE_PROTOCOL_VIOLATION.to_string())
        );
        assert!(backend.conn.lock().await.is_none());
        assert!(backend
            .cached_capabilities
            .read()
            .expect("cache lock")
            .is_none());

        let refreshed = backend.capabilities().await;
        assert!(!refreshed.restore_scan);
        assert!(calls.load(Ordering::SeqCst) >= 2);
        first_server.await.expect("violating server");
        second_server.await.expect("replacement server");
    }

    #[tokio::test]
    async fn peer_record_for_a_different_key_is_a_protocol_violation() {
        let mut operation = valid_compare_and_set(0).await;
        let wrong_record = operation.new_record.clone();
        operation.key.stable_id = bytes::Bytes::from_static(b"requested-peer-key")
            .try_into()
            .expect("valid stable ID");
        let requested_key = operation.key;
        assert_ne!(wrong_record.key, requested_key);
        let (addr, server) =
            warmed_malicious_response_server(Response::Get(Ok(Some(wrong_record)))).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);
        assert!(backend
            .cached_capabilities
            .read()
            .expect("cache lock")
            .is_some());

        let error = backend
            .get(&requested_key)
            .await
            .expect_err("a record for another key must fail closed");
        assert_eq!(
            error,
            StoreError::BackendUnavailable(REMOTE_PROTOCOL_VIOLATION.to_string())
        );
        assert!(backend.conn.lock().await.is_none());
        assert!(backend
            .cached_capabilities
            .read()
            .expect("cache lock")
            .is_none());
        server.await.expect("malicious peer");
    }

    #[tokio::test]
    async fn peer_cas_conflict_for_a_different_key_is_a_protocol_violation() {
        let operation = valid_compare_and_set(0).await;
        let mut wrong_record = operation.new_record.clone();
        wrong_record.key.stable_id = bytes::Bytes::from_static(b"wrong-cas-conflict-key")
            .try_into()
            .expect("valid stable ID");
        let response = Response::CompareAndSet(Ok(CompareAndSetResult::Conflict {
            current: Some(wrong_record),
        }));
        let (addr, server) = warmed_malicious_response_server(response).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);

        let error = backend
            .compare_and_set(operation)
            .await
            .expect_err("a CAS conflict for another key must fail closed");
        assert_eq!(error, StoreError::CasIdempotencyOutcomeUnavailable);
        assert!(backend.conn.lock().await.is_none());
        assert!(backend
            .cached_capabilities
            .read()
            .expect("cache lock")
            .is_none());
        server.await.expect("malicious peer");
    }

    async fn assert_malicious_batch_response_is_rejected(
        ops: Vec<SessionOp>,
        results: Vec<SessionOpResult>,
    ) {
        let contains_mutation = ops.iter().any(|op| !matches!(op, SessionOp::Get { .. }));
        let (addr, server) = warmed_malicious_response_server(Response::Batch(Ok(results))).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);

        let error = backend
            .batch(ops)
            .await
            .expect_err("a batch response that does not match its request must fail closed");
        if contains_mutation {
            assert_eq!(error, StoreError::BackendOperationOutcomeUnavailable);
        } else {
            assert_eq!(
                error,
                StoreError::BackendUnavailable(REMOTE_PROTOCOL_VIOLATION.to_string())
            );
        }
        assert!(backend.conn.lock().await.is_none());
        assert!(backend
            .cached_capabilities
            .read()
            .expect("cache lock")
            .is_none());
        server.await.expect("malicious peer");
    }

    #[tokio::test]
    async fn peer_batch_result_kind_must_match_the_requested_operation() {
        let operation = valid_compare_and_set(0).await;
        assert_malicious_batch_response_is_rejected(
            vec![SessionOp::Get { key: operation.key }],
            vec![SessionOpResult::CompareAndSet(Ok(
                CompareAndSetResult::Success,
            ))],
        )
        .await;
    }

    #[tokio::test]
    async fn peer_batch_get_and_cas_results_must_match_their_requested_keys() {
        let operation = valid_compare_and_set(0).await;
        let requested_key = operation.key.clone();
        let mut wrong_record = operation.new_record.clone();
        wrong_record.key.stable_id = bytes::Bytes::from_static(b"wrong-batch-get-key")
            .try_into()
            .expect("valid stable ID");
        assert_malicious_batch_response_is_rejected(
            vec![SessionOp::Get { key: requested_key }],
            vec![SessionOpResult::Get(Ok(Some(wrong_record)))],
        )
        .await;

        let operation = valid_compare_and_set(0).await;
        let mut wrong_record = operation.new_record.clone();
        wrong_record.key.stable_id = bytes::Bytes::from_static(b"wrong-batch-cas-key")
            .try_into()
            .expect("valid stable ID");
        assert_malicious_batch_response_is_rejected(
            vec![SessionOp::CompareAndSet(operation)],
            vec![SessionOpResult::CompareAndSet(Ok(
                CompareAndSetResult::Conflict {
                    current: Some(wrong_record),
                },
            ))],
        )
        .await;
    }

    #[tokio::test]
    async fn typed_ambiguity_must_match_the_exact_response_family() {
        let operation = valid_compare_and_set(0).await;
        let lease = operation.lease.clone();

        let (addr, server) = warmed_malicious_response_server(Response::Get(Err(
            StoreError::CasIdempotencyOutcomeUnavailable,
        )))
        .await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);
        assert_eq!(
            backend.get(&operation.key).await,
            Err(StoreError::BackendUnavailable(
                REMOTE_PROTOCOL_VIOLATION.to_string()
            ))
        );
        server.await.expect("malicious get ambiguity peer");

        let (addr, server) = warmed_malicious_response_server(Response::CompareAndSet(Err(
            StoreError::BackendOperationOutcomeUnavailable,
        )))
        .await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);
        assert_eq!(
            backend.compare_and_set(operation.clone()).await,
            Err(StoreError::CasIdempotencyOutcomeUnavailable)
        );
        server.await.expect("malicious CAS ambiguity peer");

        for (request, response, family) in [
            (
                Request::DeleteFenced {
                    lease: lease.clone(),
                },
                Response::DeleteFenced(Err(StoreError::CasIdempotencyOutcomeUnavailable)),
                "delete",
            ),
            (
                Request::RefreshTtl {
                    lease: lease.clone(),
                    ttl: Duration::from_secs(60),
                },
                Response::RefreshTtl(Err(StoreError::CasIdempotencyOutcomeUnavailable)),
                "refresh",
            ),
        ] {
            let (addr, server) = warmed_malicious_response_server(response).await;
            let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
            assert!(backend.capabilities().await.restore_scan);
            assert!(
                matches!(
                    backend.send_backend_mutation_once(request).await,
                    Err(StoreError::BackendOperationOutcomeUnavailable)
                ),
                "{family} accepted the CAS-only ambiguity family",
            );
            server.await.expect("malicious non-CAS ambiguity peer");
        }

        assert_malicious_batch_response_is_rejected(
            vec![SessionOp::Get {
                key: operation.key.clone(),
            }],
            vec![SessionOpResult::Get(Err(
                StoreError::CasIdempotencyOutcomeUnavailable,
            ))],
        )
        .await;
        assert_malicious_batch_response_is_rejected(
            vec![SessionOp::CompareAndSet(operation)],
            vec![SessionOpResult::CompareAndSet(Err(
                StoreError::BackendOperationOutcomeUnavailable,
            ))],
        )
        .await;
        assert_malicious_batch_response_is_rejected(
            vec![SessionOp::DeleteFenced { lease }],
            vec![SessionOpResult::DeleteFenced(Err(
                StoreError::CasIdempotencyOutcomeUnavailable,
            ))],
        )
        .await;
    }

    #[tokio::test]
    async fn peer_acquire_lease_must_match_the_requested_key_and_owner() {
        let requested_key = match valid_deadline_entry().op {
            ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };
        let requested_owner = OwnerId::new("requested-owner").expect("test owner");
        let mut wrong_key = requested_key.clone();
        wrong_key.stable_id = bytes::Bytes::from_static(b"wrong-acquire-key")
            .try_into()
            .expect("valid stable ID");
        let wrong_lease = FakeSessionBackend::new()
            .acquire(
                &wrong_key,
                OwnerId::new("wrong-owner").expect("test owner"),
                Duration::from_secs(60),
            )
            .await
            .expect("wrong test lease");
        let (addr, server) =
            warmed_malicious_response_server(Response::AcquireLease(Ok(wrong_lease))).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);

        let error = backend
            .acquire(&requested_key, requested_owner, Duration::from_secs(60))
            .await
            .expect_err("an acquire response for another key and owner must fail closed");
        assert_eq!(error, LeaseError::OperationOutcomeUnavailable);
        assert!(backend.conn.lock().await.is_none());
        assert!(backend
            .cached_capabilities
            .read()
            .expect("cache lock")
            .is_none());
        server.await.expect("malicious peer");
    }

    #[tokio::test]
    async fn peer_renewal_must_preserve_key_owner_fence_and_credential() {
        let lease = valid_compare_and_set(0).await.lease;
        let mut forged_wire = serde_json::to_value(&lease).expect("serialize lease");
        let mut wrong_key = lease.key().clone();
        wrong_key.stable_id = bytes::Bytes::from_static(b"wrong-renew-key")
            .try_into()
            .expect("valid stable ID");
        forged_wire["key"] = serde_json::to_value(wrong_key).expect("serialize wrong key");
        forged_wire["owner"] = serde_json::json!("wrong-renew-owner");
        forged_wire["fence"] = serde_json::json!(lease.fence().get() + 1);
        forged_wire["credential_id"] = serde_json::json!(lease.credential_id() + 1);
        let forged_lease: LeaseGuard =
            serde_json::from_value(forged_wire).expect("deserialize forged lease");
        assert_ne!(forged_lease.key(), lease.key());
        assert_ne!(forged_lease.owner(), lease.owner());
        assert_ne!(forged_lease.fence(), lease.fence());
        assert_ne!(forged_lease.credential_id(), lease.credential_id());

        let (addr, server) =
            warmed_malicious_response_server(Response::RenewLease(Ok(forged_lease))).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);

        let error = backend
            .renew(&lease, Duration::from_secs(60))
            .await
            .expect_err("a renewal that changes its credential must fail closed");
        assert_eq!(error, LeaseError::OperationOutcomeUnavailable);
        assert!(backend.conn.lock().await.is_none());
        assert!(backend
            .cached_capabilities
            .read()
            .expect("cache lock")
            .is_none());
        server.await.expect("malicious peer");
    }

    #[tokio::test]
    async fn wrong_response_family_is_ambiguous_for_every_remaining_mutation_family() {
        let operation = valid_compare_and_set(0).await;
        let lease = operation.lease.clone();

        let (addr, server) = warmed_malicious_response_server(Response::Get(Ok(None))).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);
        assert_eq!(
            backend
                .compare_and_set(operation)
                .await
                .expect_err("wrong CAS response family"),
            StoreError::CasIdempotencyOutcomeUnavailable
        );
        server.await.expect("malicious CAS peer");

        let (addr, server) = warmed_malicious_response_server(Response::Get(Ok(None))).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);
        assert_eq!(
            backend
                .delete_fenced(&lease)
                .await
                .expect_err("wrong delete response family"),
            StoreError::BackendOperationOutcomeUnavailable
        );
        server.await.expect("malicious delete peer");

        let (addr, server) = warmed_malicious_response_server(Response::Get(Ok(None))).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);
        assert_eq!(
            backend
                .refresh_ttl(&lease, Duration::from_secs(60))
                .await
                .expect_err("wrong refresh response family"),
            StoreError::BackendOperationOutcomeUnavailable
        );
        server.await.expect("malicious refresh peer");

        let (addr, server) = warmed_malicious_response_server(Response::Get(Ok(None))).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);
        assert_eq!(
            backend
                .batch(vec![SessionOp::DeleteFenced {
                    lease: lease.clone(),
                }])
                .await
                .expect_err("wrong mutating batch response family"),
            StoreError::BackendOperationOutcomeUnavailable
        );
        server.await.expect("malicious batch peer");

        let entry = valid_deadline_entry();
        let (addr, server) = warmed_malicious_response_server(Response::Get(Ok(None))).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);
        assert_eq!(
            backend
                .replicate_entry(entry.clone())
                .await
                .expect_err("wrong replication response family"),
            StoreError::BackendOperationOutcomeUnavailable
        );
        server.await.expect("malicious replication peer");

        let (addr, server) = warmed_malicious_response_server(Response::Get(Ok(None))).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);
        assert_eq!(
            backend
                .rebuild_replication_state(vec![entry])
                .await
                .expect_err("wrong rebuild response family"),
            StoreError::BackendOperationOutcomeUnavailable
        );
        server.await.expect("malicious rebuild peer");

        let (addr, server) = warmed_malicious_response_server(Response::Get(Ok(None))).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);
        assert_eq!(
            backend
                .release(lease)
                .await
                .expect_err("wrong release response family"),
            LeaseError::OperationOutcomeUnavailable
        );
        server.await.expect("malicious release peer");
    }

    #[tokio::test]
    async fn violating_response_connection_cannot_dispatch_a_queued_mutation() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind violating connection-race server");
        let addr = listener.local_addr().expect("server address");
        let same_connection_dispatches = Arc::new(AtomicUsize::new(0));
        let replacement_dispatches = Arc::new(AtomicUsize::new(0));
        let server_same_connection_dispatches = Arc::clone(&same_connection_dispatches);
        let server_replacement_dispatches = Arc::clone(&replacement_dispatches);
        let (first_request_tx, first_request_rx) = tokio::sync::oneshot::channel();
        let (release_response_tx, release_response_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.expect("accept first connection");
            let hello: Request = read_frame(&mut first, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read first hello");
            write_frame(&mut first, &successful_hello_ack(&hello))
                .await
                .expect("write first hello acknowledgement");
            let capabilities: Request = read_frame(&mut first, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read capabilities");
            assert!(matches!(capabilities, Request::Capabilities));
            write_frame(
                &mut first,
                &Response::Capabilities(BackendCapabilities::all_enabled()),
            )
            .await
            .expect("write capabilities");

            let first_mutation: Request = read_frame(&mut first, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read first mutation");
            assert!(matches!(first_mutation, Request::ReplicateEntry { .. }));
            let _ = first_request_tx.send(());
            let _ = release_response_rx.await;
            write_frame(&mut first, &Response::Get(Ok(None)))
                .await
                .expect("write wrong-family mutation response");

            match tokio::time::timeout(
                Duration::from_millis(250),
                read_frame::<_, Request>(&mut first, DEFAULT_MAX_FRAME_SIZE),
            )
            .await
            {
                Ok(Ok(Request::ReplicateEntry { .. })) => {
                    server_same_connection_dispatches.fetch_add(1, Ordering::SeqCst);
                    write_frame(&mut first, &Response::ReplicateEntry(Ok(())))
                        .await
                        .expect("finish incorrectly reused connection");
                }
                _ => {
                    let (mut replacement, _) =
                        tokio::time::timeout(Duration::from_secs(1), listener.accept())
                            .await
                            .expect("client reconnects after contract violation")
                            .expect("accept replacement connection");
                    let hello: Request = read_frame(&mut replacement, DEFAULT_MAX_FRAME_SIZE)
                        .await
                        .expect("read replacement hello");
                    write_frame(&mut replacement, &successful_hello_ack(&hello))
                        .await
                        .expect("write replacement hello acknowledgement");
                    let mutation: Request = read_frame(&mut replacement, DEFAULT_MAX_FRAME_SIZE)
                        .await
                        .expect("read replacement mutation");
                    assert!(matches!(mutation, Request::ReplicateEntry { .. }));
                    server_replacement_dispatches.fetch_add(1, Ordering::SeqCst);
                    write_frame(&mut replacement, &Response::ReplicateEntry(Ok(())))
                        .await
                        .expect("finish replacement mutation");
                }
            }
        });

        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(2)));
        assert!(backend.capabilities().await.restore_scan);
        let first_backend = backend.clone();
        let first =
            tokio::spawn(
                async move { first_backend.replicate_entry(valid_deadline_entry()).await },
            );
        first_request_rx
            .await
            .expect("first request reaches server");
        let second_backend = backend.clone();
        let second =
            tokio::spawn(
                async move { second_backend.replicate_entry(valid_deadline_entry()).await },
            );
        // Tokio's mutex is FIFO. Let the second caller queue before the first
        // response is released so it would win the old reinsert-then-discard
        // race deterministically.
        tokio::time::sleep(Duration::from_millis(25)).await;
        let _ = release_response_tx.send(());

        let first = first.await.expect("first mutation task");
        let second = second.await.expect("second mutation task");
        assert!(matches!(
            (&first, &second),
            (Err(StoreError::BackendOperationOutcomeUnavailable), Ok(()))
                | (Ok(()), Err(StoreError::BackendOperationOutcomeUnavailable))
        ));
        server.await.expect("race server");
        assert_eq!(
            same_connection_dispatches.load(Ordering::SeqCst),
            0,
            "a protocol-invalid connection must never return to the pool"
        );
        assert_eq!(replacement_dispatches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn wrong_replication_range_connection_cannot_dispatch_a_queued_read() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind replication connection-race server");
        let addr = listener.local_addr().expect("server address");
        let same_connection_dispatches = Arc::new(AtomicUsize::new(0));
        let replacement_dispatches = Arc::new(AtomicUsize::new(0));
        let server_same_connection_dispatches = Arc::clone(&same_connection_dispatches);
        let server_replacement_dispatches = Arc::clone(&replacement_dispatches);
        let (first_request_tx, first_request_rx) = tokio::sync::oneshot::channel();
        let (release_response_tx, release_response_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.expect("accept first connection");
            let hello: Request = read_frame(&mut first, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read first hello");
            write_frame(&mut first, &successful_hello_ack(&hello))
                .await
                .expect("write first hello acknowledgement");
            let first_read: Request = read_frame(&mut first, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read first replication request");
            assert!(matches!(
                first_read,
                Request::GetReplicationLog { start: 2, limit: 1 }
            ));
            let _ = first_request_tx.send(());
            let _ = release_response_rx.await;
            let mut wrong_entry = valid_deadline_entry();
            wrong_entry.sequence = 1;
            write_frame(
                &mut first,
                &Response::GetReplicationLog(Ok(vec![wrong_entry])),
            )
            .await
            .expect("write wrong-range response");

            let mut exact_entry = valid_deadline_entry();
            exact_entry.sequence = 2;
            match tokio::time::timeout(
                Duration::from_millis(250),
                read_frame::<_, Request>(&mut first, DEFAULT_MAX_FRAME_SIZE),
            )
            .await
            {
                Ok(Ok(Request::GetReplicationLog { start: 2, limit: 1 })) => {
                    server_same_connection_dispatches.fetch_add(1, Ordering::SeqCst);
                    write_frame(
                        &mut first,
                        &Response::GetReplicationLog(Ok(vec![exact_entry])),
                    )
                    .await
                    .expect("finish incorrectly reused connection");
                }
                _ => {
                    let (mut replacement, _) =
                        tokio::time::timeout(Duration::from_secs(1), listener.accept())
                            .await
                            .expect("client reconnects after range violation")
                            .expect("accept replacement connection");
                    let hello: Request = read_frame(&mut replacement, DEFAULT_MAX_FRAME_SIZE)
                        .await
                        .expect("read replacement hello");
                    write_frame(&mut replacement, &successful_hello_ack(&hello))
                        .await
                        .expect("write replacement hello acknowledgement");
                    let read: Request = read_frame(&mut replacement, DEFAULT_MAX_FRAME_SIZE)
                        .await
                        .expect("read replacement replication request");
                    assert!(matches!(
                        read,
                        Request::GetReplicationLog { start: 2, limit: 1 }
                    ));
                    server_replacement_dispatches.fetch_add(1, Ordering::SeqCst);
                    write_frame(
                        &mut replacement,
                        &Response::GetReplicationLog(Ok(vec![exact_entry])),
                    )
                    .await
                    .expect("finish replacement read");
                }
            }
        });

        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(2)));
        let first_backend = backend.clone();
        let first = tokio::spawn(async move { first_backend.get_replication_log(2, 1).await });
        first_request_rx
            .await
            .expect("first request reaches server");
        let second_backend = backend.clone();
        let second = tokio::spawn(async move { second_backend.get_replication_log(2, 1).await });
        tokio::time::sleep(Duration::from_millis(25)).await;
        let _ = release_response_tx.send(());

        assert_eq!(
            first.await.expect("first read task"),
            Err(StoreError::InvalidReplicationSequence)
        );
        let second = second
            .await
            .expect("second read task")
            .expect("second read reconnects");
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].sequence, 2);
        server.await.expect("range-race server");
        assert_eq!(
            same_connection_dispatches.load(Ordering::SeqCst),
            0,
            "a wrong-range connection must never return to the pool"
        );
        assert_eq!(replacement_dispatches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn legacy_close_without_ack_masks_cached_restore_capability() {
        let (compatible_addr, compatible_handle) =
            capability_server(BackendCapabilities::all_enabled()).await;
        let (legacy_addr, legacy_handle) = legacy_close_without_ack_server().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = calls.clone();
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let call = resolver_calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Ok(compatible_addr)
                } else {
                    Ok(legacy_addr)
                }
            }
            .boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_millis(250)),
        );

        let warmed = backend.capabilities().await;
        assert!(warmed.restore_scan);
        let _ = compatible_handle.await;

        let mut expected = warmed;
        expected.restore_scan = false;
        assert_eq!(
            backend.capabilities().await,
            expected,
            "clean transport EOF may retain descriptive operations, but fresh-negotiation capabilities must be masked"
        );
        let _ = legacy_handle.await;
    }

    #[tokio::test]
    async fn malformed_restore_page_is_rejected_and_discards_the_connection() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read restore request");
            assert!(matches!(request, Request::ScanRestoreRecords { .. }));

            let mut invalid_page = serde_json::to_value(Response::ScanRestoreRecords(Ok(
                RestoreScanPage::new(Vec::new(), 0, None),
            )))
            .expect("serialize valid restore page");
            invalid_page["ScanRestoreRecords"]["Ok"]["loaded_count"] = serde_json::json!(1);
            write_frame(&mut stream, &invalid_page)
                .await
                .expect("write malformed restore-page wire response");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

        let error = backend
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .expect_err("malformed peer page must fail closed");
        assert_eq!(
            error,
            StoreError::BackendUnavailable(
                "remote session backend request failed: protocol".to_string()
            )
        );
        assert!(
            backend.conn.lock().await.is_none(),
            "a connection that returned a malformed page must not be reused"
        );
        let _ = server.await;
    }

    #[tokio::test]
    async fn forged_replication_log_deadline_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read replication-log request");
            assert!(matches!(request, Request::GetReplicationLog { .. }));
            let response =
                serde_json::to_value(Response::GetReplicationLog(Ok(
                    vec![valid_deadline_entry()],
                )))
                .expect("serialize valid replication-log response");
            let response = forge_deadline_in_wire_response(response, "/GetReplicationLog/Ok/0");
            write_frame(&mut stream, &response)
                .await
                .expect("write forged replication-log wire response");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

        let error = backend
            .get_replication_log(1, 1)
            .await
            .expect_err("forged response deadline must fail closed");
        assert_eq!(
            error,
            StoreError::BackendUnavailable(
                "remote session backend request failed: protocol".to_string()
            )
        );
        let _ = server.await;
    }

    #[tokio::test]
    async fn wrong_replication_range_discards_connection_cache_and_rehandshakes() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let handshakes = Arc::new(AtomicUsize::new(0));
        let server_handshakes = Arc::clone(&handshakes);
        let server = tokio::spawn(async move {
            for attempt in 0..3 {
                let (mut stream, _) = listener.accept().await.expect("accept client");
                let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                    .await
                    .expect("read hello");
                server_handshakes.fetch_add(1, Ordering::SeqCst);
                write_frame(&mut stream, &successful_hello_ack(&hello))
                    .await
                    .expect("write hello ack");

                if attempt == 0 {
                    let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                        .await
                        .expect("read capabilities request");
                    assert!(matches!(request, Request::Capabilities));
                    write_frame(
                        &mut stream,
                        &Response::Capabilities(BackendCapabilities::all_enabled()),
                    )
                    .await
                    .expect("write capabilities response");
                }

                let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                    .await
                    .expect("read replication-log request");
                assert!(matches!(
                    request,
                    Request::GetReplicationLog { start: 2, limit: 1 }
                ));
                let mut entry = valid_deadline_entry();
                entry.sequence = match attempt {
                    0 => 100,
                    1 => 1,
                    _ => 2,
                };
                write_frame(&mut stream, &Response::GetReplicationLog(Ok(vec![entry])))
                    .await
                    .expect("write replication-log response");
            }
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

        assert!(backend.capabilities().await.ordered_replication_log);
        assert!(backend.cached_capabilities().is_some());
        assert_eq!(
            backend
                .get_replication_log(2, 1)
                .await
                .expect_err("contiguous page after the requested range"),
            StoreError::InvalidReplicationSequence
        );
        assert!(backend.conn.lock().await.is_none());
        assert!(backend.cached_capabilities().is_none());

        assert_eq!(
            backend
                .get_replication_log(2, 1)
                .await
                .expect_err("contiguous page before the requested range"),
            StoreError::InvalidReplicationSequence
        );
        assert!(backend.conn.lock().await.is_none());

        let page = backend
            .get_replication_log(2, 1)
            .await
            .expect("next call reconnects with an exact page");
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].sequence, 2);
        assert_eq!(handshakes.load(Ordering::SeqCst), 3);
        let _ = server.await;
    }

    #[tokio::test]
    async fn forged_watch_deadline_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read watch request");
            assert!(matches!(request, Request::Watch { .. }));
            write_frame(&mut stream, &Response::WatchStream)
                .await
                .expect("write watch acknowledgement");
            let response = serde_json::to_value(Response::WatchEntry(Ok(valid_deadline_entry())))
                .expect("serialize valid watch response");
            let response = forge_deadline_in_wire_response(response, "/WatchEntry/Ok");
            write_frame(&mut stream, &response)
                .await
                .expect("write forged watch wire response");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        let mut watch = backend.watch(1).await.expect("create watch stream");

        let error = tokio::time::timeout(Duration::from_secs(1), watch.next())
            .await
            .expect("watch response deadline")
            .expect("watch error item")
            .expect_err("forged watch deadline must fail closed");
        assert_eq!(
            error,
            StoreError::BackendUnavailable("remote session watch failed: protocol".to_string())
        );
        let _ = server.await;
    }

    #[tokio::test]
    async fn watch_reauthentication_reconnects_from_the_exact_delivered_successor() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind watch-rotation listener");
        let addr = listener.local_addr().expect("watch-rotation address");
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.expect("accept first watch client");
            let hello: Request = read_frame(&mut first, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read first watch hello");
            write_frame(&mut first, &successful_hello_ack(&hello))
                .await
                .expect("write first watch hello ack");
            let request: Request = read_frame(&mut first, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read first watch request");
            assert!(matches!(request, Request::Watch { start_sequence: 1 }));
            write_frame(&mut first, &Response::WatchStream)
                .await
                .expect("write first watch ack");
            write_frame(
                &mut first,
                &Response::WatchEntry(Ok(valid_deadline_entry())),
            )
            .await
            .expect("write first watch entry");
            let mut eof = [0_u8; 1];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), first.read(&mut eof))
                    .await
                    .expect("rotated watch must close promptly")
                    .expect("read rotated watch EOF"),
                0
            );

            let (mut second, _) = listener.accept().await.expect("accept replacement watch");
            let hello: Request = read_frame(&mut second, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read replacement watch hello");
            write_frame(&mut second, &successful_hello_ack(&hello))
                .await
                .expect("write replacement watch hello ack");
            let request: Request = read_frame(&mut second, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read replacement watch request");
            assert!(matches!(request, Request::Watch { start_sequence: 2 }));
            write_frame(&mut second, &Response::WatchStream)
                .await
                .expect("write replacement watch ack");
            let mut second_entry = valid_deadline_entry();
            second_entry.sequence = 2;
            second_entry.tx_id = "watch-rotation-2".try_into().expect("valid transaction ID");
            write_frame(&mut second, &Response::WatchEntry(Ok(second_entry)))
                .await
                .expect("write replacement watch entry");
        });
        let control = SessionReauthenticationControl::new();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(10),
            Duration::from_millis(500),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::ZERO,
        )
        .expect("watch lifecycle policy");
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)))
            .with_connection_lifecycle(policy)
            .with_reauthentication_control(control.clone());
        let mut watch = backend.watch(1).await.expect("open first watch");
        assert_eq!(
            watch
                .next()
                .await
                .expect("first watch item")
                .expect("first watch success")
                .sequence,
            1
        );
        control
            .request_reauthentication()
            .expect("request watch reauthentication");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), watch.next())
                .await
                .expect("replacement watch deadline")
                .expect("replacement watch item")
                .expect("replacement watch success")
                .sequence,
            2
        );
        drop(watch);
        server.await.expect("watch-rotation server");
    }

    #[tokio::test]
    async fn watch_setup_retries_only_after_complete_no_dispatch_proof() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind watch-setup-retirement listener");
        let addr = listener
            .local_addr()
            .expect("watch-setup-retirement address");
        let server = tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept watch client");
                let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                    .await
                    .expect("read watch setup hello");
                write_frame(&mut stream, &successful_hello_ack(&hello))
                    .await
                    .expect("write watch setup hello ack");
                let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                    .await
                    .expect("read watch setup request");
                assert!(matches!(request, Request::Watch { start_sequence: 7 }));
                if attempt == 0 {
                    write_frame(&mut stream, &Response::ConnectionRetiring)
                        .await
                        .expect("write watch no-dispatch proof");
                } else {
                    write_frame(&mut stream, &Response::WatchStream)
                        .await
                        .expect("write replacement watch ack");
                    let mut entry = valid_deadline_entry();
                    entry.sequence = 7;
                    entry.tx_id = "watch-setup-replacement"
                        .try_into()
                        .expect("valid transaction ID");
                    write_frame(&mut stream, &Response::WatchEntry(Ok(entry)))
                        .await
                        .expect("write replacement watch item");
                }
            }
        });
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(10),
            Duration::from_millis(500),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::ZERO,
        )
        .expect("watch setup lifecycle policy");
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)))
            .with_connection_lifecycle(policy);
        let mut watch = backend.watch(7).await.expect("retry watch setup");
        assert_eq!(
            watch
                .next()
                .await
                .expect("replacement watch item")
                .expect("replacement watch success")
                .sequence,
            7
        );
        drop(watch);
        server.await.expect("watch-setup-retirement server");
    }

    #[tokio::test]
    async fn watch_rotation_never_restarts_a_partially_consumed_frame_on_the_same_socket() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind partial-watch listener");
        let addr = listener.local_addr().expect("partial-watch address");
        let (partial_tx, partial_rx) = tokio::sync::oneshot::channel();
        let (continue_tx, continue_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept watch client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read partial-watch hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write partial-watch hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read partial-watch request");
            assert!(matches!(request, Request::Watch { start_sequence: 1 }));
            write_frame(&mut stream, &Response::WatchStream)
                .await
                .expect("write partial-watch ack");
            let encoded = serde_json::to_vec(&Response::WatchEntry(Ok(valid_deadline_entry())))
                .expect("encode watch entry");
            stream
                .write_all(
                    &u32::try_from(encoded.len())
                        .expect("bounded watch frame")
                        .to_be_bytes(),
                )
                .await
                .expect("write watch prefix");
            let midpoint = encoded.len() / 2;
            stream
                .write_all(&encoded[..midpoint])
                .await
                .expect("write first watch fragment");
            partial_tx.send(()).expect("publish partial frame");
            continue_rx.await.expect("continue partial frame");
            stream
                .write_all(&encoded[midpoint..])
                .await
                .expect("write final watch fragment");
        });
        let control = SessionReauthenticationControl::new();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::from_secs(30),
        )
        .expect("partial-watch lifecycle policy");
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)))
            .with_connection_lifecycle(policy)
            .with_reauthentication_control(control.clone());
        let edge = directed_connection_key(
            b"direct",
            backend.binding.local_replica_id().as_str(),
            backend.binding.remote_replica_id().as_str(),
        );
        let jitter = policy.deterministic_jitter(&edge);
        assert!(
            jitter > Duration::from_millis(50),
            "fixed insecure-test edge must leave a partial-frame observation window"
        );
        let mut watch = backend.watch(1).await.expect("open partial watch");
        partial_rx.await.expect("observe partial watch frame");
        control
            .request_reauthentication()
            .expect("request partial-watch reauthentication");
        tokio::time::sleep(Duration::from_millis(20)).await;
        continue_tx.send(()).expect("finish partial watch frame");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), watch.next())
                .await
                .expect("partial watch delivery deadline")
                .expect("partial watch item")
                .expect("partial watch success")
                .sequence,
            1
        );
        drop(watch);
        server.await.expect("partial-watch server");
    }

    #[tokio::test]
    async fn dropping_a_stalled_watch_closes_the_transport_task_promptly() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind cancelled-watch listener");
        let addr = listener.local_addr().expect("cancelled-watch address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept watch client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read cancelled-watch hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write cancelled-watch hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read cancelled-watch request");
            assert!(matches!(request, Request::Watch { .. }));
            write_frame(&mut stream, &Response::WatchStream)
                .await
                .expect("write cancelled-watch ack");
            let mut eof = [0_u8; 1];
            tokio::time::timeout(Duration::from_secs(1), stream.read(&mut eof))
                .await
                .expect("caller cancellation must close stalled watch")
                .expect("read cancelled-watch EOF")
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        let watch = backend.watch(1).await.expect("open cancelled watch");
        drop(watch);
        assert_eq!(server.await.expect("cancelled-watch server"), 0);
    }

    #[tokio::test]
    async fn terminal_watch_sequence_is_delivered_once_without_reconnect() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind terminal-watch listener");
        let addr = listener.local_addr().expect("terminal-watch address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept watch client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read terminal-watch hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write terminal-watch hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read terminal-watch request");
            assert!(matches!(
                request,
                Request::Watch {
                    start_sequence: u64::MAX
                }
            ));
            write_frame(&mut stream, &Response::WatchStream)
                .await
                .expect("write terminal-watch ack");
            let mut entry = valid_deadline_entry();
            entry.sequence = u64::MAX;
            entry.tx_id = "terminal-watch".try_into().expect("valid transaction ID");
            write_frame(&mut stream, &Response::WatchEntry(Ok(entry)))
                .await
                .expect("write terminal-watch entry");
            match tokio::time::timeout(Duration::from_millis(250), listener.accept()).await {
                Ok(Ok((_retry, _))) => 2,
                _ => 1,
            }
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        let mut watch = backend.watch(u64::MAX).await.expect("open terminal watch");
        assert_eq!(
            watch
                .next()
                .await
                .expect("terminal watch item")
                .expect("terminal watch success")
                .sequence,
            u64::MAX
        );
        assert!(watch.next().await.is_none());
        assert_eq!(server.await.expect("terminal-watch server"), 1);
    }

    #[tokio::test]
    async fn permanent_watch_error_is_delivered_once_without_reconnect() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind permanent-watch listener");
        let addr = listener.local_addr().expect("permanent-watch address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept watch client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read permanent-watch hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write permanent-watch hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read permanent-watch request");
            assert!(matches!(request, Request::Watch { .. }));
            write_frame(&mut stream, &Response::WatchStream)
                .await
                .expect("write permanent-watch ack");
            write_frame(
                &mut stream,
                &Response::WatchEntry(Err(StoreError::ReplicationWatchCatchUpRequired)),
            )
            .await
            .expect("write permanent watch error");
            match tokio::time::timeout(Duration::from_millis(250), listener.accept()).await {
                Ok(Ok((_retry, _))) => 2,
                _ => 1,
            }
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        let mut watch = backend.watch(1).await.expect("open permanent watch");
        assert_eq!(
            watch.next().await.expect("permanent watch item"),
            Err(StoreError::ReplicationWatchCatchUpRequired)
        );
        assert!(watch.next().await.is_none());
        assert_eq!(server.await.expect("permanent-watch server"), 1);
    }

    #[tokio::test]
    async fn slow_watch_consumer_gets_one_explicit_terminal_error_without_unbounded_retention() {
        let before = METRICS
            .session_net_watch_slow_consumers
            .load(Ordering::Relaxed);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind slow-watch listener");
        let addr = listener.local_addr().expect("slow-watch address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept watch client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read slow-watch hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write slow-watch hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read slow-watch request");
            assert!(matches!(request, Request::Watch { start_sequence: 1 }));
            write_frame(&mut stream, &Response::WatchStream)
                .await
                .expect("write slow-watch ack");
            for sequence in
                1..=u64::try_from(WATCH_CHANNEL_CAPACITY + 2).expect("bounded watch test width")
            {
                let mut entry = valid_deadline_entry();
                entry.sequence = sequence;
                entry.tx_id = format!("slow-watch-{sequence}")
                    .try_into()
                    .expect("valid transaction ID");
                if write_frame(&mut stream, &Response::WatchEntry(Ok(entry)))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        let mut watch = backend.watch(1).await.expect("open slow watch");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut successes = 0_usize;
        let mut terminal = None;
        while let Some(item) = tokio::time::timeout(Duration::from_secs(1), watch.next())
            .await
            .expect("slow-watch terminal deadline")
        {
            match item {
                Ok(entry) => {
                    successes += 1;
                    drop(entry.into_validated());
                }
                Err(error) => {
                    terminal = Some(error);
                    break;
                }
            }
        }
        assert!(successes <= WATCH_CHANNEL_CAPACITY);
        assert_eq!(
            terminal,
            Some(StoreError::BackendUnavailable(
                "remote session watch consumer is too slow".to_string()
            ))
        );
        assert!(watch.next().await.is_none());
        assert!(
            METRICS
                .session_net_watch_slow_consumers
                .load(Ordering::Relaxed)
                > before
        );
        server.await.expect("slow-watch server");
    }

    #[tokio::test]
    async fn authenticated_peer_watch_entry_before_requested_cursor_terminates_stream() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read watch request");
            assert!(matches!(request, Request::Watch { start_sequence: 2 }));
            write_frame(&mut stream, &Response::WatchStream)
                .await
                .expect("write watch acknowledgement");
            write_frame(
                &mut stream,
                &Response::WatchEntry(Ok(replication_entry_at_operation_limit())),
            )
            .await
            .expect("write lower watch entry");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        let mut watch = backend.watch(2).await.expect("create watch stream");

        assert_eq!(
            watch
                .next()
                .await
                .expect("integrity error item")
                .expect_err("lower sequence must fail closed"),
            StoreError::BackendUnavailable("remote session watch failed: protocol".to_string())
        );
        assert!(watch.next().await.is_none(), "corrupt stream must close");
        let _ = server.await;
    }

    #[tokio::test]
    async fn over_limit_replication_log_entry_is_rejected_before_return() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read replication-log request");
            assert!(matches!(request, Request::GetReplicationLog { .. }));

            let mut response = serde_json::to_value(Response::GetReplicationLog(Ok(vec![
                replication_entry_at_depth(MAX_REPLICATION_OPERATION_DEPTH),
            ])))
            .expect("serialize exact-depth replication-log response");
            let nodes = response["GetReplicationLog"]["Ok"][0]["operation_nodes"]
                .as_array_mut()
                .expect("flat replication operation nodes");
            nodes.insert(
                nodes.len() - 1,
                serde_json::json!({"Batch": {"child_count": 1}}),
            );
            write_frame(&mut stream, &response)
                .await
                .expect("write over-depth replication-log wire response");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

        let error = match backend.get_replication_log(1, 1).await {
            Err(error) => error,
            Ok(entries) => {
                drop(validate_replication_page_owned(entries));
                panic!("an over-depth log entry must not be returned")
            }
        };
        assert_eq!(
            error,
            StoreError::BackendUnavailable(
                "remote session backend request failed: protocol".to_string()
            )
        );
        let _ = server.await;
    }

    #[tokio::test]
    async fn over_limit_watch_entry_is_rejected_before_delivery() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read watch request");
            assert!(matches!(request, Request::Watch { .. }));
            write_frame(&mut stream, &Response::WatchStream)
                .await
                .expect("write watch acknowledgement");

            let mut response = serde_json::to_value(Response::WatchEntry(Ok(
                replication_entry_at_operation_limit(),
            )))
            .expect("serialize maximum-width watch response");
            let nodes = response["WatchEntry"]["Ok"]["operation_nodes"]
                .as_array_mut()
                .expect("flat replication operation nodes");
            let leaf = nodes.last().expect("last operation node").clone();
            nodes.push(leaf);
            write_frame(&mut stream, &response)
                .await
                .expect("write over-count watch wire response");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        let mut watch = backend.watch(1).await.expect("create watch stream");

        let item = tokio::time::timeout(Duration::from_secs(1), watch.next())
            .await
            .expect("watch response deadline")
            .expect("watch error item");
        let error = match item {
            Err(error) => error,
            Ok(entry) => {
                drop(entry.into_validated());
                panic!("an over-count watch entry must not be delivered")
            }
        };
        assert_eq!(
            error,
            StoreError::BackendUnavailable("remote session watch failed: protocol".to_string())
        );
        let _ = server.await;
    }

    #[tokio::test]
    async fn remote_restore_scan_timeout_respects_the_method_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read restore request");
            assert!(matches!(request, Request::ScanRestoreRecords { .. }));
            std::future::pending::<()>().await;
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_millis(100)));
        let started = tokio::time::Instant::now();

        let error = backend
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .expect_err("stalled restore response must time out");
        assert!(matches!(error, StoreError::BackendUnavailable(_)));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(backend.conn.lock().await.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn invalid_restore_request_fails_before_connecting() {
        let backend = RemoteSessionBackend::new_insecure(
            "127.0.0.1:1".parse().expect("address"),
            Some(Duration::from_secs(1)),
        );

        let error = backend
            .scan_restore_records(RestoreScanRequest::all(0))
            .await
            .expect_err("zero limit must fail validation");
        assert!(matches!(error, StoreError::InvalidRestoreScanRequest(_)));
    }

    #[tokio::test]
    async fn legacy_restore_cursor_fails_before_connecting() {
        let backend = RemoteSessionBackend::new_insecure(
            "127.0.0.1:1".parse().expect("address"),
            Some(Duration::from_secs(1)),
        );
        let error = backend
            .scan_restore_records(RestoreScanRequest {
                cursor: Some(opc_session_store::RestoreScanCursor::from_offset(0)),
                ..RestoreScanRequest::all(1)
            })
            .await
            .expect_err("legacy cursor is local-test evidence only");
        assert_eq!(
            error,
            StoreError::CapabilityNotSupported("legacy_remote_restore_scan".to_string())
        );
    }

    #[tokio::test]
    async fn collection_limits_fail_before_resolving_or_dialing() {
        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&resolve_calls);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            resolver_calls.fetch_add(1, Ordering::SeqCst);
            async { Ok("127.0.0.1:1".parse().expect("address")) }.boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(1)),
        );

        let key = match valid_deadline_entry().op {
            opc_session_store::ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };
        let batch_error = backend
            .batch(vec![
                SessionOp::Get { key };
                MAX_SESSION_NET_BATCH_OPERATIONS + 1
            ])
            .await
            .expect_err("oversized batch must fail locally");
        assert_eq!(batch_error, StoreError::ReplicationOperationLimitExceeded);

        let log_error = backend
            .get_replication_log(1, crate::MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES + 1)
            .await
            .expect_err("oversized log page must fail locally");
        assert_eq!(
            log_error,
            StoreError::ReplicationLogPageTooLarge {
                requested: crate::MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES + 1,
                max: crate::MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES,
            }
        );
        assert_eq!(
            backend
                .get_replication_log(u64::MAX, 2)
                .await
                .expect_err("overflowing log range must fail locally"),
            StoreError::InvalidReplicationLogRange
        );
        assert!(backend
            .get_replication_log(0, 0)
            .await
            .expect("zero-limit range must not resolve")
            .is_empty());

        let lightweight_entry = ReplicationEntry {
            sequence: 1,
            tx_id: "t".try_into().expect("valid transaction ID"),
            op: opc_session_store::ReplicationOp::Batch { ops: Vec::new() },
            timestamp: opc_types::Timestamp::now_utc(),
        };
        let rebuild_error = backend
            .rebuild_replication_state(vec![lightweight_entry; MAX_SESSION_NET_REBUILD_ENTRIES + 1])
            .await
            .expect_err("oversized rebuild must fail locally");
        assert_eq!(rebuild_error, StoreError::ReplicationOperationLimitExceeded);

        assert_eq!(
            resolve_calls.load(Ordering::SeqCst),
            0,
            "collection preflight failures must not resolve or dial a peer"
        );
    }

    #[tokio::test]
    async fn frame_size_above_negotiated_ceiling_fails_before_resolving_or_dialing() {
        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&resolve_calls);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            resolver_calls.fetch_add(1, Ordering::SeqCst);
            async { Ok("127.0.0.1:1".parse().expect("address")) }.boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(1)),
        )
        .with_max_frame_size(crate::MAX_NEGOTIATED_FRAME_SIZE + 1);

        let key = match valid_deadline_entry().op {
            opc_session_store::ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };
        let error = backend
            .get(&key)
            .await
            .expect_err("an over-ceiling ordinary request must fail locally");
        assert!(matches!(error, StoreError::BackendUnavailable(_)));

        let error = backend
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .expect_err("an over-ceiling restore response frame must fail locally");
        assert!(matches!(error, StoreError::InvalidRestoreScanRequest(_)));
        assert!(
            backend.watch(0).await.is_err(),
            "an over-ceiling watch must fail before spawning its resolver task"
        );
        assert_eq!(
            resolve_calls.load(Ordering::SeqCst),
            0,
            "ordinary, restore, and watch width failures must not resolve or dial a peer"
        );
    }

    #[tokio::test]
    async fn unrepresentable_client_deadline_fails_before_resolving_or_dialing() {
        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&resolve_calls);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            resolver_calls.fetch_add(1, Ordering::SeqCst);
            async { Ok("127.0.0.1:1".parse().expect("address")) }.boxed()
        });
        let backend =
            RemoteSessionBackend::new_insecure_with_resolver(resolver, Some(Duration::MAX));

        let error = backend
            .max_replication_sequence()
            .await
            .expect_err("an unrepresentable absolute deadline must fail locally");
        assert!(matches!(error, StoreError::BackendUnavailable(_)));
        assert_eq!(
            resolve_calls.load(Ordering::SeqCst),
            0,
            "deadline conversion failure must not resolve or dial a peer"
        );
    }

    #[test]
    fn resolver_target_uses_hostname_for_tls_server_name_across_addresses() {
        let resolver: RemoteAddrResolver =
            Arc::new(|| async { Ok("127.0.0.1:1".parse().expect("addr")) }.boxed());
        let target = RemoteTarget::resolved(
            Some("peer-0.sessions.core.svc.cluster.local".to_string()),
            resolver,
        );
        let first = target
            .tls_server_name("127.0.0.1:1234".parse().expect("addr"))
            .expect("first server name");
        let second = target
            .tls_server_name("127.0.0.2:1234".parse().expect("addr"))
            .expect("second server name");

        assert_eq!(format!("{first:?}"), format!("{second:?}"));
        assert!(format!("{first:?}").contains("peer-0.sessions.core.svc.cluster.local"));
        assert!(!format!("{first:?}").contains("127.0.0.1"));
    }
}
