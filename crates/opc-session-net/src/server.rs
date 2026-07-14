use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use opc_redaction::metrics::METRICS;
use opc_session_store::backend::{
    validate_replication_log_page_owned, validate_replication_page_owned,
    validate_replication_prefix_owned, CompareAndSet, CompareAndSetResult, ReplicationEntry,
    ReplicationLogRange, ReplicationOp, ReplicationWatchCursor, SessionOpResult,
};
use opc_session_store::error::{LeaseError, StoreError};
use opc_session_store::quorum::SessionStoreBackend;
#[cfg(test)]
use opc_session_store::RestoreScanCursor;
use opc_session_store::{
    record_expiry_preflights, validate_session_ttl, validate_stored_record_expiry_profile,
    RecordExpiryPreflight, ReplicaId, RestoreScanCursorProfile, RestoreScanPage,
    RestoreScanRequest,
};
use opc_types::SpiffeId;
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Notify, OwnedSemaphorePermit, Semaphore};
use tracing;

use crate::error::{classify_tls_io_error, ProtocolError};
use crate::identity::{LocalReplicaBinding, SessionClusterId};
use crate::lifecycle::{
    directed_connection_key, material_status_matches_admission, CertificateExpiryEvidence,
    ConnectionLifecycle, ConnectionLifecyclePolicy, RetirementReason,
    SessionReauthenticationControl,
};
use crate::protocol::{
    bounded_session_op_expectations, checked_frame_size, checked_wire_frame_size,
    compare_and_set_result_matches_key, conservative_payload_budget,
    ensure_frame_fits_until as ensure_frame_fits_until_controlled,
    ensure_replication_log_success_frame_fits_until as ensure_replication_log_success_frame_fits_until_controlled,
    ensure_restore_scan_success_frame_fits_until as ensure_restore_scan_success_frame_fits_until_controlled,
    get_result_matches_key, negotiate_response_frame_size, read_frame_within, read_request_frame,
    read_request_frame_within, session_op_results_match_expectations,
    validate_request_payload_limit, write_frame_bounded_until_cancellable, BootstrapHello,
    BootstrapHelloAck, BootstrapRequest, BootstrapResponse, HelloRejectReason, InboundRequest,
    Request, Response, CONTRACT_VERSION, CURRENT_CONTRACT_PROFILE, DEFAULT_MAX_FRAME_SIZE,
    MAX_HANDSHAKE_FRAME_SIZE, MAX_SESSION_NET_BATCH_OPERATIONS, MAX_SESSION_NET_REBUILD_ENTRIES,
    MIN_NEGOTIATED_FRAME_SIZE, MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE, SESSION_NET_ALPN,
};

/// Handle to a running [`SessionReplicationServer`].
#[derive(Debug)]
pub struct ServerHandle {
    accept_handle: tokio::task::JoinHandle<()>,
    _shutdown_tx: tokio::sync::mpsc::Sender<()>,
    connection_tasks: Arc<std::sync::Mutex<ConnectionTaskRegistry>>,
    cancellation: Arc<ServerCancellation>,
}

#[derive(Debug, Default)]
struct ServerCancellation {
    stopped: AtomicBool,
    notify: Notify,
}

impl ServerCancellation {
    fn cancel(&self) {
        self.stopped.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn flag(&self) -> &AtomicBool {
        &self.stopped
    }

    async fn cancelled(&self) {
        loop {
            if self.stopped.load(Ordering::Acquire) {
                return;
            }
            let notified = self.notify.notified();
            if self.stopped.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

impl std::ops::Deref for ServerCancellation {
    type Target = AtomicBool;

    fn deref(&self) -> &Self::Target {
        self.flag()
    }
}

#[derive(Debug)]
struct ConnectionTaskRegistry {
    stopping: bool,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl ServerHandle {
    /// Schedule immediate cancellation of the listener and every connection.
    ///
    /// This non-blocking compatibility method returns before cancellation has
    /// completed. Use [`Self::abort_and_wait`] when subsequent work must know
    /// that the listener and all registered handlers have stopped.
    pub fn abort(&self) {
        // Tokio task abortion is observed only at an await. Publish a
        // cooperative stop before aborting so synchronous response encoders
        // can stop between serializer writes and retained chunks.
        self.cancellation.cancel();
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

    /// Abort the listener and every connection, then wait for all tasks to end.
    ///
    /// When this future returns, no handler registered by this server remains
    /// alive and the bound listener has been dropped. This is the deterministic
    /// lifecycle barrier for tests and callers that must restart or probe the
    /// endpoint immediately after teardown.
    pub async fn abort_and_wait(mut self) {
        // Abort every registered handler before the first await. If the caller
        // cancels this barrier, dropping JoinHandles can detach only tasks that
        // have already received cancellation. The shared `stopping` flag also
        // prevents an accept already in progress from registering a late task.
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

    /// Request graceful listener shutdown without waiting for completion.
    ///
    /// Existing connection handlers are allowed to finish independently. Use
    /// [`Self::abort_and_wait`] when a hard completion barrier is required.
    pub fn shutdown(self) {
        drop(self._shutdown_tx);
    }
}

/// Default per-frame read deadline for accepted connections.
const DEFAULT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const DEFAULT_BACKEND_OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const DEFAULT_BACKEND_OPERATION_CONCURRENCY: usize = 16;
const DEFAULT_RESTORE_SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const RESTORE_SCAN_CONCURRENCY: usize = 1;
const CAS_IDEMPOTENCY_CACHE_CAPACITY: usize = 4_096;
const CAS_IDEMPOTENCY_CACHE_PER_PEER_CAPACITY: usize = 512;
const CAS_IDEMPOTENCY_CACHE_MAX_BYTES: usize = 32 * 1024 * 1024;
const CAS_IDEMPOTENCY_CACHE_PER_PEER_MAX_BYTES: usize = 8 * 1024 * 1024;
const CAS_IDEMPOTENCY_RESULT_RETENTION: Duration = Duration::from_secs(5 * 60);
const CAS_IDEMPOTENCY_TOMBSTONE_RETENTION: Duration = Duration::from_secs(10 * 60);
const CAS_IDEMPOTENCY_CLEANUP_WORK: usize = 64;
const CAS_IDEMPOTENCY_ENTRY_OVERHEAD: usize = 128;
const CAS_OPERATION_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-net/cas-idempotency/v1\0";
const RESPONSE_LIMIT_MESSAGE: &str = "session response exceeds negotiated frame limit";
const WATCH_RESPONSE_LIMIT_MESSAGE: &str = "watch item exceeds negotiated frame limit";
const BACKEND_CONTRACT_MESSAGE: &str = "session backend returned an inconsistent response";

#[derive(Clone, Copy)]
enum ResponseFamily {
    Capabilities,
    Get,
    CompareAndSet,
    DeleteFenced,
    RefreshTtl,
    RecordExpiryPreflight,
    Batch,
    RestoreScan,
    MaxReplicationSequence,
    ReplicationLog,
    ReplicateEntry,
    RebuildReplicationState,
    Watch,
    NextLeaseInfo,
    AcquireLease,
    RenewLease,
    ReleaseLease,
    ConnectionRetiring,
}

impl ResponseFamily {
    const fn code(self) -> &'static str {
        match self {
            Self::Capabilities => "capabilities",
            Self::Get => "get",
            Self::CompareAndSet => "compare_and_set",
            Self::DeleteFenced => "delete_fenced",
            Self::RefreshTtl => "refresh_ttl",
            Self::RecordExpiryPreflight => "record_expiry_preflight",
            Self::Batch => "batch",
            Self::RestoreScan => "restore_scan",
            Self::MaxReplicationSequence => "max_replication_sequence",
            Self::ReplicationLog => "replication_log",
            Self::ReplicateEntry => "replicate_entry",
            Self::RebuildReplicationState => "rebuild_replication_state",
            Self::Watch => "watch",
            Self::NextLeaseInfo => "next_lease_info",
            Self::AcquireLease => "acquire_lease",
            Self::RenewLease => "renew_lease",
            Self::ReleaseLease => "release_lease",
            Self::ConnectionRetiring => "connection_retiring",
        }
    }
}

fn connection_failure_reason(error: &ProtocolError) -> &'static str {
    match error {
        ProtocolError::Io(error) if error.kind() == std::io::ErrorKind::TimedOut => "timeout",
        ProtocolError::Io(_) => "transport",
        ProtocolError::Authentication => "authentication",
        ProtocolError::BackendUnavailable(_) => "backend",
        ProtocolError::FrameTooLarge(_) => "frame_too_large",
        ProtocolError::VersionMismatch { .. } => "version_mismatch",
        ProtocolError::ContractMismatch => "contract_mismatch",
        ProtocolError::InvalidWireValue => "invalid_wire_value",
        ProtocolError::UnexpectedResponse => "unexpected_response",
        ProtocolError::Serialization(_) => "serialization",
    }
}

fn record_server_connection_failure(error: &ProtocolError) {
    match error {
        ProtocolError::Io(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            &METRICS.session_net_connection_failure_timeout
        }
        ProtocolError::Io(_) => &METRICS.session_net_connection_failure_transport,
        ProtocolError::Authentication => &METRICS.session_net_connection_failure_authentication,
        ProtocolError::BackendUnavailable(_) => &METRICS.session_net_connection_failure_backend,
        _ => &METRICS.session_net_connection_failure_protocol,
    }
    .fetch_add(1, Ordering::Relaxed);
}

fn capabilities_for_transport(
    mut capabilities: opc_session_store::BackendCapabilities,
    request_frame_size: usize,
    response_frame_size: usize,
) -> opc_session_store::BackendCapabilities {
    capabilities.max_value_bytes = capabilities
        .max_value_bytes
        .min(conservative_payload_budget(request_frame_size))
        .min(conservative_payload_budget(response_frame_size));
    if response_frame_size < MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE {
        capabilities.restore_scan = false;
    }
    capabilities
}

fn capabilities_for_restore_profile(
    mut capabilities: opc_session_store::BackendCapabilities,
    profile: Option<RestoreScanCursorProfile>,
) -> opc_session_store::BackendCapabilities {
    if profile != Some(RestoreScanCursorProfile::DurableOpaqueV1) {
        capabilities.restore_scan = false;
    }
    capabilities
}

fn response_write_deadline(
    timeout: std::time::Duration,
) -> Result<tokio::time::Instant, ProtocolError> {
    tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| {
            ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "response write timeout is not representable",
            ))
        })
}

fn bounded_response_deadline(
    request_deadline: tokio::time::Instant,
    timeout: std::time::Duration,
) -> Result<tokio::time::Instant, ProtocolError> {
    Ok(response_write_deadline(timeout)?.min(request_deadline))
}

fn response_write_timeout_error() -> ProtocolError {
    ProtocolError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "timed out preparing response frame",
    ))
}

fn check_response_write_deadline(deadline: tokio::time::Instant) -> Result<(), ProtocolError> {
    if tokio::time::Instant::now() >= deadline {
        Err(response_write_timeout_error())
    } else {
        Ok(())
    }
}

fn check_response_write_control(
    deadline: tokio::time::Instant,
    cancellation: &AtomicBool,
) -> Result<(), ProtocolError> {
    if cancellation.load(Ordering::Acquire) {
        return Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "response preparation cancelled",
        )));
    }
    check_response_write_deadline(deadline)
}

fn ensure_frame_fits_until<T>(
    frame: &T,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &AtomicBool,
) -> Result<(), ProtocolError>
where
    T: serde::Serialize,
{
    ensure_frame_fits_until_controlled(frame, max_frame_size, deadline, cancellation)
}

fn ensure_restore_scan_success_frame_fits_until(
    page: &RestoreScanPage,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &AtomicBool,
) -> Result<(), ProtocolError> {
    ensure_restore_scan_success_frame_fits_until_controlled(
        page,
        max_frame_size,
        deadline,
        cancellation,
    )
}

fn ensure_replication_log_success_frame_fits_until(
    entries: &[ReplicationEntry],
    max_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &AtomicBool,
) -> Result<(), ProtocolError> {
    ensure_replication_log_success_frame_fits_until_controlled(
        entries,
        max_frame_size,
        deadline,
        cancellation,
    )
}

fn record_response_write_failure(error: &ProtocolError, family: ResponseFamily) {
    let reason = match error {
        ProtocolError::FrameTooLarge(_) => "frame_too_large",
        ProtocolError::Io(error) if error.kind() == std::io::ErrorKind::TimedOut => "write_timeout",
        ProtocolError::Io(_) => "transport",
        _ => "encoding",
    };
    tracing::warn!(
        response_family = family.code(),
        reason,
        "session response write failed"
    );
}

async fn write_frame_until_server_cancellation<W, T>(
    writer: &mut W,
    frame: &T,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &ServerCancellation,
) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: serde::Serialize,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "response write cancelled",
        ))),
        result = write_frame_bounded_until_cancellable(
            writer,
            frame,
            max_frame_size,
            deadline,
            cancellation.flag(),
        ) => result,
    }
}

async fn write_post_auth_response_until<W>(
    writer: &mut W,
    response: &Response,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
    family: ResponseFamily,
    cancellation: &ServerCancellation,
) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let result = write_frame_until_server_cancellation(
        writer,
        response,
        max_frame_size,
        deadline,
        cancellation,
    )
    .await;
    if let Err(error) = &result {
        record_response_write_failure(error, family);
    }
    result
}

async fn write_post_auth_response<W>(
    writer: &mut W,
    response: &Response,
    max_frame_size: usize,
    timeout: std::time::Duration,
    family: ResponseFamily,
    cancellation: &ServerCancellation,
) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let deadline = response_write_deadline(timeout)?;
    write_post_auth_response_until(
        writer,
        response,
        max_frame_size,
        deadline,
        family,
        cancellation,
    )
    .await
}

#[cfg(test)]
async fn write_post_auth_response_with_fallback<W>(
    writer: &mut W,
    response: Response,
    fallback: Response,
    max_frame_size: usize,
    timeout: std::time::Duration,
    family: ResponseFamily,
    cancellation: &ServerCancellation,
) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let deadline = response_write_deadline(timeout)?;
    write_post_auth_response_with_fallback_until(
        writer,
        response,
        fallback,
        max_frame_size,
        deadline,
        family,
        cancellation,
    )
    .await
}

async fn write_post_auth_response_with_fallback_until<W>(
    writer: &mut W,
    response: Response,
    fallback: Response,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
    family: ResponseFamily,
    cancellation: &ServerCancellation,
) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    match write_frame_until_server_cancellation(
        writer,
        &response,
        max_frame_size,
        deadline,
        cancellation,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(ProtocolError::FrameTooLarge(_)) => {
            let ambiguity_fallback_count = ambiguity_fallback_count(&response, &fallback);
            discard_response_iteratively(response);
            if ambiguity_fallback_count != 0 {
                METRICS
                    .session_net_backend_ambiguous_outcomes
                    .fetch_add(ambiguity_fallback_count, Ordering::Relaxed);
            }
            tracing::warn!(
                response_family = family.code(),
                reason = "frame_too_large",
                "session backend response exceeded the negotiated frame limit"
            );
            write_post_auth_response_until(
                writer,
                &fallback,
                max_frame_size,
                deadline,
                family,
                cancellation,
            )
            .await
        }
        Err(other) => {
            discard_response_iteratively(response);
            record_response_write_failure(&other, family);
            Err(other)
        }
    }
}

fn response_is_ambiguous_outcome(response: &Response) -> bool {
    match response {
        Response::CompareAndSet(Err(StoreError::CasIdempotencyOutcomeUnavailable)) => true,
        Response::DeleteFenced(Err(StoreError::BackendOperationOutcomeUnavailable))
        | Response::RefreshTtl(Err(StoreError::BackendOperationOutcomeUnavailable))
        | Response::RecordExpiryPreflight(Err(StoreError::BackendOperationOutcomeUnavailable))
        | Response::Batch(Err(StoreError::BackendOperationOutcomeUnavailable))
        | Response::ReplicateEntry(Err(StoreError::BackendOperationOutcomeUnavailable))
        | Response::RebuildReplicationState(Err(StoreError::BackendOperationOutcomeUnavailable)) => {
            true
        }
        Response::AcquireLease(Err(LeaseError::OperationOutcomeUnavailable))
        | Response::RenewLease(Err(LeaseError::OperationOutcomeUnavailable))
        | Response::ReleaseLease(Err(LeaseError::OperationOutcomeUnavailable)) => true,
        Response::Batch(Ok(results)) => batch_results_have_ambiguous_outcome(results),
        _ => false,
    }
}

fn ambiguity_fallback_count(primary: &Response, fallback: &Response) -> u64 {
    u64::from(!response_is_ambiguous_outcome(primary) && response_is_ambiguous_outcome(fallback))
}

#[cfg(test)]
async fn write_watch_response<W>(
    writer: &mut W,
    response: Response,
    max_frame_size: usize,
    timeout: std::time::Duration,
    cancellation: &ServerCancellation,
) -> Result<bool, ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let deadline = response_write_deadline(timeout)?;
    write_watch_response_until(writer, response, max_frame_size, deadline, cancellation).await
}

async fn write_watch_response_until<W>(
    writer: &mut W,
    response: Response,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &ServerCancellation,
) -> Result<bool, ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    match write_frame_until_server_cancellation(
        writer,
        &response,
        max_frame_size,
        deadline,
        cancellation,
    )
    .await
    {
        Ok(()) => Ok(false),
        Err(ProtocolError::FrameTooLarge(_)) => {
            discard_watch_response_iteratively(response);
            tracing::warn!(
                response_family = ResponseFamily::Watch.code(),
                reason = "frame_too_large",
                "watch response exceeded the negotiated frame limit"
            );
            let fallback = Response::WatchEntry(Err(StoreError::BackendUnavailable(
                WATCH_RESPONSE_LIMIT_MESSAGE.to_string(),
            )));
            write_post_auth_response_until(
                writer,
                &fallback,
                max_frame_size,
                deadline,
                ResponseFamily::Watch,
                cancellation,
            )
            .await?;
            Ok(true)
        }
        Err(other) => {
            discard_watch_response_iteratively(response);
            record_response_write_failure(&other, ResponseFamily::Watch);
            Err(other)
        }
    }
}

fn discard_watch_response_iteratively(response: Response) {
    if let Response::WatchEntry(Ok(entry)) = response {
        discard_replication_entries_iteratively(vec![entry]);
    }
}

fn discard_response_iteratively(response: Response) {
    match response {
        Response::GetReplicationLog(Ok(entries)) => {
            discard_replication_entries_iteratively(entries);
        }
        Response::WatchEntry(Ok(entry)) => {
            discard_replication_entries_iteratively(vec![entry]);
        }
        response => drop(response),
    }
}

fn store_response_limit_error() -> StoreError {
    StoreError::BackendUnavailable(RESPONSE_LIMIT_MESSAGE.to_string())
}

fn backend_contract_error() -> StoreError {
    StoreError::BackendUnavailable(BACKEND_CONTRACT_MESSAGE.to_string())
}

fn cas_outcome_is_definitive(result: &Result<CompareAndSetResult, StoreError>) -> bool {
    !matches!(
        result,
        Err(StoreError::BackendUnavailable(_)
            | StoreError::BackendOperationOutcomeUnavailable
            | StoreError::CasIdempotencyOutcomeUnavailable)
    )
}

fn backend_lease_contract_error() -> LeaseError {
    LeaseError::Backend(BACKEND_CONTRACT_MESSAGE.to_string())
}

#[derive(Clone)]
struct DispatchConfig {
    binding: LocalReplicaBinding,
    max_frame_size: usize,
    idle_timeout: std::time::Duration,
    backend_operation_timeout: std::time::Duration,
    backend_slots: BackendOperationSlots,
    restore_scan_timeout: std::time::Duration,
    restore_scan_slots: Arc<Semaphore>,
    cancellation: Arc<ServerCancellation>,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
}

#[derive(Clone)]
struct BackendOperationSlots {
    read: Arc<Semaphore>,
    mutation: Arc<Semaphore>,
    lease: Arc<Semaphore>,
    watch_setup: Arc<Semaphore>,
}

impl BackendOperationSlots {
    fn new(per_family: usize) -> Self {
        Self {
            read: Arc::new(Semaphore::new(per_family)),
            mutation: Arc::new(Semaphore::new(per_family)),
            lease: Arc::new(Semaphore::new(per_family)),
            watch_setup: Arc::new(Semaphore::new(per_family)),
        }
    }
}

#[derive(Clone, Copy)]
enum BackendDeadlineOutcome {
    Read,
    Preflight,
    Mutation,
    CompareAndSet,
    RestoreScan,
}

#[derive(Clone, Copy)]
enum BackendOperationPhase {
    Queue,
    Execute,
}

impl BackendOperationPhase {
    const fn code(self) -> &'static str {
        match self {
            Self::Queue => "queue",
            Self::Execute => "execute",
        }
    }
}

fn record_backend_operation_failure(
    family: ResponseFamily,
    phase: BackendOperationPhase,
    reason: &'static str,
) {
    match (phase, reason) {
        (BackendOperationPhase::Queue, "timeout") => {
            METRICS
                .session_net_backend_queue_timeouts
                .fetch_add(1, Ordering::Relaxed);
        }
        (BackendOperationPhase::Execute, "timeout") => {
            METRICS
                .session_net_backend_execution_timeouts
                .fetch_add(1, Ordering::Relaxed);
        }
        (_, "cancelled") => {
            METRICS
                .session_net_backend_cancellations
                .fetch_add(1, Ordering::Relaxed);
        }
        (_, "peer_disconnect") => {
            METRICS
                .session_net_backend_peer_disconnects
                .fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
    tracing::warn!(
        response_family = family.code(),
        operation_phase = phase.code(),
        reason,
        "session backend operation did not complete"
    );
}

fn backend_control_error(kind: std::io::ErrorKind, message: &'static str) -> ProtocolError {
    ProtocolError::Io(std::io::Error::new(kind, message))
}

async fn await_backend_stage<R, F, T>(
    reader: &mut R,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &ServerCancellation,
    family: ResponseFamily,
    phase: BackendOperationPhase,
    future: F,
) -> Result<Option<T>, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
    F: Future<Output = T>,
{
    tokio::pin!(future);
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            record_backend_operation_failure(family, phase, "cancelled");
            Err(backend_control_error(
                std::io::ErrorKind::Interrupted,
                "backend operation cancelled",
            ))
        }
        output = &mut future => Ok(Some(output)),
        peer = read_request_frame(reader, max_frame_size) => {
            match peer {
                Err(ProtocolError::Io(error))
                    if error.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    record_backend_operation_failure(family, phase, "peer_disconnect");
                    Err(ProtocolError::Io(error))
                }
                Err(error) => Err(error),
                Ok(_pipelined_request) => {
                    record_backend_operation_failure(family, phase, "pipelined_request");
                    Err(ProtocolError::UnexpectedResponse)
                }
            }
        }
        _ = tokio::time::sleep_until(deadline) => {
            record_backend_operation_failure(family, phase, "timeout");
            Ok(None)
        }
    }
}

fn store_deadline_error(
    outcome: BackendDeadlineOutcome,
    phase: BackendOperationPhase,
) -> StoreError {
    match (outcome, phase) {
        (BackendDeadlineOutcome::Mutation, BackendOperationPhase::Execute) => {
            StoreError::BackendOperationOutcomeUnavailable
        }
        (BackendDeadlineOutcome::CompareAndSet, BackendOperationPhase::Execute) => {
            StoreError::CasIdempotencyOutcomeUnavailable
        }
        (BackendDeadlineOutcome::RestoreScan, _) => StoreError::RestoreScanWorkBudgetExceeded,
        (BackendDeadlineOutcome::Preflight, _) => {
            StoreError::BackendUnavailable("backend preflight deadline exceeded".to_string())
        }
        _ => StoreError::BackendUnavailable("backend operation deadline exceeded".to_string()),
    }
}

fn record_store_ambiguous_outcome<T>(result: &Result<T, StoreError>) {
    if matches!(
        result,
        Err(StoreError::CasIdempotencyOutcomeUnavailable
            | StoreError::BackendOperationOutcomeUnavailable)
    ) {
        METRICS
            .session_net_backend_ambiguous_outcomes
            .fetch_add(1, Ordering::Relaxed);
    }
}

fn batch_results_have_ambiguous_outcome(results: &[SessionOpResult]) -> bool {
    results.iter().any(|result| {
        matches!(
            result,
            SessionOpResult::Get(Err(StoreError::CasIdempotencyOutcomeUnavailable
                | StoreError::BackendOperationOutcomeUnavailable))
                | SessionOpResult::CompareAndSet(Err(StoreError::CasIdempotencyOutcomeUnavailable
                    | StoreError::BackendOperationOutcomeUnavailable))
                | SessionOpResult::DeleteFenced(Err(StoreError::CasIdempotencyOutcomeUnavailable
                    | StoreError::BackendOperationOutcomeUnavailable))
                | SessionOpResult::RefreshTtl(Err(StoreError::CasIdempotencyOutcomeUnavailable
                    | StoreError::BackendOperationOutcomeUnavailable))
        )
    })
}

fn batch_ambiguous_outcome_count(result: &Result<Vec<SessionOpResult>, StoreError>) -> u64 {
    u64::from(
        result
            .as_ref()
            .is_ok_and(|results| batch_results_have_ambiguous_outcome(results)),
    )
}

fn record_batch_ambiguous_outcome(result: &Result<Vec<SessionOpResult>, StoreError>) {
    let count = batch_ambiguous_outcome_count(result);
    if count != 0 {
        // One request-level signal is emitted even when several batch slots
        // report ambiguity; the metric counts ambiguous operations, not slots.
        METRICS
            .session_net_backend_ambiguous_outcomes
            .fetch_add(count, Ordering::Relaxed);
    }
}

fn record_lease_ambiguous_outcome<T>(result: &Result<T, LeaseError>) {
    if matches!(result, Err(LeaseError::OperationOutcomeUnavailable)) {
        METRICS
            .session_net_backend_ambiguous_outcomes
            .fetch_add(1, Ordering::Relaxed);
    }
}

fn normalize_store_backend_outcome<T>(
    result: Result<T, StoreError>,
    outcome: BackendDeadlineOutcome,
) -> Result<T, StoreError> {
    match (outcome, result) {
        (
            BackendDeadlineOutcome::Preflight,
            Err(
                StoreError::BackendUnavailable(_)
                | StoreError::BackendOperationOutcomeUnavailable
                | StoreError::CasIdempotencyOutcomeUnavailable,
            ),
        ) => Err(StoreError::BackendUnavailable(
            "backend record-expiry preflight unavailable".into(),
        )),
        (
            BackendDeadlineOutcome::CompareAndSet,
            Err(
                StoreError::BackendUnavailable(_)
                | StoreError::BackendOperationOutcomeUnavailable
                | StoreError::CasIdempotencyOutcomeUnavailable,
            ),
        ) => Err(StoreError::CasIdempotencyOutcomeUnavailable),
        (
            BackendDeadlineOutcome::Mutation,
            Err(
                StoreError::BackendUnavailable(_)
                | StoreError::BackendOperationOutcomeUnavailable
                | StoreError::CasIdempotencyOutcomeUnavailable,
            ),
        ) => Err(StoreError::BackendOperationOutcomeUnavailable),
        (_, result) => result,
    }
}

fn normalize_lease_backend_outcome<T>(result: Result<T, LeaseError>) -> Result<T, LeaseError> {
    match result {
        Err(LeaseError::Backend(_) | LeaseError::OperationOutcomeUnavailable) => {
            Err(LeaseError::OperationOutcomeUnavailable)
        }
        result => result,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_store_backend_operation<R, F, T>(
    reader: &mut R,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &ServerCancellation,
    family: ResponseFamily,
    slots: Arc<Semaphore>,
    deadline_outcome: BackendDeadlineOutcome,
    operation: F,
) -> Result<Result<T, StoreError>, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
    F: Future<Output = Result<T, StoreError>>,
{
    let permit: OwnedSemaphorePermit = match await_backend_stage(
        reader,
        max_frame_size,
        deadline,
        cancellation,
        family,
        BackendOperationPhase::Queue,
        slots.acquire_owned(),
    )
    .await?
    {
        Some(Ok(permit)) => permit,
        Some(Err(_closed)) => {
            return Ok(Err(StoreError::BackendUnavailable(
                "backend operation capacity unavailable".to_string(),
            )))
        }
        None => {
            return Ok(Err(store_deadline_error(
                deadline_outcome,
                BackendOperationPhase::Queue,
            )))
        }
    };
    let result = await_backend_stage(
        reader,
        max_frame_size,
        deadline,
        cancellation,
        family,
        BackendOperationPhase::Execute,
        operation,
    )
    .await?;
    drop(permit);
    let result = result.unwrap_or_else(|| {
        Err(store_deadline_error(
            deadline_outcome,
            BackendOperationPhase::Execute,
        ))
    });
    let result = normalize_store_backend_outcome(result, deadline_outcome);
    record_store_ambiguous_outcome(&result);
    Ok(result)
}

async fn run_store_backend_operation_if_capacity<R, F, T>(
    reader: &mut R,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &ServerCancellation,
    family: ResponseFamily,
    slots: Arc<Semaphore>,
    operation: F,
) -> Result<Result<T, StoreError>, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
    F: Future<Output = Result<T, StoreError>>,
{
    let permit = match slots.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            record_backend_operation_failure(
                family,
                BackendOperationPhase::Queue,
                "capacity_exhausted",
            );
            return Ok(Err(StoreError::BackendUnavailable(
                "backend operation capacity exhausted".to_string(),
            )));
        }
    };
    let result = await_backend_stage(
        reader,
        max_frame_size,
        deadline,
        cancellation,
        family,
        BackendOperationPhase::Execute,
        operation,
    )
    .await?;
    drop(permit);
    Ok(result.unwrap_or_else(|| {
        Err(store_deadline_error(
            BackendDeadlineOutcome::Read,
            BackendOperationPhase::Execute,
        ))
    }))
}

async fn run_lease_backend_operation<R, F, T>(
    reader: &mut R,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &ServerCancellation,
    family: ResponseFamily,
    slots: Arc<Semaphore>,
    operation: F,
) -> Result<Result<T, LeaseError>, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
    F: Future<Output = Result<T, LeaseError>>,
{
    let permit: OwnedSemaphorePermit = match await_backend_stage(
        reader,
        max_frame_size,
        deadline,
        cancellation,
        family,
        BackendOperationPhase::Queue,
        slots.acquire_owned(),
    )
    .await?
    {
        Some(Ok(permit)) => permit,
        Some(Err(_closed)) => {
            return Ok(Err(LeaseError::Backend(
                "backend operation capacity unavailable".to_string(),
            )))
        }
        None => {
            return Ok(Err(LeaseError::Backend(
                "backend operation deadline exceeded".to_string(),
            )))
        }
    };
    let result = await_backend_stage(
        reader,
        max_frame_size,
        deadline,
        cancellation,
        family,
        BackendOperationPhase::Execute,
        operation,
    )
    .await?;
    drop(permit);
    let result = normalize_lease_backend_outcome(
        result.unwrap_or(Err(LeaseError::OperationOutcomeUnavailable)),
    );
    record_lease_ambiguous_outcome(&result);
    Ok(result)
}

async fn next_watch_item_or_disconnect<R>(
    reader: &mut R,
    max_frame_size: usize,
    cancellation: &ServerCancellation,
    stream: &mut futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
) -> Result<Option<Result<ReplicationEntry, StoreError>>, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(backend_control_error(
            std::io::ErrorKind::Interrupted,
            "watch stream cancelled",
        )),
        item = stream.next() => Ok(item),
        peer = read_request_frame(reader, max_frame_size) => {
            match peer {
                Err(ProtocolError::Io(error))
                    if error.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    record_backend_operation_failure(
                        ResponseFamily::Watch,
                        BackendOperationPhase::Execute,
                        "peer_disconnect",
                    );
                    Err(ProtocolError::Io(error))
                }
                Err(error) => Err(error),
                Ok(_pipelined_request) => Err(ProtocolError::UnexpectedResponse),
            }
        }
    }
}

fn bounded_restore_scan_response(
    result: Result<RestoreScanPage, StoreError>,
    request: &RestoreScanRequest,
    max_response_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &AtomicBool,
) -> Result<Response, ProtocolError> {
    let page = match result {
        Ok(page) => page,
        Err(error) => {
            return bounded_restore_scan_error_response(
                error,
                max_response_frame_size,
                deadline,
                cancellation,
            );
        }
    };

    check_response_write_control(deadline, cancellation)?;
    let validation = page.validate_for_request(request);
    check_response_write_control(deadline, cancellation)?;
    if let Err(error) = validation {
        return bounded_restore_scan_error_response(
            error,
            max_response_frame_size,
            deadline,
            cancellation,
        );
    }

    match ensure_restore_scan_success_frame_fits_until(
        &page,
        max_response_frame_size,
        deadline,
        cancellation,
    ) {
        Ok(()) => Ok(Response::ScanRestoreRecords(Ok(page))),
        Err(ProtocolError::FrameTooLarge(_)) => bounded_restore_scan_error_response(
            StoreError::RestoreScanResponseTooLarge {
                max_bytes: max_response_frame_size,
            },
            max_response_frame_size,
            deadline,
            cancellation,
        ),
        Err(other) => Err(other),
    }
}

fn validate_dispatched_restore_page(
    page: &RestoreScanPage,
    dispatched_request: &RestoreScanRequest,
) -> Result<(), StoreError> {
    if page.cursor_profile != RestoreScanCursorProfile::DurableOpaqueV1 {
        return Err(StoreError::CapabilityNotSupported(
            "legacy_remote_restore_scan".to_string(),
        ));
    }
    page.validate_for_request(dispatched_request)
}

fn bounded_restore_scan_error_response(
    error: StoreError,
    max_response_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &AtomicBool,
) -> Result<Response, ProtocolError> {
    let response = Response::ScanRestoreRecords(Err(sanitize_restore_scan_error(error)));
    match ensure_frame_fits_until(&response, max_response_frame_size, deadline, cancellation) {
        Ok(()) => Ok(response),
        Err(ProtocolError::FrameTooLarge(_)) => {
            let fallback = Response::ScanRestoreRecords(Err(StoreError::BackendUnavailable(
                "restore scan error exceeded the response limit".to_string(),
            )));
            ensure_frame_fits_until(&fallback, max_response_frame_size, deadline, cancellation)?;
            Ok(fallback)
        }
        Err(other) => Err(other),
    }
}

fn sanitize_restore_scan_error(error: StoreError) -> StoreError {
    match error {
        StoreError::CapabilityNotSupported(_) => {
            StoreError::CapabilityNotSupported("restore_scan".to_string())
        }
        StoreError::BackendUnavailable(_) => {
            StoreError::BackendUnavailable("restore scan backend unavailable".to_string())
        }
        StoreError::InvalidKey(_) => {
            StoreError::InvalidKey("restore scan backend rejected a record".to_string())
        }
        StoreError::Crypto(_) => {
            StoreError::Crypto("restore scan record cryptography failed".to_string())
        }
        StoreError::Serialization(_) => {
            StoreError::Serialization("restore scan record decoding failed".to_string())
        }
        StoreError::InvalidRestoreScanRequest(_) => {
            StoreError::InvalidRestoreScanRequest("restore scan request was rejected".to_string())
        }
        StoreError::InvalidRestoreScanResponse(_) => StoreError::InvalidRestoreScanResponse(
            "restore scan backend returned an invalid page".to_string(),
        ),
        other => other,
    }
}

fn discard_replication_entries_iteratively(entries: Vec<ReplicationEntry>) {
    for entry in entries {
        let mut pending = vec![vec![entry.op].into_iter()];
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
}

fn bounded_replication_log_response(
    result: Result<Vec<ReplicationEntry>, StoreError>,
    max_response_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &AtomicBool,
) -> Result<Response, ProtocolError> {
    let mut entries = match result {
        Ok(entries) => entries,
        Err(error) => return Ok(Response::GetReplicationLog(Err(error))),
    };

    match ensure_replication_log_success_frame_fits_until(
        &entries,
        max_response_frame_size,
        deadline,
        cancellation,
    ) {
        Ok(()) => return Ok(Response::GetReplicationLog(Ok(entries))),
        Err(ProtocolError::FrameTooLarge(_)) => {}
        Err(other) => {
            discard_replication_entries_iteratively(entries);
            return Err(other);
        }
    }

    let mut lower = 0_usize;
    let mut upper = entries.len();
    while lower < upper {
        let candidate = lower + (upper - lower).div_ceil(2);
        match ensure_replication_log_success_frame_fits_until(
            &entries[..candidate],
            max_response_frame_size,
            deadline,
            cancellation,
        ) {
            Ok(()) => lower = candidate,
            Err(ProtocolError::FrameTooLarge(_)) => upper = candidate - 1,
            Err(other) => {
                discard_replication_entries_iteratively(entries);
                return Err(other);
            }
        }
    }

    if lower == 0 {
        discard_replication_entries_iteratively(entries);
        tracing::warn!(
            response_family = ResponseFamily::ReplicationLog.code(),
            reason = "frame_too_large",
            "one replication-log entry exceeded the negotiated frame limit"
        );
        let fallback = Response::GetReplicationLog(Err(store_response_limit_error()));
        return Ok(fallback);
    }

    let discarded = entries.split_off(lower);
    discard_replication_entries_iteratively(discarded);
    tracing::warn!(
        response_family = ResponseFamily::ReplicationLog.code(),
        reason = "page_shortened",
        "replication-log response was shortened to the negotiated frame limit"
    );
    Ok(Response::GetReplicationLog(Ok(entries)))
}

type CasOutcome = Result<CompareAndSetResult, StoreError>;

#[derive(Debug)]
enum CasIdempotencyState {
    InFlight {
        outcome: watch::Sender<Option<CasOutcome>>,
    },
    Complete {
        outcome: Box<CasOutcome>,
        completed_at: Instant,
    },
    Ambiguous {
        since: Instant,
    },
}

#[derive(Debug)]
struct CasIdempotencyEntry {
    peer: ReplicaId,
    operation_digest: [u8; 32],
    retained_bytes: usize,
    state: CasIdempotencyState,
}

#[derive(Debug, Default, Clone, Copy)]
struct CasPeerUsage {
    entries: usize,
    bytes: usize,
}

#[derive(Debug)]
struct CasIdempotencyCache {
    epoch: uuid::Uuid,
    entries: HashMap<uuid::Uuid, CasIdempotencyEntry>,
    order: VecDeque<uuid::Uuid>,
    peer_usage: HashMap<ReplicaId, CasPeerUsage>,
    retained_bytes: usize,
}

impl Default for CasIdempotencyCache {
    fn default() -> Self {
        Self {
            epoch: uuid::Uuid::new_v4(),
            entries: HashMap::new(),
            order: VecDeque::new(),
            peer_usage: HashMap::new(),
            retained_bytes: 0,
        }
    }
}

impl CasIdempotencyCache {
    fn epoch(&self) -> uuid::Uuid {
        self.epoch
    }

    fn begin(
        cache: &Arc<StdMutex<Self>>,
        peer: &ReplicaId,
        request_id: uuid::Uuid,
        epoch: uuid::Uuid,
        operation_digest: [u8; 32],
        now: Instant,
    ) -> CasIdempotencyAdmission {
        let mut cache_guard = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache_guard.cleanup(now);

        if epoch != cache_guard.epoch {
            record_cas_idempotency_rejection("stale_epoch");
            return CasIdempotencyAdmission::Reject(StoreError::CasIdempotencyOutcomeUnavailable);
        }

        if let Some(entry) = cache_guard.entries.get(&request_id) {
            if entry.peer != *peer || entry.operation_digest != operation_digest {
                record_cas_idempotency_rejection("identity_reuse");
                return CasIdempotencyAdmission::Reject(StoreError::CasIdempotencyConflict);
            }
            return match &entry.state {
                CasIdempotencyState::InFlight { outcome } => {
                    CasIdempotencyAdmission::Wait(outcome.subscribe())
                }
                CasIdempotencyState::Complete { outcome, .. } => {
                    CasIdempotencyAdmission::Replay(outcome.as_ref().clone())
                }
                CasIdempotencyState::Ambiguous { .. } => {
                    record_cas_idempotency_rejection("ambiguous");
                    CasIdempotencyAdmission::Reject(StoreError::CasIdempotencyOutcomeUnavailable)
                }
            };
        }

        let retained_bytes = CAS_IDEMPOTENCY_ENTRY_OVERHEAD.saturating_add(peer.as_str().len());
        let usage = cache_guard
            .peer_usage
            .get(peer)
            .copied()
            .unwrap_or_default();
        if cache_guard.entries.len() >= CAS_IDEMPOTENCY_CACHE_CAPACITY
            || usage.entries >= CAS_IDEMPOTENCY_CACHE_PER_PEER_CAPACITY
            || cache_guard
                .retained_bytes
                .checked_add(retained_bytes)
                .is_none_or(|bytes| bytes > CAS_IDEMPOTENCY_CACHE_MAX_BYTES)
            || usage
                .bytes
                .checked_add(retained_bytes)
                .is_none_or(|bytes| bytes > CAS_IDEMPOTENCY_CACHE_PER_PEER_MAX_BYTES)
        {
            record_cas_idempotency_rejection("capacity");
            return CasIdempotencyAdmission::Reject(StoreError::CasIdempotencyOutcomeUnavailable);
        }

        let (outcome, _) = watch::channel(None);
        cache_guard.order.push_back(request_id);
        cache_guard.retained_bytes += retained_bytes;
        let usage = cache_guard.peer_usage.entry(peer.clone()).or_default();
        usage.entries += 1;
        usage.bytes += retained_bytes;
        cache_guard.entries.insert(
            request_id,
            CasIdempotencyEntry {
                peer: peer.clone(),
                operation_digest,
                retained_bytes,
                state: CasIdempotencyState::InFlight { outcome },
            },
        );
        drop(cache_guard);

        CasIdempotencyAdmission::Execute(CasExecutionPermit {
            cache: Arc::clone(cache),
            request_id,
            operation_digest,
            completed: false,
        })
    }

    fn cleanup(&mut self, now: Instant) {
        let work = self.order.len().min(CAS_IDEMPOTENCY_CLEANUP_WORK);
        let mut rotate_epoch = false;
        for _ in 0..work {
            let Some(request_id) = self.order.pop_front() else {
                break;
            };
            let disposition = self
                .entries
                .get(&request_id)
                .map(|entry| match entry.state {
                    CasIdempotencyState::InFlight { .. } => CasCleanupDisposition::Keep,
                    CasIdempotencyState::Complete { completed_at, .. }
                        if now.saturating_duration_since(completed_at)
                            >= CAS_IDEMPOTENCY_RESULT_RETENTION =>
                    {
                        CasCleanupDisposition::Tombstone
                    }
                    CasIdempotencyState::Ambiguous { since }
                        if now.saturating_duration_since(since)
                            >= CAS_IDEMPOTENCY_TOMBSTONE_RETENTION =>
                    {
                        CasCleanupDisposition::Remove
                    }
                    CasIdempotencyState::Complete { .. }
                    | CasIdempotencyState::Ambiguous { .. } => CasCleanupDisposition::Keep,
                });
            match disposition {
                Some(CasCleanupDisposition::Tombstone) => {
                    self.mark_ambiguous(request_id, now);
                    self.order.push_back(request_id);
                }
                Some(CasCleanupDisposition::Remove) => {
                    rotate_epoch = true;
                    self.order.push_back(request_id);
                }
                Some(CasCleanupDisposition::Keep) => self.order.push_back(request_id),
                None => {}
            }
        }
        if rotate_epoch
            && !self
                .entries
                .values()
                .any(|entry| matches!(entry.state, CasIdempotencyState::InFlight { .. }))
        {
            self.epoch = uuid::Uuid::new_v4();
            self.entries.clear();
            self.order.clear();
            self.peer_usage.clear();
            self.retained_bytes = 0;
        }
    }

    fn resize_entry(&mut self, peer: &ReplicaId, old_bytes: usize, new_bytes: usize) -> bool {
        let additional = new_bytes.saturating_sub(old_bytes);
        let usage = self.peer_usage.get(peer).copied().unwrap_or_default();
        if self
            .retained_bytes
            .checked_add(additional)
            .is_none_or(|bytes| bytes > CAS_IDEMPOTENCY_CACHE_MAX_BYTES)
            || usage
                .bytes
                .checked_add(additional)
                .is_none_or(|bytes| bytes > CAS_IDEMPOTENCY_CACHE_PER_PEER_MAX_BYTES)
        {
            return false;
        }
        self.retained_bytes = self.retained_bytes.saturating_sub(old_bytes) + new_bytes;
        if let Some(usage) = self.peer_usage.get_mut(peer) {
            usage.bytes = usage.bytes.saturating_sub(old_bytes) + new_bytes;
        }
        true
    }

    fn mark_ambiguous(&mut self, request_id: uuid::Uuid, now: Instant) {
        let Some(entry) = self.entries.get(&request_id) else {
            return;
        };
        let peer = entry.peer.clone();
        let old_bytes = entry.retained_bytes;
        let notify = match &entry.state {
            CasIdempotencyState::InFlight { outcome } => Some(outcome.clone()),
            CasIdempotencyState::Complete { .. } | CasIdempotencyState::Ambiguous { .. } => None,
        };
        let new_bytes = CAS_IDEMPOTENCY_ENTRY_OVERHEAD + peer.as_str().len();
        let _ = self.resize_entry(&peer, old_bytes, new_bytes);
        if let Some(entry) = self.entries.get_mut(&request_id) {
            entry.retained_bytes = new_bytes;
            entry.state = CasIdempotencyState::Ambiguous { since: now };
        }
        if let Some(notify) = notify {
            let _ = notify.send(Some(Err(StoreError::CasIdempotencyOutcomeUnavailable)));
        }
    }
}

fn record_cas_idempotency_rejection(reason: &'static str) {
    tracing::debug!(
        response_family = ResponseFamily::CompareAndSet.code(),
        reason,
        "direct CAS idempotency rejected"
    );
}

#[derive(Debug, Clone, Copy)]
enum CasCleanupDisposition {
    Keep,
    Tombstone,
    Remove,
}

enum CasIdempotencyAdmission {
    Execute(CasExecutionPermit),
    Wait(watch::Receiver<Option<CasOutcome>>),
    Replay(CasOutcome),
    Reject(StoreError),
}

struct CasExecutionPermit {
    cache: Arc<StdMutex<CasIdempotencyCache>>,
    request_id: uuid::Uuid,
    operation_digest: [u8; 32],
    completed: bool,
}

impl CasExecutionPermit {
    fn complete(mut self, outcome: CasOutcome) {
        let now = Instant::now();
        let encoded_bytes =
            serde_json::to_vec(&outcome).map_or(usize::MAX, |encoded| encoded.len());
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(entry) = cache.entries.get(&self.request_id) else {
            self.completed = true;
            return;
        };
        if entry.operation_digest != self.operation_digest {
            cache.mark_ambiguous(self.request_id, now);
            self.completed = true;
            return;
        }
        let peer = entry.peer.clone();
        let old_bytes = entry.retained_bytes;
        let notify = match &entry.state {
            CasIdempotencyState::InFlight { outcome } => Some(outcome.clone()),
            CasIdempotencyState::Complete { .. } | CasIdempotencyState::Ambiguous { .. } => None,
        };
        let new_bytes = old_bytes.saturating_add(encoded_bytes);
        if !cache.resize_entry(&peer, old_bytes, new_bytes) {
            cache.mark_ambiguous(self.request_id, now);
            self.completed = true;
            return;
        }
        if let Some(entry) = cache.entries.get_mut(&self.request_id) {
            entry.retained_bytes = new_bytes;
            entry.state = CasIdempotencyState::Complete {
                outcome: Box::new(outcome.clone()),
                completed_at: now,
            };
        }
        if let Some(notify) = notify {
            let _ = notify.send(Some(outcome));
        }
        self.completed = true;
    }
}

impl Drop for CasExecutionPermit {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.mark_ambiguous(self.request_id, Instant::now());
    }
}

fn hash_cas_field(hasher: &mut Sha256, field: &[u8]) -> Result<(), StoreError> {
    let length = u64::try_from(field.len())
        .map_err(|_| StoreError::Serialization("CAS idempotency input is too large".into()))?;
    hasher.update(length.to_be_bytes());
    hasher.update(field);
    Ok(())
}

fn cas_operation_digest(
    binding: &LocalReplicaBinding,
    peer: &ReplicaId,
    request_id: uuid::Uuid,
    idempotency_epoch: uuid::Uuid,
    operation: &CompareAndSet,
) -> Result<[u8; 32], StoreError> {
    let operation = serde_json::to_vec(operation)
        .map_err(|_| StoreError::Serialization("CAS idempotency encoding failed".into()))?;
    let contract = serde_json::to_vec(&CURRENT_CONTRACT_PROFILE)
        .map_err(|_| StoreError::Serialization("CAS contract encoding failed".into()))?;
    let mut hasher = Sha256::new();
    hasher.update(CAS_OPERATION_DIGEST_DOMAIN);
    hash_cas_field(&mut hasher, binding.cluster_id().as_str().as_bytes())?;
    hash_cas_field(&mut hasher, &CONTRACT_VERSION.to_be_bytes())?;
    hash_cas_field(&mut hasher, &contract)?;
    hash_cas_field(&mut hasher, binding.configuration_id().as_bytes())?;
    hash_cas_field(
        &mut hasher,
        &binding.configuration_epoch().get().to_be_bytes(),
    )?;
    hash_cas_field(&mut hasher, peer.as_str().as_bytes())?;
    hash_cas_field(&mut hasher, request_id.as_bytes())?;
    hash_cas_field(&mut hasher, idempotency_epoch.as_bytes())?;
    hash_cas_field(&mut hasher, &operation)?;
    Ok(hasher.finalize().into())
}

async fn wait_for_cas_outcome(mut outcome: watch::Receiver<Option<CasOutcome>>) -> CasOutcome {
    loop {
        if let Some(outcome) = outcome.borrow().clone() {
            return outcome;
        }
        if outcome.changed().await.is_err() {
            return Err(StoreError::CasIdempotencyOutcomeUnavailable);
        }
    }
}

/// Networked session replication server.
pub struct SessionReplicationServer {
    backend: Arc<dyn SessionStoreBackend>,
    tls_config: Option<opc_tls::AuthenticatedServerConfig>,
    binding: LocalReplicaBinding,
    max_connections: usize,
    max_frame_size: usize,
    idle_timeout: std::time::Duration,
    backend_operation_timeout: std::time::Duration,
    backend_operation_concurrency: usize,
    restore_scan_timeout: std::time::Duration,
    cas_idempotency_cache: Arc<StdMutex<CasIdempotencyCache>>,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
}

impl fmt::Debug for SessionReplicationServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionReplicationServer")
            .field("tls_config", &self.tls_config.is_some())
            .field("binding", &self.binding)
            .field("max_connections", &self.max_connections)
            .field("max_frame_size", &self.max_frame_size)
            .field("backend_operation_timeout", &self.backend_operation_timeout)
            .field(
                "backend_operation_concurrency",
                &self.backend_operation_concurrency,
            )
            .field("restore_scan_timeout", &self.restore_scan_timeout)
            .finish()
    }
}

impl SessionReplicationServer {
    /// Create a new mTLS server.
    ///
    /// `binding` selects this server's exact stable replica ID and immutable
    /// authorized member manifest. Each accepted connection must present a
    /// canonical SPIFFE identity mapped to its claimed client `ReplicaId` and
    /// must agree on this server ID and manifest scope before backend dispatch.
    /// Session caches and tickets are disabled so every accepted connection
    /// performs a full mutual-TLS certificate exchange.
    ///
    /// Production session replication must run over authenticated TLS. Use
    /// [`SessionReplicationServer::new_insecure`] only in test builds that
    /// explicitly enable the `insecure-test` feature.
    pub fn new(
        backend: Arc<dyn SessionStoreBackend>,
        tls_config: opc_tls::AuthenticatedServerConfig,
        binding: LocalReplicaBinding,
    ) -> Self {
        Self {
            backend,
            tls_config: Some(tls_config),
            binding,
            max_connections: 128,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            backend_operation_timeout: DEFAULT_BACKEND_OPERATION_TIMEOUT,
            backend_operation_concurrency: DEFAULT_BACKEND_OPERATION_CONCURRENCY,
            restore_scan_timeout: DEFAULT_RESTORE_SCAN_TIMEOUT,
            cas_idempotency_cache: Arc::new(StdMutex::new(CasIdempotencyCache::default())),
            lifecycle_policy: ConnectionLifecyclePolicy::default(),
            reauthentication: SessionReauthenticationControl::new(),
        }
    }

    /// Create a new plaintext server (requires `insecure-test` feature).
    #[cfg(feature = "insecure-test")]
    pub fn new_insecure(backend: Arc<dyn SessionStoreBackend>) -> Self {
        Self {
            backend,
            tls_config: None,
            binding: crate::identity::insecure_test_server_binding(),
            max_connections: 128,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            backend_operation_timeout: DEFAULT_BACKEND_OPERATION_TIMEOUT,
            backend_operation_concurrency: DEFAULT_BACKEND_OPERATION_CONCURRENCY,
            restore_scan_timeout: DEFAULT_RESTORE_SCAN_TIMEOUT,
            cas_idempotency_cache: Arc::new(StdMutex::new(CasIdempotencyCache::default())),
            lifecycle_policy: ConnectionLifecyclePolicy::default(),
            reauthentication: SessionReauthenticationControl::new(),
        }
    }

    /// Set the per-frame read deadline for accepted connections. A peer that
    /// does not deliver a complete frame within this window is disconnected,
    /// freeing its connection slot.
    pub fn with_idle_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the post-decode lifetime of backend-slot queueing plus backend work
    /// for one authenticated request. The server first allows one
    /// `idle_timeout` to receive a complete frame, then starts this deadline,
    /// and finally reserves another `idle_timeout` for bounded response
    /// validation, encoding, and socket write. A connection slot therefore has
    /// three bounded phases; backend timeout plus the final idle timeout is the
    /// checked post-decode lifetime.
    pub fn with_backend_operation_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.backend_operation_timeout = timeout;
        self
    }

    /// Set the independent concurrency bound applied to each backend family:
    /// reads, mutations, lease mutations, and watch setup. Restore scan keeps
    /// its stricter dedicated single-worker bound.
    pub fn with_backend_operation_concurrency(mut self, per_family: usize) -> Self {
        self.backend_operation_concurrency = per_family;
        self
    }

    /// Set the maximum duration of one cancellable backend restore-scan
    /// request. Blocking backend implementations must enforce their own work
    /// bounds; bounded SQLite/quorum scan work remains tracked in #133.
    pub fn with_restore_scan_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.restore_scan_timeout = timeout;
        self
    }

    /// Set the maximum number of concurrent connections.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set the maximum post-bootstrap frame size in bytes.
    ///
    /// Values outside
    /// [`crate::MIN_NEGOTIATED_FRAME_SIZE`]..=[`crate::MAX_NEGOTIATED_FRAME_SIZE`]
    /// fail during [`Self::listen`] before the socket is bound.
    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    /// Set the finite authentication, drain, and reconnect policy.
    #[must_use]
    pub fn with_connection_lifecycle(mut self, policy: ConnectionLifecyclePolicy) -> Self {
        self.lifecycle_policy = policy;
        self
    }

    /// Share an orchestration control that gracefully retires authenticated
    /// connections through the bounded drain path.
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

    /// Bind and start accepting connections.
    pub async fn listen(
        self,
        bind_addr: SocketAddr,
    ) -> std::io::Result<(ServerHandle, SocketAddr)> {
        if self.max_connections == 0 || self.max_connections > Semaphore::MAX_PERMITS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "session connection limit is outside the supported range",
            ));
        }
        if self.backend_operation_concurrency == 0
            || self.backend_operation_concurrency > Semaphore::MAX_PERMITS
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "session backend operation limit is outside the supported range",
            ));
        }
        if self.max_frame_size < MIN_NEGOTIATED_FRAME_SIZE
            || checked_wire_frame_size(self.max_frame_size).is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "session frame size is outside the negotiated profile range",
            ));
        }
        let now = tokio::time::Instant::now();
        if self.lifecycle_policy.validate_at(now).is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "session connection lifecycle policy is not representable",
            ));
        }
        if now.checked_add(self.idle_timeout).is_none()
            || now
                .checked_add(self.backend_operation_timeout)
                .and_then(|deadline| deadline.checked_add(self.idle_timeout))
                .is_none()
            || now.checked_add(self.restore_scan_timeout).is_none()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "session server timeout is not representable",
            ));
        }
        let listener = TcpListener::bind(bind_addr).await?;
        let bound_addr = listener.local_addr()?;
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
        let sem = Arc::new(Semaphore::new(self.max_connections));
        let tls_config = self.tls_config.clone();
        let backend = self.backend.clone();
        let cas_idempotency_cache = self.cas_idempotency_cache.clone();
        let cancellation = Arc::new(ServerCancellation::default());
        let dispatch_config = DispatchConfig {
            binding: self.binding.clone(),
            max_frame_size: self.max_frame_size,
            idle_timeout: self.idle_timeout,
            backend_operation_timeout: self.backend_operation_timeout,
            backend_slots: BackendOperationSlots::new(self.backend_operation_concurrency),
            restore_scan_timeout: self.restore_scan_timeout,
            restore_scan_slots: Arc::new(Semaphore::new(RESTORE_SCAN_CONCURRENCY)),
            cancellation: cancellation.clone(),
            lifecycle_policy: self.lifecycle_policy,
            reauthentication: self.reauthentication.clone(),
        };
        let connection_tasks = Arc::new(std::sync::Mutex::new(ConnectionTaskRegistry {
            stopping: false,
            handles: Vec::new(),
        }));
        let connection_tasks_clone = connection_tasks.clone();

        let handle = tokio::spawn(async move {
            loop {
                let permit = match sem.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };

                tokio::select! {
                    biased;
                    _ = shutdown_rx.recv() => break,
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, _peer)) => {
                                let backend = backend.clone();
                                let tls_config = tls_config.clone();
                                let cas_idempotency_cache = cas_idempotency_cache.clone();
                                let dispatch_config = dispatch_config.clone();
                                let mut registry = connection_tasks_clone
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                registry.handles.retain(|handle| !handle.is_finished());
                                if registry.stopping {
                                    break;
                                }
                                let conn_handle = tokio::spawn(async move {
                                    let _permit = permit;
                                    METRICS
                                        .session_net_connection_attempts
                                        .fetch_add(1, Ordering::Relaxed);
                                    let result = handle_connection(
                                        backend,
                                        stream,
                                        tls_config,
                                        cas_idempotency_cache,
                                        dispatch_config,
                                    )
                                    .await;
                                    if let Err(error) = result {
                                        record_server_connection_failure(&error);
                                        tracing::debug!(
                                            reason = connection_failure_reason(&error),
                                            "connection handler exited"
                                        );
                                    } else {
                                        METRICS
                                            .session_net_connection_successes
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                });
                                registry.handles.push(conn_handle);
                            }
                            Err(_error) => {
                                tracing::warn!(reason = "transport", "session accept failed");
                            }
                        }
                    }
                }
            }
        });

        Ok((
            ServerHandle {
                accept_handle: handle,
                _shutdown_tx: shutdown_tx,
                connection_tasks,
                cancellation,
            },
            bound_addr,
        ))
    }
}

fn session_server_tls_config(config: Arc<opc_tls::ServerConfig>) -> Arc<opc_tls::ServerConfig> {
    let mut config = config.as_ref().clone();
    config.alpn_protocols = vec![SESSION_NET_ALPN.to_vec()];
    // A resumed session may authenticate from cached state rather than the
    // certificate currently selected by the reloadable SVID resolver. Disable
    // every server-side resumption mechanism so reconnect always observes and
    // verifies the live peer certificate.
    config.session_storage = Arc::new(tokio_rustls::rustls::server::NoServerSessionStorage {});
    config.ticketer = Arc::new(DisabledSessionTickets);
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    Arc::new(config)
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

enum ConnectionPeerIdentity {
    Authenticated(SpiffeId),
    InsecureTest,
}

struct PendingServerLifecycle {
    handshake: Option<opc_tls::TlsServerHandshake>,
    tls_config: Option<opc_tls::AuthenticatedServerConfig>,
    local_certificate_expiry: Option<CertificateExpiryEvidence>,
    peer_certificate_expiry: Option<CertificateExpiryEvidence>,
    established_at: tokio::time::Instant,
    generation: u64,
    #[cfg(test)]
    expire_at_final_ack_boundary: bool,
}

enum PendingServerAdmissionError {
    Retired(RetirementReason),
    Protocol(ProtocolError),
}

impl PendingServerLifecycle {
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
        admitted_generation: u64,
    ) -> Result<
        (
            ConnectionLifecycle,
            Option<opc_tls::AuthenticatedServerConfig>,
        ),
        PendingServerAdmissionError,
    > {
        if admitted_generation != self.generation {
            return Err(PendingServerAdmissionError::Retired(
                RetirementReason::Explicit,
            ));
        }
        let epoch = match self.handshake {
            Some(handshake) => {
                let admission = handshake.admit().map_err(|_| {
                    PendingServerAdmissionError::Retired(RetirementReason::MaterialEpoch)
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
        .map_err(|_| PendingServerAdmissionError::Protocol(ProtocolError::InvalidWireValue))?;
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

struct LifecycleTask(tokio::task::JoinHandle<()>);

impl Drop for LifecycleTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn wait_server_material_change(receiver: &mut Option<opc_tls::TlsMaterialStatusReceiver>) {
    let closed = match receiver.as_mut() {
        Some(receiver) => receiver.changed().await.is_err(),
        None => {
            std::future::pending::<()>().await;
            false
        }
    };
    if closed {
        *receiver = None;
    }
}

fn spawn_connection_lifecycle(
    mut lifecycle: ConnectionLifecycle,
    peer_key: Vec<u8>,
    tls_config: Option<opc_tls::AuthenticatedServerConfig>,
    reauthentication: SessionReauthenticationControl,
    server_cancellation: Arc<ServerCancellation>,
    cancellation: Arc<ServerCancellation>,
) -> (LifecycleTask, watch::Receiver<bool>) {
    let (retirement_tx, retirement_rx) = watch::channel(false);
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
                &peer_key,
            );
            if lifecycle.retirement(now).is_some() {
                retirement_tx.send_replace(true);
                let hard_deadline = match lifecycle.hard_deadline() {
                    Ok(deadline) => deadline,
                    Err(_) => {
                        cancellation.cancel();
                        return;
                    }
                };
                tokio::select! {
                    _ = server_cancellation.cancelled() => cancellation.cancel(),
                    _ = tokio::time::sleep_until(hard_deadline) => {
                        lifecycle.record_hard_overrun();
                        cancellation.cancel();
                    },
                }
                return;
            }
            let retire_at = lifecycle.retire_at();
            tokio::select! {
                biased;
                _ = server_cancellation.cancelled() => {
                    cancellation.cancel();
                    return;
                }
                _ = reauthentication_rx.changed() => {}
                _ = wait_server_material_change(&mut material_rx) => {}
                _ = tokio::time::sleep_until(retire_at) => {}
            }
        }
    });
    (LifecycleTask(task), retirement_rx)
}

async fn handle_connection(
    backend: Arc<dyn SessionStoreBackend>,
    stream: TcpStream,
    tls_config: Option<opc_tls::AuthenticatedServerConfig>,
    cas_idempotency_cache: Arc<StdMutex<CasIdempotencyCache>>,
    dispatch_config: DispatchConfig,
) -> Result<(), ProtocolError> {
    let idle_timeout = dispatch_config.idle_timeout;
    if let Some(tls_config) = tls_config {
        let generation = dispatch_config.reauthentication.generation();
        let handshake = tls_config
            .begin_handshake()
            .map_err(|_| ProtocolError::Authentication)?;
        let acceptor =
            tokio_rustls::TlsAcceptor::from(session_server_tls_config(handshake.rustls_config()));
        let tls_stream = tokio::time::timeout(idle_timeout, acceptor.accept(stream))
            .await
            .map_err(|_| {
                ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TLS handshake timed out",
                ))
            })?
            .map_err(classify_tls_io_error)?;
        let established_at = tokio::time::Instant::now();
        if tls_stream.get_ref().1.alpn_protocol() != Some(SESSION_NET_ALPN) {
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
        let (mut r, mut w) = tokio::io::split(tls_stream);
        dispatch(
            backend,
            cas_idempotency_cache,
            &mut r,
            &mut w,
            ConnectionPeerIdentity::Authenticated(peer.spiffe_id().clone()),
            PendingServerLifecycle {
                handshake: Some(handshake),
                tls_config: Some(tls_config),
                local_certificate_expiry: Some(local_certificate_expiry),
                peer_certificate_expiry: Some(peer_certificate_expiry),
                established_at,
                generation,
                #[cfg(test)]
                expire_at_final_ack_boundary: false,
            },
            dispatch_config,
        )
        .await
    } else {
        let (mut r, mut w) = tokio::io::split(stream);
        dispatch(
            backend,
            cas_idempotency_cache,
            &mut r,
            &mut w,
            ConnectionPeerIdentity::InsecureTest,
            PendingServerLifecycle::insecure(dispatch_config.reauthentication.generation()),
            dispatch_config,
        )
        .await
    }
}

async fn dispatch<R, W>(
    backend: Arc<dyn SessionStoreBackend>,
    cas_idempotency_cache: Arc<StdMutex<CasIdempotencyCache>>,
    reader: &mut R,
    writer: &mut W,
    peer_identity: ConnectionPeerIdentity,
    pending_lifecycle: PendingServerLifecycle,
    dispatch_config: DispatchConfig,
) -> Result<(), ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let DispatchConfig {
        binding,
        max_frame_size,
        idle_timeout,
        backend_operation_timeout,
        backend_slots,
        restore_scan_timeout,
        restore_scan_slots,
        cancellation: server_cancellation,
        lifecycle_policy,
        reauthentication,
    } = dispatch_config;
    #[cfg(test)]
    let expire_at_final_ack_boundary = pending_lifecycle.expire_at_final_ack_boundary;

    // Start the authentication clock at TLS completion, not after a peer
    // eventually sends Hello. A stalled peer cannot retain a slot past the
    // certificate/age hard bound, and no application admission starts after
    // the soft boundary.
    let bootstrap_lifecycle = pending_lifecycle.provisional_lifecycle(lifecycle_policy)?;
    let cancellation = Arc::new(ServerCancellation::default());
    let bootstrap_hard_deadline = bootstrap_lifecycle
        .hard_deadline()
        .map_err(|_| ProtocolError::InvalidWireValue)?;
    let bootstrap_server_cancellation = server_cancellation.clone();
    let bootstrap_cancellation = cancellation.clone();
    let bootstrap_hard_lifecycle = bootstrap_lifecycle.clone();
    let _bootstrap_hard_task = LifecycleTask(tokio::spawn(async move {
        tokio::select! {
            _ = bootstrap_server_cancellation.cancelled() => {}
            _ = tokio::time::sleep_until(bootstrap_hard_deadline) => {
                let now = tokio::time::Instant::now();
                let _ = bootstrap_hard_lifecycle.retirement(now);
                bootstrap_hard_lifecycle.record_hard_overrun();
            }
        }
        bootstrap_cancellation.cancel();
    }));
    let mut bootstrap_reauthentication_rx = reauthentication.subscribe();
    let mut bootstrap_material_rx = pending_lifecycle
        .tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedServerConfig::subscribe_material_changes);
    let hello: BootstrapRequest = {
        let hello_read = read_frame_within(
            reader,
            max_frame_size.min(MAX_HANDSHAKE_FRAME_SIZE),
            idle_timeout,
        );
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
                return retire_bootstrap(writer, idle_timeout, &cancellation).await;
            }
            if !material_status_matches_admission(
                bootstrap_lifecycle.admitted_material_epoch(),
                current_material_status,
            ) {
                bootstrap_lifecycle.record_forced_retirement(RetirementReason::MaterialEpoch);
                return retire_bootstrap(writer, idle_timeout, &cancellation).await;
            }
            if bootstrap_lifecycle.retirement(now).is_some() {
                return retire_bootstrap(writer, idle_timeout, &cancellation).await;
            }
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    return Err(ProtocolError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "session bootstrap authentication deadline expired",
                    )));
                }
                changed = bootstrap_reauthentication_rx.changed() => {
                    if changed.is_err() {
                        return Err(ProtocolError::Authentication);
                    }
                }
                _ = wait_server_material_change(&mut bootstrap_material_rx) => {}
                _ = tokio::time::sleep_until(bootstrap_lifecycle.retire_at()) => {}
                result = &mut hello_read => break result?,
            }
        }
    };
    let BootstrapRequest::Hello(BootstrapHello {
        contract_version,
        node_id,
        expected_server_replica_id,
        cluster_id,
        configuration_id,
        configuration_epoch,
        handshake_nonce,
        contract_profile,
        requested_response_frame_size,
    }) = hello;
    if contract_version != CONTRACT_VERSION {
        write_bootstrap_ack(
            writer,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            idle_timeout,
            &cancellation,
        )
        .await?;
        return Err(ProtocolError::VersionMismatch {
            local: CONTRACT_VERSION,
            remote: contract_version,
        });
    }
    if contract_profile != Some(CURRENT_CONTRACT_PROFILE) {
        write_bootstrap_ack(
            writer,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            idle_timeout,
            &cancellation,
        )
        .await?;
        return Err(ProtocolError::ContractMismatch);
    }

    let Some(requested_response_frame_size) = requested_response_frame_size else {
        return reject_hello(
            writer,
            HelloRejectReason::Malformed,
            idle_timeout,
            &cancellation,
        )
        .await;
    };
    let accepted_response_frame_size =
        match negotiate_response_frame_size(requested_response_frame_size, max_frame_size) {
            Ok(size) => size,
            Err(_) => {
                return reject_hello(
                    writer,
                    HelloRejectReason::Malformed,
                    idle_timeout,
                    &cancellation,
                )
                .await;
            }
        };
    let effective_response_frame_size = checked_frame_size(accepted_response_frame_size)?;
    let server_request_frame_size = checked_wire_frame_size(max_frame_size)?;

    let Some(expected_server_replica_id) = expected_server_replica_id else {
        return reject_hello(
            writer,
            HelloRejectReason::Malformed,
            idle_timeout,
            &cancellation,
        )
        .await;
    };
    let Some(cluster_id) = cluster_id else {
        return reject_hello(
            writer,
            HelloRejectReason::Malformed,
            idle_timeout,
            &cancellation,
        )
        .await;
    };
    let Some(configuration_id) = configuration_id else {
        return reject_hello(
            writer,
            HelloRejectReason::Malformed,
            idle_timeout,
            &cancellation,
        )
        .await;
    };
    let Some(configuration_epoch) = configuration_epoch else {
        return reject_hello(
            writer,
            HelloRejectReason::Malformed,
            idle_timeout,
            &cancellation,
        )
        .await;
    };
    let Some(handshake_nonce) = handshake_nonce else {
        return reject_hello(
            writer,
            HelloRejectReason::Malformed,
            idle_timeout,
            &cancellation,
        )
        .await;
    };

    let client_replica_id = match ReplicaId::new(node_id) {
        Ok(replica_id) => replica_id,
        Err(_) => {
            return reject_hello(
                writer,
                HelloRejectReason::Malformed,
                idle_timeout,
                &cancellation,
            )
            .await;
        }
    };
    let expected_server_replica_id = match ReplicaId::new(expected_server_replica_id) {
        Ok(replica_id) => replica_id,
        Err(_) => {
            return reject_hello(
                writer,
                HelloRejectReason::Malformed,
                idle_timeout,
                &cancellation,
            )
            .await;
        }
    };
    if SessionClusterId::new(cluster_id.clone()).is_err() || !is_configuration_id(&configuration_id)
    {
        return reject_hello(
            writer,
            HelloRejectReason::Malformed,
            idle_timeout,
            &cancellation,
        )
        .await;
    }

    let configured_client_spiffe = binding.member_spiffe_id(&client_replica_id);
    let authenticated_client_matches = match (&peer_identity, configured_client_spiffe) {
        (ConnectionPeerIdentity::Authenticated(actual), Some(configured)) => {
            actual.as_str() == configured.as_str()
        }
        (ConnectionPeerIdentity::InsecureTest, Some(_)) => true,
        _ => false,
    };
    let scope_matches = expected_server_replica_id == *binding.local_replica_id()
        && cluster_id == binding.cluster_id().as_str()
        && configuration_id == binding.configuration_id().to_hex()
        && configuration_epoch == binding.configuration_epoch().get();
    if !authenticated_client_matches || !scope_matches {
        return reject_hello(
            writer,
            HelloRejectReason::Authentication,
            idle_timeout,
            &cancellation,
        )
        .await;
    }

    let cas_idempotency_epoch = cas_idempotency_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .epoch();
    // Validate the immutable TLS material and explicit generation before an
    // Accepted frame can become caller-visible. A rotation during bootstrap
    // closes the connection without publishing a false application admission.
    let mut admission_reauthentication_rx = reauthentication.subscribe();
    let (mut lifecycle, lifecycle_tls_config) =
        match pending_lifecycle.admit(lifecycle_policy, reauthentication.generation()) {
            Ok(admitted) => admitted,
            // Peer identity and scope already succeeded. An admission epoch
            // mismatch is a concurrent local retirement, not a permanent
            // peer authentication failure. Prove that no request was
            // dispatched so a client can reconnect safely.
            Err(PendingServerAdmissionError::Retired(reason)) => {
                bootstrap_lifecycle.record_forced_retirement(reason);
                return retire_bootstrap(writer, idle_timeout, &cancellation).await;
            }
            Err(PendingServerAdmissionError::Protocol(error)) => return Err(error),
        };
    drop(bootstrap_lifecycle);
    let mut admission_material_rx = lifecycle_tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedServerConfig::subscribe_material_changes);
    let peer_key = directed_connection_key(
        b"direct",
        client_replica_id.as_str(),
        binding.local_replica_id().as_str(),
    )
    .to_vec();
    let now = tokio::time::Instant::now();
    let admitted_material_epoch = lifecycle.admitted_material_epoch();
    let current_material_status = lifecycle_tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedServerConfig::material_status);
    lifecycle.observe_rotation(
        now,
        reauthentication.generation(),
        current_material_status.map(|status| status.epoch()),
        &peer_key,
    );
    if let Some(reason) = lifecycle.evidence_mismatch_reason(
        reauthentication.generation(),
        current_material_status.map(|status| status.epoch()),
    ) {
        lifecycle.record_forced_retirement(reason);
        return retire_bootstrap(writer, idle_timeout, &cancellation).await;
    }
    if admission_reauthentication_rx.has_changed().unwrap_or(true) {
        lifecycle.record_forced_retirement(RetirementReason::Explicit);
        return retire_bootstrap(writer, idle_timeout, &cancellation).await;
    }
    if !material_status_matches_admission(admitted_material_epoch, current_material_status) {
        lifecycle.record_forced_retirement(RetirementReason::MaterialEpoch);
        return retire_bootstrap(writer, idle_timeout, &cancellation).await;
    }
    if lifecycle.retirement(now).is_some() {
        return retire_bootstrap(writer, idle_timeout, &cancellation).await;
    }
    drop(_bootstrap_hard_task);
    let cancellation = Arc::new(ServerCancellation::default());
    let admitted_generation = lifecycle.admitted_generation();
    let (_lifecycle_task, mut retirement_rx) = spawn_connection_lifecycle(
        lifecycle.clone(),
        peer_key,
        lifecycle_tls_config.clone(),
        reauthentication.clone(),
        server_cancellation.clone(),
        cancellation.clone(),
    );
    // This is the final zero-Ack-byte boundary. Before the acknowledgement
    // future exists, a complete retirement frame is an unambiguous proof of
    // no application admission. Once that future is polled it may have
    // written a partial frame, so every later retirement branch only closes
    // the connection and must never append a second bootstrap frame.
    let pre_ack_material_status = lifecycle_tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedServerConfig::material_status);
    if let Some(reason) = lifecycle.evidence_mismatch_reason(
        reauthentication.generation(),
        pre_ack_material_status.map(|status| status.epoch()),
    ) {
        lifecycle.record_forced_retirement(reason);
        return retire_bootstrap(writer, idle_timeout, &cancellation).await;
    }
    if !material_status_matches_admission(admitted_material_epoch, pre_ack_material_status) {
        lifecycle.record_forced_retirement(RetirementReason::MaterialEpoch);
        return retire_bootstrap(writer, idle_timeout, &cancellation).await;
    }
    if *retirement_rx.borrow() {
        return retire_bootstrap(writer, idle_timeout, &cancellation).await;
    }
    #[cfg(test)]
    if expire_at_final_ack_boundary {
        // Deterministically model the soft deadline crossing after the earlier
        // sample while the spawned lifecycle task has not been scheduled.
        lifecycle.expire_at_final_ack_boundary_for_test();
    }
    if lifecycle.retirement(tokio::time::Instant::now()).is_some() {
        return retire_bootstrap(writer, idle_timeout, &cancellation).await;
    }
    {
        let acknowledgement = write_bootstrap_ack(
            writer,
            Some(binding.local_replica_id().as_str().to_string()),
            Some(client_replica_id.as_str().to_string()),
            Some(binding.cluster_id().as_str().to_string()),
            Some(binding.configuration_id().to_hex()),
            Some(binding.configuration_epoch().get()),
            Some(handshake_nonce),
            Some(cas_idempotency_epoch),
            Some(accepted_response_frame_size),
            Some(server_request_frame_size),
            idle_timeout,
            &cancellation,
        );
        tokio::pin!(acknowledgement);
        loop {
            tokio::select! {
                biased;
                _ = server_cancellation.cancelled() => return Ok(()),
                changed = admission_reauthentication_rx.changed() => {
                    if changed.is_err() || reauthentication.generation() != admitted_generation {
                        lifecycle.record_forced_retirement(RetirementReason::Explicit);
                        return Ok(());
                    }
                }
                _ = wait_server_material_change(&mut admission_material_rx) => {
                    let status = lifecycle_tls_config
                        .as_ref()
                        .map(opc_tls::AuthenticatedServerConfig::material_status);
                    if !material_status_matches_admission(admitted_material_epoch, status) {
                        lifecycle.record_forced_retirement(RetirementReason::MaterialEpoch);
                        return Ok(());
                    }
                }
                _ = retirement_rx.changed() => return Ok(()),
                result = &mut acknowledgement => {
                    result?;
                    break;
                }
            }
        }
    }

    let transport_payload_limit = conservative_payload_budget(max_frame_size)
        .min(conservative_payload_budget(effective_response_frame_size));

    // Dispatch loop
    loop {
        // Keep one exact request read pinned while soft retirement races
        // admission. If retirement wins, finishing this authenticated frame
        // is only correlation: the request is never validated for dispatch,
        // sent to the backend, or inserted into an outcome cache. A complete
        // fixed response therefore proves that this request did not execute.
        let inbound_result = {
            let inbound_read = read_request_frame_within(reader, max_frame_size, idle_timeout);
            tokio::pin!(inbound_read);
            let mut admitted_request = None;
            let retiring = if *retirement_rx.borrow() {
                true
            } else {
                tokio::select! {
                    biased;
                    changed = retirement_rx.changed() => {
                        let _ = changed;
                        true
                    }
                    inbound = &mut inbound_read => {
                        admitted_request = Some(inbound);
                        false
                    },
                }
            };
            if retiring {
                let correlated_request = tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => return Ok(()),
                    inbound = &mut inbound_read => inbound,
                };
                match correlated_request {
                    Ok(_request_never_dispatched) => {
                        write_post_auth_response(
                            writer,
                            &Response::ConnectionRetiring,
                            effective_response_frame_size,
                            idle_timeout,
                            ResponseFamily::ConnectionRetiring,
                            &cancellation,
                        )
                        .await?;
                        return Ok(());
                    }
                    Err(ProtocolError::Io(error))
                        if error.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            }
            match admitted_request {
                Some(inbound) => inbound,
                None => inbound_read.await,
            }
        };
        let inbound = match inbound_result {
            Ok(request) => request,
            Err(ProtocolError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };
        let req = match inbound {
            InboundRequest::Operation(request) => request,
            InboundRequest::ReplicateEntryOperationLimitExceeded => {
                write_post_auth_response(
                    writer,
                    &Response::ReplicateEntry(Err(StoreError::ReplicationOperationLimitExceeded)),
                    effective_response_frame_size,
                    idle_timeout,
                    ResponseFamily::ReplicateEntry,
                    &cancellation,
                )
                .await?;
                continue;
            }
            InboundRequest::RebuildReplicationStateOperationLimitExceeded => {
                write_post_auth_response(
                    writer,
                    &Response::RebuildReplicationState(Err(
                        StoreError::ReplicationOperationLimitExceeded,
                    )),
                    effective_response_frame_size,
                    idle_timeout,
                    ResponseFamily::RebuildReplicationState,
                    &cancellation,
                )
                .await?;
                continue;
            }
        };
        let mut request_payload_error =
            validate_request_payload_limit(&req, transport_payload_limit).err();
        let operation_deadline = tokio::time::Instant::now()
            .checked_add(backend_operation_timeout)
            .ok_or_else(|| {
                backend_control_error(
                    std::io::ErrorKind::InvalidInput,
                    "backend operation timeout is not representable",
                )
            })?;
        // Reserve a separate, bounded response-preparation/write interval.
        // Reusing the backend deadline would make a timeout impossible to
        // report: it would already be expired before the typed result was
        // encoded. The checked sum is the post-decode dispatch/response
        // lifetime; the preceding frame read has its own idle-timeout bound.
        let request_deadline = operation_deadline
            .checked_add(idle_timeout)
            .ok_or_else(|| {
                backend_control_error(
                    std::io::ErrorKind::InvalidInput,
                    "request timeout is not representable",
                )
            })?;

        match req {
            Request::Capabilities => {
                let backend_capabilities = run_store_backend_operation_if_capacity(
                    reader,
                    max_frame_size,
                    operation_deadline,
                    &cancellation,
                    ResponseFamily::Capabilities,
                    backend_slots.read.clone(),
                    async { Ok(backend.capabilities().await) },
                )
                .await?
                .unwrap_or_else(|_| opc_session_store::BackendCapabilities::minimal());
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                let backend_capabilities = capabilities_for_restore_profile(
                    backend_capabilities,
                    backend.restore_scan_cursor_profile(),
                );
                let caps = capabilities_for_transport(
                    backend_capabilities,
                    max_frame_size,
                    effective_response_frame_size,
                );
                write_post_auth_response_until(
                    writer,
                    &Response::Capabilities(caps),
                    effective_response_frame_size,
                    response_deadline,
                    ResponseFamily::Capabilities,
                    &cancellation,
                )
                .await?;
            }
            Request::Get { key } => {
                let result = run_store_backend_operation(
                    reader,
                    max_frame_size,
                    operation_deadline,
                    &cancellation,
                    ResponseFamily::Get,
                    backend_slots.read.clone(),
                    BackendDeadlineOutcome::Read,
                    backend.get(&key),
                )
                .await?;
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                let result = if get_result_matches_key(&key, &result) {
                    result
                } else {
                    Err(backend_contract_error())
                };
                write_post_auth_response_with_fallback_until(
                    writer,
                    Response::Get(result),
                    Response::Get(Err(store_response_limit_error())),
                    effective_response_frame_size,
                    response_deadline,
                    ResponseFamily::Get,
                    &cancellation,
                )
                .await?;
            }
            Request::CompareAndSet {
                op,
                request_id,
                idempotency_epoch,
            } => {
                if let Some(error) = request_payload_error.take() {
                    let response_deadline =
                        bounded_response_deadline(request_deadline, idle_timeout)?;
                    write_post_auth_response_with_fallback_until(
                        writer,
                        Response::CompareAndSet(Err(error)),
                        Response::CompareAndSet(Err(StoreError::CasIdempotencyOutcomeUnavailable)),
                        effective_response_frame_size,
                        response_deadline,
                        ResponseFamily::CompareAndSet,
                        &cancellation,
                    )
                    .await?;
                    continue;
                }
                let expected_key = op.key.clone();
                let preflight = RecordExpiryPreflight::from_record(&op.new_record);
                let expiry_validation = match validate_stored_record_expiry_profile(&op.new_record)
                {
                    Ok(()) => {
                        run_store_backend_operation(
                            reader,
                            max_frame_size,
                            operation_deadline,
                            &cancellation,
                            ResponseFamily::CompareAndSet,
                            backend_slots.mutation.clone(),
                            BackendDeadlineOutcome::Preflight,
                            backend.preflight_record_expiry(std::slice::from_ref(&preflight)),
                        )
                        .await?
                    }
                    Err(error) => Err(error),
                };
                let res = match expiry_validation {
                    Ok(()) => {
                        run_store_backend_operation(
                            reader,
                            max_frame_size,
                            operation_deadline,
                            &cancellation,
                            ResponseFamily::CompareAndSet,
                            backend_slots.mutation.clone(),
                            BackendDeadlineOutcome::CompareAndSet,
                            async {
                                if let (Some(request_id), Some(idempotency_epoch)) =
                                    (request_id, idempotency_epoch)
                                {
                                    let request_id = uuid::Uuid::parse_str(&request_id)
                                        .map_err(|_| StoreError::CasIdempotencyConflict)?;
                                    let idempotency_epoch = uuid::Uuid::parse_str(&idempotency_epoch)
                                        .map_err(|_| StoreError::CasIdempotencyConflict)?;
                                    let operation_digest = cas_operation_digest(
                                        &binding,
                                        &client_replica_id,
                                        request_id,
                                        idempotency_epoch,
                                        &op,
                                    );
                                    match operation_digest {
                                        Ok(operation_digest) => match CasIdempotencyCache::begin(
                                            &cas_idempotency_cache,
                                            &client_replica_id,
                                            request_id,
                                            idempotency_epoch,
                                            operation_digest,
                                            Instant::now(),
                                        ) {
                                            CasIdempotencyAdmission::Execute(permit) => {
                                                let result = backend.compare_and_set(op).await;
                                                let result = if compare_and_set_result_matches_key(
                                                    &expected_key,
                                                    &result,
                                                ) {
                                                    result
                                                } else {
                                                    Err(backend_contract_error())
                                                };
                                                if cas_outcome_is_definitive(&result) {
                                                    permit.complete(result.clone());
                                                    result
                                                } else {
                                                    // A backend availability error can
                                                    // arrive after its commit boundary.
                                                    // Dropping the permit leaves a
                                                    // tombstone so this request ID can
                                                    // never replay a falsely definitive
                                                    // retryable outcome.
                                                    drop(permit);
                                                    Err(StoreError::CasIdempotencyOutcomeUnavailable)
                                                }
                                            }
                                            CasIdempotencyAdmission::Wait(outcome) => {
                                                wait_for_cas_outcome(outcome).await
                                            }
                                            CasIdempotencyAdmission::Replay(outcome) => outcome,
                                            CasIdempotencyAdmission::Reject(error) => Err(error),
                                        },
                                        Err(error) => Err(error),
                                    }
                                } else {
                                    Err(StoreError::CasIdempotencyOutcomeUnavailable)
                                }
                            },
                        )
                        .await?
                    }
                    Err(error) => Err(error),
                };
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                write_post_auth_response_with_fallback_until(
                    writer,
                    Response::CompareAndSet(res),
                    Response::CompareAndSet(Err(StoreError::CasIdempotencyOutcomeUnavailable)),
                    effective_response_frame_size,
                    response_deadline,
                    ResponseFamily::CompareAndSet,
                    &cancellation,
                )
                .await?;
            }
            Request::DeleteFenced { lease } => {
                let res = run_store_backend_operation(
                    reader,
                    max_frame_size,
                    operation_deadline,
                    &cancellation,
                    ResponseFamily::DeleteFenced,
                    backend_slots.mutation.clone(),
                    BackendDeadlineOutcome::Mutation,
                    backend.delete_fenced(&lease),
                )
                .await?;
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                write_post_auth_response_with_fallback_until(
                    writer,
                    Response::DeleteFenced(res),
                    Response::DeleteFenced(Err(StoreError::BackendOperationOutcomeUnavailable)),
                    effective_response_frame_size,
                    response_deadline,
                    ResponseFamily::DeleteFenced,
                    &cancellation,
                )
                .await?;
            }
            Request::RefreshTtl { lease, ttl } => {
                let res = match validate_session_ttl(ttl) {
                    Ok(()) => {
                        run_store_backend_operation(
                            reader,
                            max_frame_size,
                            operation_deadline,
                            &cancellation,
                            ResponseFamily::RefreshTtl,
                            backend_slots.mutation.clone(),
                            BackendDeadlineOutcome::Mutation,
                            backend.refresh_ttl(&lease, ttl),
                        )
                        .await?
                    }
                    Err(error) => Err(error),
                };
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                write_post_auth_response_with_fallback_until(
                    writer,
                    Response::RefreshTtl(res),
                    Response::RefreshTtl(Err(StoreError::BackendOperationOutcomeUnavailable)),
                    effective_response_frame_size,
                    response_deadline,
                    ResponseFamily::RefreshTtl,
                    &cancellation,
                )
                .await?;
            }
            Request::RecordExpiryPreflight { preflights } => {
                let res = run_store_backend_operation(
                    reader,
                    max_frame_size,
                    operation_deadline,
                    &cancellation,
                    ResponseFamily::RecordExpiryPreflight,
                    backend_slots.mutation.clone(),
                    BackendDeadlineOutcome::Preflight,
                    backend.preflight_record_expiry(&preflights),
                )
                .await?;
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                write_post_auth_response_with_fallback_until(
                    writer,
                    Response::RecordExpiryPreflight(res),
                    Response::RecordExpiryPreflight(Err(StoreError::BackendUnavailable(
                        "backend record-expiry preflight unavailable".into(),
                    ))),
                    effective_response_frame_size,
                    response_deadline,
                    ResponseFamily::RecordExpiryPreflight,
                    &cancellation,
                )
                .await?;
            }
            Request::Batch { ops } => {
                let expected_results = ops.len();
                let expected = bounded_session_op_expectations(&ops);
                let deadline_outcome = if ops
                    .iter()
                    .any(|op| !matches!(op, opc_session_store::SessionOp::Get { .. }))
                {
                    BackendDeadlineOutcome::Mutation
                } else {
                    BackendDeadlineOutcome::Read
                };
                let slots = match deadline_outcome {
                    BackendDeadlineOutcome::Mutation => backend_slots.mutation.clone(),
                    _ => backend_slots.read.clone(),
                };
                let res = if let Some(error) = request_payload_error.take() {
                    Err(error)
                } else if expected_results > MAX_SESSION_NET_BATCH_OPERATIONS {
                    Err(StoreError::ReplicationOperationLimitExceeded)
                } else {
                    let expiry_validation = match record_expiry_preflights(&ops) {
                        Ok(preflights) => {
                            run_store_backend_operation(
                                reader,
                                max_frame_size,
                                operation_deadline,
                                &cancellation,
                                ResponseFamily::Batch,
                                Arc::clone(&slots),
                                BackendDeadlineOutcome::Preflight,
                                backend.preflight_record_expiry(&preflights),
                            )
                            .await?
                        }
                        Err(error) => Err(error),
                    };
                    match expiry_validation {
                        Ok(()) => {
                            run_store_backend_operation(
                                reader,
                                max_frame_size,
                                operation_deadline,
                                &cancellation,
                                ResponseFamily::Batch,
                                slots,
                                deadline_outcome,
                                async {
                                    match backend.batch(ops).await {
                                        Ok(results)
                                            if expected.as_ref().is_ok_and(|expected| {
                                                session_op_results_match_expectations(
                                                    expected, &results,
                                                )
                                            }) =>
                                        {
                                            Ok(results)
                                        }
                                        Ok(results) => {
                                            drop(results);
                                            Err(backend_contract_error())
                                        }
                                        Err(error) => Err(error),
                                    }
                                },
                            )
                            .await?
                        }
                        Err(error) => Err(error),
                    }
                };
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                record_batch_ambiguous_outcome(&res);
                write_post_auth_response_with_fallback_until(
                    writer,
                    Response::Batch(res),
                    Response::Batch(Err(match deadline_outcome {
                        BackendDeadlineOutcome::Mutation => {
                            StoreError::BackendOperationOutcomeUnavailable
                        }
                        _ => store_response_limit_error(),
                    })),
                    effective_response_frame_size,
                    response_deadline,
                    ResponseFamily::Batch,
                    &cancellation,
                )
                .await?;
            }
            Request::ScanRestoreRecords {
                request: wire_request,
                max_response_frame_size,
            } => {
                let client_max = checked_frame_size(max_response_frame_size)?;
                let effective_max = client_max.min(effective_response_frame_size);
                if effective_max < MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE {
                    return Err(ProtocolError::FrameTooLarge(
                        MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE,
                    ));
                }

                let request = match RestoreScanRequest::try_from(wire_request) {
                    Ok(request) => request,
                    Err(error) => {
                        let response_deadline =
                            bounded_response_deadline(request_deadline, idle_timeout)?;
                        let response = bounded_restore_scan_error_response(
                            error,
                            effective_max,
                            response_deadline,
                            &cancellation,
                        )?;
                        write_post_auth_response_until(
                            writer,
                            &response,
                            effective_max,
                            response_deadline,
                            ResponseFamily::RestoreScan,
                            &cancellation,
                        )
                        .await?;
                        continue;
                    }
                };
                let mut backend_request = request.clone();
                let frame_limited_records =
                    (effective_max / MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE).max(1);
                backend_request.limit = backend_request.limit.min(frame_limited_records);
                let restore_deadline = tokio::time::Instant::now()
                    .checked_add(restore_scan_timeout)
                    .ok_or_else(|| {
                        backend_control_error(
                            std::io::ErrorKind::InvalidInput,
                            "restore scan timeout is not representable",
                        )
                    })?
                    .min(operation_deadline);
                let result = run_store_backend_operation(
                    reader,
                    max_frame_size,
                    restore_deadline,
                    &cancellation,
                    ResponseFamily::RestoreScan,
                    restore_scan_slots.clone(),
                    BackendDeadlineOutcome::RestoreScan,
                    backend.scan_restore_records(backend_request.clone()),
                )
                .await?;
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                let response = match result {
                    Ok(page) => {
                        check_response_write_control(response_deadline, &cancellation)?;
                        let validation = validate_dispatched_restore_page(&page, &backend_request);
                        check_response_write_control(response_deadline, &cancellation)?;
                        if let Err(error) = validation {
                            bounded_restore_scan_error_response(
                                error,
                                effective_max,
                                response_deadline,
                                &cancellation,
                            )?
                        } else {
                            let response = Response::ScanRestoreRecords(Ok(page));
                            match write_frame_until_server_cancellation(
                                writer,
                                &response,
                                effective_max,
                                response_deadline,
                                &cancellation,
                            )
                            .await
                            {
                                Ok(()) => {
                                    continue;
                                }
                                Err(ProtocolError::FrameTooLarge(_)) => {
                                    tracing::warn!(
                                        response_family = ResponseFamily::RestoreScan.code(),
                                        reason = "frame_too_large",
                                        "restore-scan response exceeded the negotiated frame limit"
                                    );
                                    let Response::ScanRestoreRecords(Ok(page)) = response else {
                                        unreachable!("constructed restore response changed family")
                                    };
                                    bounded_restore_scan_response(
                                        Ok(page),
                                        &backend_request,
                                        effective_max,
                                        response_deadline,
                                        &cancellation,
                                    )?
                                }
                                Err(other) => {
                                    record_response_write_failure(
                                        &other,
                                        ResponseFamily::RestoreScan,
                                    );
                                    return Err(other);
                                }
                            }
                        }
                    }
                    Err(error) => bounded_restore_scan_error_response(
                        error,
                        effective_max,
                        response_deadline,
                        &cancellation,
                    )?,
                };
                write_post_auth_response_until(
                    writer,
                    &response,
                    effective_max,
                    response_deadline,
                    ResponseFamily::RestoreScan,
                    &cancellation,
                )
                .await?;
            }
            Request::MaxReplicationSequence => {
                let res = run_store_backend_operation_if_capacity(
                    reader,
                    max_frame_size,
                    operation_deadline,
                    &cancellation,
                    ResponseFamily::MaxReplicationSequence,
                    backend_slots.read.clone(),
                    backend.max_replication_sequence(),
                )
                .await?;
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                write_post_auth_response_with_fallback_until(
                    writer,
                    Response::MaxReplicationSequence(res),
                    Response::MaxReplicationSequence(Err(store_response_limit_error())),
                    effective_response_frame_size,
                    response_deadline,
                    ResponseFamily::MaxReplicationSequence,
                    &cancellation,
                )
                .await?;
            }
            Request::GetReplicationLog { start, limit } => {
                let backend_result = match ReplicationLogRange::try_new(start, limit) {
                    Err(error) => Err(error),
                    Ok(range) if range.is_empty() => Ok(Vec::new()),
                    Ok(_) => {
                        run_store_backend_operation(
                            reader,
                            max_frame_size,
                            operation_deadline,
                            &cancellation,
                            ResponseFamily::ReplicationLog,
                            backend_slots.read.clone(),
                            BackendDeadlineOutcome::Read,
                            backend.get_replication_log(start, limit),
                        )
                        .await?
                    }
                };
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                check_response_write_control(response_deadline, &cancellation)?;
                let res = match backend_result {
                    Ok(entries) if entries.len() <= limit => {
                        validate_replication_log_page_owned(start, limit, entries)
                    }
                    Ok(entries) => {
                        drop(validate_replication_page_owned(entries));
                        Err(StoreError::BackendUnavailable(
                            "replication backend returned an oversized page".to_string(),
                        ))
                    }
                    Err(error) => Err(error),
                };
                check_response_write_control(response_deadline, &cancellation)?;
                match res {
                    Ok(entries) => {
                        let response = Response::GetReplicationLog(Ok(entries));
                        match write_frame_until_server_cancellation(
                            writer,
                            &response,
                            effective_response_frame_size,
                            response_deadline,
                            &cancellation,
                        )
                        .await
                        {
                            Ok(()) => {}
                            Err(ProtocolError::FrameTooLarge(_)) => {
                                let Response::GetReplicationLog(Ok(entries)) = response else {
                                    unreachable!("constructed replication response changed family")
                                };
                                let response = bounded_replication_log_response(
                                    Ok(entries),
                                    effective_response_frame_size,
                                    response_deadline,
                                    &cancellation,
                                )?;
                                write_post_auth_response_with_fallback_until(
                                    writer,
                                    response,
                                    Response::GetReplicationLog(Err(store_response_limit_error())),
                                    effective_response_frame_size,
                                    response_deadline,
                                    ResponseFamily::ReplicationLog,
                                    &cancellation,
                                )
                                .await?;
                            }
                            Err(other) => {
                                let Response::GetReplicationLog(Ok(entries)) = response else {
                                    unreachable!("constructed replication response changed family")
                                };
                                discard_replication_entries_iteratively(entries);
                                record_response_write_failure(
                                    &other,
                                    ResponseFamily::ReplicationLog,
                                );
                                return Err(other);
                            }
                        }
                    }
                    Err(error) => {
                        write_post_auth_response_with_fallback_until(
                            writer,
                            Response::GetReplicationLog(Err(error)),
                            Response::GetReplicationLog(Err(store_response_limit_error())),
                            effective_response_frame_size,
                            response_deadline,
                            ResponseFamily::ReplicationLog,
                            &cancellation,
                        )
                        .await?;
                    }
                }
            }
            Request::ReplicateEntry { entry } => {
                let res = match request_payload_error.take() {
                    Some(error) => Err(error),
                    None => match entry.into_validated() {
                        Ok(entry) => {
                            run_store_backend_operation(
                                reader,
                                max_frame_size,
                                operation_deadline,
                                &cancellation,
                                ResponseFamily::ReplicateEntry,
                                backend_slots.mutation.clone(),
                                BackendDeadlineOutcome::Mutation,
                                backend.replicate_entry(entry),
                            )
                            .await?
                        }
                        Err(error) => Err(error),
                    },
                };
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                write_post_auth_response_with_fallback_until(
                    writer,
                    Response::ReplicateEntry(res),
                    Response::ReplicateEntry(Err(StoreError::BackendOperationOutcomeUnavailable)),
                    effective_response_frame_size,
                    response_deadline,
                    ResponseFamily::ReplicateEntry,
                    &cancellation,
                )
                .await?;
            }
            Request::RebuildReplicationState { entries } => {
                let res = if let Some(error) = request_payload_error.take() {
                    Err(error)
                } else if entries.len() > MAX_SESSION_NET_REBUILD_ENTRIES {
                    Err(StoreError::ReplicationOperationLimitExceeded)
                } else {
                    match validate_replication_prefix_owned(entries) {
                        Ok(entries) => {
                            run_store_backend_operation(
                                reader,
                                max_frame_size,
                                operation_deadline,
                                &cancellation,
                                ResponseFamily::RebuildReplicationState,
                                backend_slots.mutation.clone(),
                                BackendDeadlineOutcome::Mutation,
                                backend.rebuild_replication_state(entries),
                            )
                            .await?
                        }
                        Err(error) => Err(error),
                    }
                };
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                write_post_auth_response_with_fallback_until(
                    writer,
                    Response::RebuildReplicationState(res),
                    Response::RebuildReplicationState(Err(
                        StoreError::BackendOperationOutcomeUnavailable,
                    )),
                    effective_response_frame_size,
                    response_deadline,
                    ResponseFamily::RebuildReplicationState,
                    &cancellation,
                )
                .await?;
            }
            Request::Watch { start_sequence } => {
                let cursor = ReplicationWatchCursor::new(start_sequence);
                match run_store_backend_operation(
                    reader,
                    max_frame_size,
                    operation_deadline,
                    &cancellation,
                    ResponseFamily::Watch,
                    backend_slots.watch_setup.clone(),
                    BackendDeadlineOutcome::Read,
                    backend.watch(cursor.first_sequence()),
                )
                .await?
                {
                    Ok(mut stream) => {
                        let mut expected_sequence = cursor.first_sequence();
                        let response_deadline =
                            bounded_response_deadline(request_deadline, idle_timeout)?;
                        write_post_auth_response_until(
                            writer,
                            &Response::WatchStream,
                            effective_response_frame_size,
                            response_deadline,
                            ResponseFamily::Watch,
                            &cancellation,
                        )
                        .await?;
                        while let Some(item) = next_watch_item_or_disconnect(
                            reader,
                            max_frame_size,
                            &cancellation,
                            &mut stream,
                        )
                        .await?
                        {
                            let deadline = response_write_deadline(idle_timeout)?;
                            check_response_write_control(deadline, &cancellation)?;
                            let (item, close_after) = match item {
                                Ok(entry) => match entry.into_validated() {
                                    Ok(entry) if entry.sequence == expected_sequence => {
                                        let terminal = expected_sequence == u64::MAX;
                                        if !terminal {
                                            expected_sequence = expected_sequence
                                                .checked_add(1)
                                                .ok_or(ProtocolError::InvalidWireValue)?;
                                        }
                                        (Ok(entry), terminal)
                                    }
                                    Ok(entry) => {
                                        discard_replication_entries_iteratively(vec![entry]);
                                        (Err(StoreError::InvalidReplicationSequence), true)
                                    }
                                    Err(error) => (Err(error), true),
                                },
                                Err(error) => (Err(error), true),
                            };
                            check_response_write_control(deadline, &cancellation)?;
                            let terminate = write_watch_response_until(
                                writer,
                                Response::WatchEntry(item),
                                effective_response_frame_size,
                                deadline,
                                &cancellation,
                            )
                            .await?;
                            if terminate || close_after {
                                return Ok(());
                            }
                        }
                    }
                    Err(e) => {
                        let deadline = response_write_deadline(idle_timeout)?;
                        let terminate = write_watch_response_until(
                            writer,
                            Response::WatchEntry(Err(e)),
                            effective_response_frame_size,
                            deadline,
                            &cancellation,
                        )
                        .await?;
                        if terminate {
                            return Ok(());
                        }
                    }
                }
            }
            Request::NextLeaseInfo => {
                let res = run_store_backend_operation(
                    reader,
                    max_frame_size,
                    operation_deadline,
                    &cancellation,
                    ResponseFamily::NextLeaseInfo,
                    backend_slots.read.clone(),
                    BackendDeadlineOutcome::Read,
                    backend.next_lease_info(),
                )
                .await?;
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                write_post_auth_response_with_fallback_until(
                    writer,
                    Response::NextLeaseInfo(res),
                    Response::NextLeaseInfo(Err(store_response_limit_error())),
                    effective_response_frame_size,
                    response_deadline,
                    ResponseFamily::NextLeaseInfo,
                    &cancellation,
                )
                .await?;
            }
            Request::AcquireLease { key, owner, ttl } => {
                let expected_owner = owner.clone();
                let res = match validate_session_ttl(ttl) {
                    Ok(()) => {
                        run_lease_backend_operation(
                            reader,
                            max_frame_size,
                            operation_deadline,
                            &cancellation,
                            ResponseFamily::AcquireLease,
                            backend_slots.lease.clone(),
                            async {
                                match backend.acquire(&key, owner, ttl).await {
                                    Ok(lease)
                                        if lease.key() == &key
                                            && lease.owner() == &expected_owner =>
                                    {
                                        Ok(lease)
                                    }
                                    Ok(_) => Err(backend_lease_contract_error()),
                                    Err(error) => Err(error),
                                }
                            },
                        )
                        .await?
                    }
                    Err(error) => Err(LeaseError::from(error)),
                };
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                write_post_auth_response_with_fallback_until(
                    writer,
                    Response::AcquireLease(res),
                    Response::AcquireLease(Err(LeaseError::OperationOutcomeUnavailable)),
                    effective_response_frame_size,
                    response_deadline,
                    ResponseFamily::AcquireLease,
                    &cancellation,
                )
                .await?;
            }
            Request::RenewLease { lease, ttl } => {
                let res = match validate_session_ttl(ttl) {
                    Ok(()) => {
                        run_lease_backend_operation(
                            reader,
                            max_frame_size,
                            operation_deadline,
                            &cancellation,
                            ResponseFamily::RenewLease,
                            backend_slots.lease.clone(),
                            async {
                                match backend.renew(&lease, ttl).await {
                                    Ok(renewed)
                                        if renewed.key() == lease.key()
                                            && renewed.owner() == lease.owner()
                                            && renewed.fence() == lease.fence()
                                            && renewed.credential_id() == lease.credential_id() =>
                                    {
                                        Ok(renewed)
                                    }
                                    Ok(_) => Err(backend_lease_contract_error()),
                                    Err(error) => Err(error),
                                }
                            },
                        )
                        .await?
                    }
                    Err(error) => Err(LeaseError::from(error)),
                };
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                write_post_auth_response_with_fallback_until(
                    writer,
                    Response::RenewLease(res),
                    Response::RenewLease(Err(LeaseError::OperationOutcomeUnavailable)),
                    effective_response_frame_size,
                    response_deadline,
                    ResponseFamily::RenewLease,
                    &cancellation,
                )
                .await?;
            }
            Request::ReleaseLease { lease } => {
                let res = run_lease_backend_operation(
                    reader,
                    max_frame_size,
                    operation_deadline,
                    &cancellation,
                    ResponseFamily::ReleaseLease,
                    backend_slots.lease.clone(),
                    backend.release(lease),
                )
                .await?;
                let response_deadline = bounded_response_deadline(request_deadline, idle_timeout)?;
                write_post_auth_response_with_fallback_until(
                    writer,
                    Response::ReleaseLease(res),
                    Response::ReleaseLease(Err(LeaseError::OperationOutcomeUnavailable)),
                    effective_response_frame_size,
                    response_deadline,
                    ResponseFamily::ReleaseLease,
                    &cancellation,
                )
                .await?;
            }
            Request::Hello { .. } => {
                return reject_hello(
                    writer,
                    HelloRejectReason::Malformed,
                    idle_timeout,
                    &cancellation,
                )
                .await;
            }
        }
    }

    Ok(())
}

fn is_configuration_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[allow(clippy::too_many_arguments)]
async fn write_bootstrap_ack<W>(
    writer: &mut W,
    server_replica_id: Option<String>,
    accepted_client_replica_id: Option<String>,
    cluster_id: Option<String>,
    configuration_id: Option<String>,
    configuration_epoch: Option<u64>,
    handshake_nonce: Option<uuid::Uuid>,
    cas_idempotency_epoch: Option<uuid::Uuid>,
    accepted_response_frame_size: Option<u32>,
    server_request_frame_size: Option<u32>,
    timeout: std::time::Duration,
    cancellation: &ServerCancellation,
) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let deadline = response_write_deadline(timeout)?;
    write_frame_until_server_cancellation(
        writer,
        &BootstrapResponse::HelloAck(Box::new(BootstrapHelloAck {
            contract_version: CONTRACT_VERSION,
            server_replica_id,
            accepted_client_replica_id,
            cluster_id,
            configuration_id,
            configuration_epoch,
            handshake_nonce,
            cas_idempotency_epoch,
            contract_profile: Some(CURRENT_CONTRACT_PROFILE),
            accepted_response_frame_size,
            server_request_frame_size,
        })),
        MAX_HANDSHAKE_FRAME_SIZE,
        deadline,
        cancellation,
    )
    .await
}

async fn reject_hello<W>(
    writer: &mut W,
    reason: HelloRejectReason,
    timeout: std::time::Duration,
    cancellation: &ServerCancellation,
) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let deadline = response_write_deadline(timeout)?;
    write_frame_until_server_cancellation(
        writer,
        &BootstrapResponse::HelloRejected { reason },
        MAX_HANDSHAKE_FRAME_SIZE,
        deadline,
        cancellation,
    )
    .await?;
    Err(ProtocolError::Authentication)
}

async fn retire_bootstrap<W>(
    writer: &mut W,
    timeout: std::time::Duration,
    cancellation: &ServerCancellation,
) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    tracing::debug!(
        reason = "rotation_bootstrap_retired",
        "retiring authenticated session connection before application admission"
    );
    let deadline = response_write_deadline(timeout)?;
    write_frame_until_server_cancellation(
        writer,
        &BootstrapResponse::ConnectionRetiring,
        MAX_HANDSHAKE_FRAME_SIZE,
        deadline,
        cancellation,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        ensure_frame_fits, ensure_restore_scan_success_frame_fits, read_frame, write_frame,
    };
    use bytes::Bytes;
    use opc_session_store::{
        EncryptedSessionPayload, FenceToken, Generation, OwnerId, SessionKey, SessionKeyType,
        StateClass, StateType, StoredSessionRecord,
    };
    use opc_types::{NetworkFunctionKind, TenantId};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncWrite;

    static TEST_NOT_CANCELLED: AtomicBool = AtomicBool::new(false);
    static TEST_SERVER_NOT_CANCELLED: std::sync::LazyLock<ServerCancellation> =
        std::sync::LazyLock::new(ServerCancellation::default);

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    struct PartialAcknowledgementWriter {
        bytes: Arc<StdMutex<Vec<u8>>>,
        first_chunk_written: bool,
        wrote_first_chunk: Arc<Notify>,
    }

    impl AsyncWrite for PartialAcknowledgementWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
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
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Pending
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    fn test_dispatch_config(reauthentication: SessionReauthenticationControl) -> DispatchConfig {
        DispatchConfig {
            binding: crate::identity::insecure_test_server_binding(),
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            idle_timeout: Duration::from_secs(1),
            backend_operation_timeout: Duration::from_secs(1),
            backend_slots: BackendOperationSlots::new(1),
            restore_scan_timeout: Duration::from_secs(1),
            restore_scan_slots: Arc::new(Semaphore::new(1)),
            cancellation: Arc::new(ServerCancellation::default()),
            lifecycle_policy: ConnectionLifecyclePolicy::try_new(
                Duration::from_secs(10),
                Duration::from_secs(1),
                Duration::from_millis(1),
                Duration::from_millis(5),
                Duration::ZERO,
            )
            .expect("test lifecycle policy"),
            reauthentication,
        }
    }

    async fn valid_bootstrap_hello_bytes() -> Vec<u8> {
        let binding = crate::identity::insecure_test_client_binding();
        let mut bytes = Vec::new();
        write_frame(
            &mut bytes,
            &BootstrapRequest::Hello(BootstrapHello {
                contract_version: CONTRACT_VERSION,
                node_id: binding.local_replica_id().as_str().to_owned(),
                expected_server_replica_id: Some(binding.remote_replica_id().as_str().to_owned()),
                cluster_id: Some(binding.cluster_id().as_str().to_owned()),
                configuration_id: Some(binding.configuration_id().to_hex()),
                configuration_epoch: Some(binding.configuration_epoch().get()),
                handshake_nonce: Some(uuid::Uuid::nil()),
                contract_profile: Some(CURRENT_CONTRACT_PROFILE),
                requested_response_frame_size: Some(DEFAULT_MAX_FRAME_SIZE as u32),
            }),
        )
        .await
        .expect("encode valid bootstrap Hello");
        bytes
    }

    #[tokio::test]
    async fn pre_hello_generation_retirement_emits_one_explicit_no_dispatch_control() {
        let reauthentication = SessionReauthenticationControl::new();
        let pending = PendingServerLifecycle::insecure(reauthentication.generation());
        reauthentication
            .request_reauthentication()
            .expect("advance test generation");
        let config = test_dispatch_config(reauthentication);
        let mut reader = tokio::io::empty();
        let mut writer = Vec::new();

        dispatch(
            Arc::new(opc_session_store::fake::FakeSessionBackend::new()),
            Arc::new(StdMutex::new(CasIdempotencyCache::default())),
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            pending,
            config,
        )
        .await
        .expect("pre-Hello retirement is an expected control exchange");

        let mut encoded = std::io::Cursor::new(writer);
        assert!(matches!(
            read_frame::<_, BootstrapResponse>(&mut encoded, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read retirement control"),
            BootstrapResponse::ConnectionRetiring
        ));
        assert_eq!(
            usize::try_from(encoded.position()).expect("cursor position"),
            encoded.get_ref().len(),
            "exactly one control frame must be emitted"
        );
    }

    #[tokio::test]
    async fn expiry_crossing_at_final_zero_ack_boundary_emits_only_retirement_control() {
        let reauthentication = SessionReauthenticationControl::new();
        let mut pending = PendingServerLifecycle::insecure(reauthentication.generation());
        pending.expire_at_final_ack_boundary = true;
        let config = test_dispatch_config(reauthentication);
        let mut input = valid_bootstrap_hello_bytes().await;
        let hello_bytes = input.len();
        write_frame(&mut input, &Request::Capabilities)
            .await
            .expect("append application request behind valid Hello");
        let mut reader = std::io::Cursor::new(input);
        let mut writer = Vec::new();

        dispatch(
            Arc::new(opc_session_store::fake::FakeSessionBackend::new()),
            Arc::new(StdMutex::new(CasIdempotencyCache::default())),
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            pending,
            config,
        )
        .await
        .expect("final-boundary expiry is an expected control exchange");

        assert_eq!(
            usize::try_from(reader.position()).expect("reader position"),
            hello_bytes,
            "no application request bytes may be read or dispatched"
        );
        let mut encoded = std::io::Cursor::new(writer);
        assert!(matches!(
            read_frame::<_, BootstrapResponse>(&mut encoded, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read final-boundary retirement control"),
            BootstrapResponse::ConnectionRetiring
        ));
        assert_eq!(
            usize::try_from(encoded.position()).expect("writer position"),
            encoded.get_ref().len(),
            "one complete retirement control and zero Ack bytes must be emitted"
        );
    }

    #[test]
    fn post_hello_pre_admit_material_change_is_recorded_once_as_material_retirement() {
        let material = crate::test_support::RotatableServerMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/server",
        );
        let tls_config = material.config();
        let handshake = tls_config
            .begin_handshake()
            .expect("capture pre-rotation server material");
        let established_at = tokio::time::Instant::now();
        let pending = PendingServerLifecycle {
            handshake: Some(handshake),
            tls_config: Some(tls_config),
            local_certificate_expiry: None,
            peer_certificate_expiry: None,
            established_at,
            generation: 0,
            expire_at_final_ack_boundary: false,
        };
        let policy = test_dispatch_config(SessionReauthenticationControl::new()).lifecycle_policy;
        let bootstrap_lifecycle = pending
            .provisional_lifecycle(policy)
            .expect("provisional post-TLS lifecycle");

        // `PendingServerLifecycle::admit` is the exact gate called only after
        // Hello identity/scope validation and before any Ack write or backend
        // dispatch. Advance the snapshot at that narrow boundary.
        material.rotate();
        let reason = match pending.admit(policy, 0) {
            Err(PendingServerAdmissionError::Retired(reason)) => reason,
            Err(PendingServerAdmissionError::Protocol(error)) => {
                panic!("material race was misclassified as protocol: {error}")
            }
            Ok(_) => panic!("stale handshake snapshot must not be admitted"),
        };
        assert_eq!(reason, RetirementReason::MaterialEpoch);
        bootstrap_lifecycle.record_forced_retirement(reason);
        bootstrap_lifecycle.record_forced_retirement(reason);
        assert_eq!(
            bootstrap_lifecycle.recorded_retirement_count(),
            1,
            "the admission race must select and publish one lifecycle retirement outcome"
        );
    }

    #[tokio::test]
    async fn rotation_after_ack_bytes_start_closes_without_appending_retirement_control() {
        let reauthentication = SessionReauthenticationControl::new();
        let pending = PendingServerLifecycle::insecure(reauthentication.generation());
        let config = test_dispatch_config(reauthentication.clone());
        let mut reader = std::io::Cursor::new(valid_bootstrap_hello_bytes().await);
        let bytes = Arc::new(StdMutex::new(Vec::new()));
        let wrote_first_chunk = Arc::new(Notify::new());
        let first_chunk = wrote_first_chunk.notified();
        tokio::pin!(first_chunk);
        let mut writer = PartialAcknowledgementWriter {
            bytes: Arc::clone(&bytes),
            first_chunk_written: false,
            wrote_first_chunk: Arc::clone(&wrote_first_chunk),
        };
        let dispatch = dispatch(
            Arc::new(opc_session_store::fake::FakeSessionBackend::new()),
            Arc::new(StdMutex::new(CasIdempotencyCache::default())),
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            pending,
            config,
        );
        tokio::pin!(dispatch);
        tokio::select! {
            _ = &mut first_chunk => {}
            result = &mut dispatch => panic!("dispatch ended before partial Ack: {result:?}"),
        }
        reauthentication
            .request_reauthentication()
            .expect("retire after Ack transmission starts");
        tokio::time::timeout(Duration::from_secs(1), &mut dispatch)
            .await
            .expect("partial-Ack retirement must close promptly")
            .expect("partial-Ack retirement is a conservative close");

        let written = bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            written.len(),
            2,
            "only the partial Ack prefix may be written"
        );
        assert!(!String::from_utf8_lossy(&written).contains("ConnectionRetiring"));
    }

    #[tokio::test]
    async fn backend_queue_timeout_never_polls_work_and_execution_timeout_is_ambiguous() {
        let slots = Arc::new(Semaphore::new(1));
        let held = slots
            .clone()
            .acquire_owned()
            .await
            .expect("hold the only slot");
        let (peer, mut reader) = tokio::io::duplex(64);
        let cancellation = ServerCancellation::default();
        let polled = Arc::new(AtomicBool::new(false));
        let operation_polled = Arc::clone(&polled);
        let queued = run_store_backend_operation(
            &mut reader,
            MIN_NEGOTIATED_FRAME_SIZE,
            tokio::time::Instant::now() + Duration::from_millis(20),
            &cancellation,
            ResponseFamily::DeleteFenced,
            Arc::clone(&slots),
            BackendDeadlineOutcome::Mutation,
            async move {
                operation_polled.store(true, Ordering::Release);
                Ok::<(), StoreError>(())
            },
        )
        .await
        .expect("queue timeout is a typed backend response");
        assert!(matches!(queued, Err(StoreError::BackendUnavailable(_))));
        assert!(!polled.load(Ordering::Acquire));
        assert_eq!(slots.available_permits(), 0);
        drop(held);
        assert_eq!(slots.available_permits(), 1);
        drop(peer);

        let (peer, mut reader) = tokio::io::duplex(64);
        let dropped = Arc::new(AtomicBool::new(false));
        let drop_signal = Arc::clone(&dropped);
        let executed = run_store_backend_operation(
            &mut reader,
            MIN_NEGOTIATED_FRAME_SIZE,
            tokio::time::Instant::now() + Duration::from_millis(20),
            &cancellation,
            ResponseFamily::DeleteFenced,
            Arc::clone(&slots),
            BackendDeadlineOutcome::Mutation,
            async move {
                let _drop_signal = DropSignal(drop_signal);
                std::future::pending::<()>().await;
                Ok::<(), StoreError>(())
            },
        )
        .await
        .expect("execution timeout is a typed backend response");
        assert_eq!(
            executed,
            Err(StoreError::BackendOperationOutcomeUnavailable)
        );
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(slots.available_permits(), 1);
        drop(peer);
    }

    #[tokio::test]
    async fn expiry_preflight_queue_execute_and_backend_ambiguity_remain_retry_safe() {
        let slots = Arc::new(Semaphore::new(1));
        let held = slots
            .clone()
            .acquire_owned()
            .await
            .expect("hold preflight slot");
        let cancellation = ServerCancellation::default();
        let (peer, mut reader) = tokio::io::duplex(64);
        let polled = Arc::new(AtomicBool::new(false));
        let operation_polled = Arc::clone(&polled);
        let queued = run_store_backend_operation(
            &mut reader,
            MIN_NEGOTIATED_FRAME_SIZE,
            tokio::time::Instant::now() + Duration::from_millis(20),
            &cancellation,
            ResponseFamily::RecordExpiryPreflight,
            Arc::clone(&slots),
            BackendDeadlineOutcome::Preflight,
            async move {
                operation_polled.store(true, Ordering::Release);
                Ok::<(), StoreError>(())
            },
        )
        .await
        .expect("preflight queue timeout response");
        assert!(matches!(queued, Err(StoreError::BackendUnavailable(_))));
        assert!(!polled.load(Ordering::Acquire));
        drop(held);
        drop(peer);

        let (peer, mut reader) = tokio::io::duplex(64);
        let executed = run_store_backend_operation(
            &mut reader,
            MIN_NEGOTIATED_FRAME_SIZE,
            tokio::time::Instant::now() + Duration::from_millis(20),
            &cancellation,
            ResponseFamily::RecordExpiryPreflight,
            Arc::clone(&slots),
            BackendDeadlineOutcome::Preflight,
            std::future::pending::<Result<(), StoreError>>(),
        )
        .await
        .expect("preflight execution timeout response");
        assert!(matches!(executed, Err(StoreError::BackendUnavailable(_))));
        drop(peer);

        for reported in [
            StoreError::BackendUnavailable("backend detail".into()),
            StoreError::BackendOperationOutcomeUnavailable,
            StoreError::CasIdempotencyOutcomeUnavailable,
        ] {
            let (peer, mut reader) = tokio::io::duplex(64);
            let normalized = run_store_backend_operation(
                &mut reader,
                MIN_NEGOTIATED_FRAME_SIZE,
                tokio::time::Instant::now() + Duration::from_secs(1),
                &cancellation,
                ResponseFamily::RecordExpiryPreflight,
                Arc::clone(&slots),
                BackendDeadlineOutcome::Preflight,
                async { Err::<(), StoreError>(reported) },
            )
            .await
            .expect("preflight backend response");
            assert!(matches!(normalized, Err(StoreError::BackendUnavailable(_))));
            drop(peer);
        }
    }

    struct SlowCooperativeFrame {
        started: Arc<AtomicBool>,
    }

    impl serde::Serialize for SlowCooperativeFrame {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut sequence = serializer.serialize_seq(Some(1_001))?;
            serde::ser::SerializeSeq::serialize_element(&mut sequence, &0_u8)?;
            self.started.store(true, Ordering::Release);
            for value in 1_u16..=1_000 {
                let until = std::time::Instant::now() + std::time::Duration::from_millis(2);
                while std::time::Instant::now() < until {
                    std::hint::spin_loop();
                }
                serde::ser::SerializeSeq::serialize_element(&mut sequence, &value)?;
            }
            serde::ser::SerializeSeq::end(sequence)
        }
    }

    fn restore_record(stable_id: &'static [u8], payload_len: usize) -> StoredSessionRecord {
        StoredSessionRecord {
            key: SessionKey {
                tenant: TenantId::from_static("tenant-a"),
                nf_kind: NetworkFunctionKind::from_static("smf"),
                key_type: SessionKeyType::PduSession,
                stable_id: Bytes::from_static(stable_id)
                    .try_into()
                    .expect("valid stable ID"),
            },
            generation: Generation::new(1),
            owner: OwnerId::new("owner-a").expect("owner"),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("pdu-session"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(vec![7; payload_len]),
        }
    }

    fn large_bounded_durable_cursor() -> RestoreScanCursor {
        // The model-wide 64-byte stable-ID bound makes 517 bytes the maximum
        // durable token. A 512-byte syntactic token exercises the high end
        // without duplicating the store's private encoding constants.
        let mut token = vec![0_u8; 512];
        token[0] = 1;
        // Clear cumulative examined-row position, big endian.
        token[8] = 1;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = Vec::with_capacity(token.len() * 2);
        for byte in token {
            encoded.push(HEX[usize::from(byte >> 4)]);
            encoded.push(HEX[usize::from(byte & 0x0f)]);
        }
        let encoded = String::from_utf8(encoded).expect("lowercase cursor hex");
        serde_json::from_value(serde_json::Value::String(encoded))
            .expect("strictly bounded durable cursor shape")
    }

    fn replication_log_entry(sequence: u64, payload_len: usize) -> ReplicationEntry {
        let record = restore_record(b"log-entry", payload_len);
        let key = record.key.clone();
        let timestamp = opc_types::Timestamp::now_utc();
        ReplicationEntry {
            sequence,
            tx_id: format!("log-{sequence}")
                .try_into()
                .expect("valid transaction ID"),
            op: ReplicationOp::CompareAndSet {
                key,
                expected_generation: None,
                credential_id: sequence,
                guard_expires_at: timestamp,
                new_record: record,
            },
            timestamp,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abort_and_wait_cooperatively_interrupts_synchronous_frame_encoding() {
        let cancellation = Arc::new(ServerCancellation::default());
        let started = Arc::new(AtomicBool::new(false));
        let observed_interruption = Arc::new(AtomicBool::new(false));
        let task_cancellation = cancellation.clone();
        let task_started = started.clone();
        let task_observed = observed_interruption.clone();
        let connection = tokio::spawn(async move {
            let mut writer = tokio::io::sink();
            let deadline = tokio::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(5))
                .expect("test deadline");
            let result = write_frame_bounded_until_cancellable(
                &mut writer,
                &SlowCooperativeFrame {
                    started: task_started,
                },
                MAX_HANDSHAKE_FRAME_SIZE,
                deadline,
                &task_cancellation,
            )
            .await;
            if matches!(
                result,
                Err(ProtocolError::Io(ref error))
                    if error.kind() == std::io::ErrorKind::Interrupted
            ) {
                task_observed.store(true, Ordering::Release);
            }
        });

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("test encoder must start");

        let accept_handle = tokio::spawn(std::future::pending());
        let (shutdown_tx, _shutdown_rx) = tokio::sync::mpsc::channel(1);
        let handle = ServerHandle {
            accept_handle,
            _shutdown_tx: shutdown_tx,
            connection_tasks: Arc::new(std::sync::Mutex::new(ConnectionTaskRegistry {
                stopping: false,
                handles: vec![connection],
            })),
            cancellation: cancellation.clone(),
        };

        tokio::time::timeout(std::time::Duration::from_secs(1), handle.abort_and_wait())
            .await
            .expect("cooperative cancellation must bound synchronous encoder shutdown");
        assert!(cancellation.load(Ordering::Acquire));
        assert!(
            observed_interruption.load(Ordering::Acquire),
            "the encoding sink must observe the server cancellation signal"
        );
    }

    #[test]
    fn cas_idempotency_cache_replays_exact_outcome_and_rejects_reuse() {
        let cache = Arc::new(StdMutex::new(CasIdempotencyCache::default()));
        let peer = ReplicaId::new("replica-a").expect("peer");
        let first = uuid::Uuid::from_u128(u128::MAX);
        let epoch = cache.lock().expect("cache").epoch();
        let digest = [7; 32];

        let CasIdempotencyAdmission::Execute(permit) =
            CasIdempotencyCache::begin(&cache, &peer, first, epoch, digest, Instant::now())
        else {
            panic!("first request must execute");
        };
        permit.complete(Ok(CompareAndSetResult::Success));

        assert!(matches!(
            CasIdempotencyCache::begin(&cache, &peer, first, epoch, digest, Instant::now()),
            CasIdempotencyAdmission::Replay(Ok(CompareAndSetResult::Success))
        ));
        assert!(matches!(
            CasIdempotencyCache::begin(&cache, &peer, first, epoch, [8; 32], Instant::now()),
            CasIdempotencyAdmission::Reject(StoreError::CasIdempotencyConflict)
        ));

        let other_peer = ReplicaId::new("replica-b").expect("other peer");
        assert!(matches!(
            CasIdempotencyCache::begin(&cache, &other_peer, first, epoch, digest, Instant::now()),
            CasIdempotencyAdmission::Reject(StoreError::CasIdempotencyConflict)
        ));
    }

    #[test]
    fn cas_idempotency_cache_tombstones_backend_ambiguous_outcomes() {
        let cache = Arc::new(StdMutex::new(CasIdempotencyCache::default()));
        let peer = ReplicaId::new("replica-a").expect("peer");
        let request_id = uuid::Uuid::from_u128(73);
        let epoch = cache.lock().expect("cache").epoch();
        let digest = [3; 32];
        let CasIdempotencyAdmission::Execute(permit) =
            CasIdempotencyCache::begin(&cache, &peer, request_id, epoch, digest, Instant::now())
        else {
            panic!("first request must execute");
        };

        let unavailable = Err(StoreError::BackendUnavailable(
            "backend lost its commit response".into(),
        ));
        assert!(!cas_outcome_is_definitive(&unavailable));
        drop(permit);

        assert!(matches!(
            CasIdempotencyCache::begin(&cache, &peer, request_id, epoch, digest, Instant::now()),
            CasIdempotencyAdmission::Reject(StoreError::CasIdempotencyOutcomeUnavailable)
        ));
    }

    #[tokio::test]
    async fn backend_reported_ambiguity_is_counted_for_store_and_lease_families() {
        let before = METRICS
            .session_net_backend_ambiguous_outcomes
            .load(Ordering::Relaxed);
        let slots = Arc::new(Semaphore::new(1));
        let cancellation = ServerCancellation::default();

        let (peer, mut reader) = tokio::io::duplex(64);
        let result = run_store_backend_operation(
            &mut reader,
            MIN_NEGOTIATED_FRAME_SIZE,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &cancellation,
            ResponseFamily::DeleteFenced,
            Arc::clone(&slots),
            BackendDeadlineOutcome::Mutation,
            async { Err::<(), _>(StoreError::BackendUnavailable("lost commit result".into())) },
        )
        .await
        .expect("store result");
        assert_eq!(result, Err(StoreError::BackendOperationOutcomeUnavailable));
        drop(peer);

        let (peer, mut reader) = tokio::io::duplex(64);
        let result = run_lease_backend_operation(
            &mut reader,
            MIN_NEGOTIATED_FRAME_SIZE,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &cancellation,
            ResponseFamily::ReleaseLease,
            slots,
            async { Err::<(), _>(LeaseError::Backend("lost lease result".into())) },
        )
        .await
        .expect("lease result");
        assert_eq!(result, Err(LeaseError::OperationOutcomeUnavailable));
        drop(peer);

        assert!(
            METRICS
                .session_net_backend_ambiguous_outcomes
                .load(Ordering::Relaxed)
                >= before + 2
        );
    }

    #[test]
    fn batch_slot_ambiguity_counts_once_per_request() {
        let ambiguous = Ok(vec![
            SessionOpResult::CompareAndSet(Err(StoreError::CasIdempotencyOutcomeUnavailable)),
            SessionOpResult::DeleteFenced(Err(StoreError::BackendOperationOutcomeUnavailable)),
        ]);
        assert_eq!(batch_ambiguous_outcome_count(&ambiguous), 1);
        assert_eq!(
            batch_ambiguous_outcome_count(&Ok(vec![SessionOpResult::Get(Ok(None))])),
            0
        );
        assert_eq!(
            batch_ambiguous_outcome_count(&Err(StoreError::BackendOperationOutcomeUnavailable)),
            0,
            "outer ambiguity is counted by the generic operation wrapper"
        );

        let primary = Response::Batch(ambiguous);
        let fallback = Response::Batch(Err(StoreError::BackendOperationOutcomeUnavailable));
        assert_eq!(
            u64::from(response_is_ambiguous_outcome(&primary))
                + ambiguity_fallback_count(&primary, &fallback),
            1,
            "an oversized nested ambiguity must not be counted again by its fallback"
        );
    }

    #[tokio::test]
    async fn concurrent_cas_duplicates_share_one_exact_conflict() {
        let cache = Arc::new(StdMutex::new(CasIdempotencyCache::default()));
        let peer = ReplicaId::new("replica-a").expect("peer");
        let request_id = uuid::Uuid::from_u128(41);
        let epoch = cache.lock().expect("cache").epoch();
        let digest = [9; 32];
        let CasIdempotencyAdmission::Execute(permit) =
            CasIdempotencyCache::begin(&cache, &peer, request_id, epoch, digest, Instant::now())
        else {
            panic!("first duplicate must execute");
        };
        let CasIdempotencyAdmission::Wait(waiter) =
            CasIdempotencyCache::begin(&cache, &peer, request_id, epoch, digest, Instant::now())
        else {
            panic!("concurrent duplicate must wait");
        };

        let conflict = Ok(CompareAndSetResult::Conflict { current: None });
        permit.complete(conflict.clone());
        assert_eq!(wait_for_cas_outcome(waiter).await, conflict);
        assert!(matches!(
            CasIdempotencyCache::begin(&cache, &peer, request_id, epoch, digest, Instant::now()),
            CasIdempotencyAdmission::Replay(Ok(CompareAndSetResult::Conflict { current: None }))
        ));
    }

    #[test]
    fn cancelled_cas_is_retained_as_ambiguous() {
        let cache = Arc::new(StdMutex::new(CasIdempotencyCache::default()));
        let peer = ReplicaId::new("replica-a").expect("peer");
        let request_id = uuid::Uuid::from_u128(42);
        let epoch = cache.lock().expect("cache").epoch();
        let digest = [10; 32];
        let CasIdempotencyAdmission::Execute(permit) =
            CasIdempotencyCache::begin(&cache, &peer, request_id, epoch, digest, Instant::now())
        else {
            panic!("first request must execute");
        };
        drop(permit);

        assert!(matches!(
            CasIdempotencyCache::begin(&cache, &peer, request_id, epoch, digest, Instant::now()),
            CasIdempotencyAdmission::Reject(StoreError::CasIdempotencyOutcomeUnavailable)
        ));
    }

    #[test]
    fn restart_and_retention_rotate_the_cas_epoch_before_reuse() {
        let peer = ReplicaId::new("replica-a").expect("peer");
        let request_id = uuid::Uuid::from_u128(43);
        let digest = [11; 32];
        let old_cache = Arc::new(StdMutex::new(CasIdempotencyCache::default()));
        let old_epoch = old_cache.lock().expect("cache").epoch();
        let CasIdempotencyAdmission::Execute(permit) = CasIdempotencyCache::begin(
            &old_cache,
            &peer,
            request_id,
            old_epoch,
            digest,
            Instant::now(),
        ) else {
            panic!("first request must execute");
        };
        permit.complete(Ok(CompareAndSetResult::Success));

        let restarted = Arc::new(StdMutex::new(CasIdempotencyCache::default()));
        let restarted_epoch = restarted.lock().expect("cache").epoch();
        assert_ne!(old_epoch, restarted_epoch);
        assert!(matches!(
            CasIdempotencyCache::begin(
                &restarted,
                &peer,
                request_id,
                old_epoch,
                digest,
                Instant::now()
            ),
            CasIdempotencyAdmission::Reject(StoreError::CasIdempotencyOutcomeUnavailable)
        ));

        let now = Instant::now();
        {
            let mut cache = old_cache.lock().expect("cache");
            let entry = cache.entries.get_mut(&request_id).expect("entry");
            entry.state = CasIdempotencyState::Complete {
                outcome: Box::new(Ok(CompareAndSetResult::Success)),
                completed_at: now - CAS_IDEMPOTENCY_RESULT_RETENTION,
            };
            cache.cleanup(now);
            assert!(matches!(
                cache.entries.get(&request_id).map(|entry| &entry.state),
                Some(CasIdempotencyState::Ambiguous { .. })
            ));
            let entry = cache.entries.get_mut(&request_id).expect("tombstone");
            entry.state = CasIdempotencyState::Ambiguous {
                since: now - CAS_IDEMPOTENCY_TOMBSTONE_RETENTION,
            };
            cache.cleanup(now);
            assert_ne!(cache.epoch(), old_epoch);
            assert!(cache.entries.is_empty());
        }
    }

    #[test]
    fn one_peer_cannot_consume_another_peers_cas_share() {
        let cache = Arc::new(StdMutex::new(CasIdempotencyCache::default()));
        let noisy_peer = ReplicaId::new("replica-noisy").expect("noisy peer");
        let other_peer = ReplicaId::new("replica-other").expect("other peer");
        let epoch = cache.lock().expect("cache").epoch();
        for index in 0..CAS_IDEMPOTENCY_CACHE_PER_PEER_CAPACITY {
            let request_id = uuid::Uuid::from_u128((index + 1) as u128);
            let CasIdempotencyAdmission::Execute(permit) = CasIdempotencyCache::begin(
                &cache,
                &noisy_peer,
                request_id,
                epoch,
                [12; 32],
                Instant::now(),
            ) else {
                panic!("request inside per-peer share must execute");
            };
            permit.complete(Ok(CompareAndSetResult::Success));
        }
        assert!(matches!(
            CasIdempotencyCache::begin(
                &cache,
                &noisy_peer,
                uuid::Uuid::from_u128(u128::MAX),
                epoch,
                [12; 32],
                Instant::now()
            ),
            CasIdempotencyAdmission::Reject(StoreError::CasIdempotencyOutcomeUnavailable)
        ));
        assert!(matches!(
            CasIdempotencyCache::begin(
                &cache,
                &other_peer,
                uuid::Uuid::from_u128(u128::MAX - 1),
                epoch,
                [13; 32],
                Instant::now()
            ),
            CasIdempotencyAdmission::Execute(_)
        ));
    }

    #[test]
    fn bounded_restore_scan_response_rejects_a_page_that_does_not_fit() {
        let request = RestoreScanRequest {
            scope: Default::default(),
            cursor: Some(RestoreScanCursor::from_offset(7)),
            limit: 2,
        };
        let first = restore_record(b"a", 64);
        let second = restore_record(b"b", 64);
        let full_page = RestoreScanPage::new(vec![first.clone(), second], 0, None);
        let full_size = serde_json::to_vec(&Response::ScanRestoreRecords(Ok(full_page.clone())))
            .expect("encode full page")
            .len();
        let budget = full_size.checked_sub(1).expect("response is non-empty");

        let response = bounded_restore_scan_response(
            Ok(full_page),
            &request,
            budget,
            response_write_deadline(std::time::Duration::from_secs(1)).expect("deadline"),
            &TEST_NOT_CANCELLED,
        )
        .expect("bounded response");
        assert!(matches!(
            response,
            Response::ScanRestoreRecords(Err(StoreError::RestoreScanResponseTooLarge {
                max_bytes
            })) if max_bytes == budget
        ));
    }

    #[test]
    fn bounded_opaque_cursor_fits_the_minimum_negotiated_frame() {
        let request = RestoreScanRequest::all(1);
        let mut page = RestoreScanPage::new(Vec::new(), 1, Some(large_bounded_durable_cursor()));
        page.cursor_profile = RestoreScanCursorProfile::DurableOpaqueV1;
        page.validate_for_request(&request)
            .expect("syntactic test cursor proves exact page progress");
        assert!(ensure_restore_scan_success_frame_fits(
            &page,
            crate::protocol::MIN_NEGOTIATED_FRAME_SIZE,
        )
        .is_ok());

        let response = bounded_restore_scan_response(
            Ok(page),
            &request,
            crate::protocol::MIN_NEGOTIATED_FRAME_SIZE,
            response_write_deadline(std::time::Duration::from_secs(1)).expect("deadline"),
            &TEST_NOT_CANCELLED,
        )
        .expect("bounded negotiated-fit response");
        assert!(matches!(response, Response::ScanRestoreRecords(Ok(_))));
    }

    #[test]
    fn restore_backend_page_is_checked_against_the_narrowed_dispatch_contract() {
        let mut oversized = RestoreScanPage::new(
            vec![restore_record(b"a", 16), restore_record(b"b", 16)],
            0,
            None,
        );
        oversized.cursor_profile = RestoreScanCursorProfile::DurableOpaqueV1;
        let narrowed = RestoreScanRequest::all(1);
        assert!(matches!(
            validate_dispatched_restore_page(&oversized, &narrowed),
            Err(StoreError::InvalidRestoreScanResponse(_))
        ));

        let legacy = RestoreScanPage::new(vec![restore_record(b"a", 16)], 0, None);
        assert_eq!(
            validate_dispatched_restore_page(&legacy, &narrowed),
            Err(StoreError::CapabilityNotSupported(
                "legacy_remote_restore_scan".to_string()
            ))
        );
    }

    #[test]
    fn single_oversized_restore_record_returns_a_bounded_typed_error() {
        let request = RestoreScanRequest::all(1);
        let page = RestoreScanPage::new(vec![restore_record(b"large", 32 * 1024)], 0, None);

        let response = bounded_restore_scan_response(
            Ok(page),
            &request,
            MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE,
            response_write_deadline(std::time::Duration::from_secs(1)).expect("deadline"),
            &TEST_NOT_CANCELLED,
        )
        .expect("bounded response");
        assert!(matches!(
            response,
            Response::ScanRestoreRecords(Err(StoreError::RestoreScanResponseTooLarge {
                max_bytes: MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE
            }))
        ));
    }

    #[test]
    fn backend_error_text_is_replaced_with_a_fixed_message() {
        let response = bounded_restore_scan_response(
            Err(StoreError::BackendUnavailable(
                "secret database path and schema details".to_string(),
            )),
            &RestoreScanRequest::all(1),
            MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE,
            response_write_deadline(std::time::Duration::from_secs(1)).expect("deadline"),
            &TEST_NOT_CANCELLED,
        )
        .expect("bounded error response");

        assert!(matches!(
            response,
            Response::ScanRestoreRecords(Err(StoreError::BackendUnavailable(message)))
                if message == "restore scan backend unavailable"
        ));
    }

    #[test]
    fn every_fixed_fallback_fits_the_negotiated_minimum() {
        let responses = vec![
            Response::Capabilities(opc_session_store::BackendCapabilities::all_enabled()),
            Response::Get(Err(store_response_limit_error())),
            Response::CompareAndSet(Err(StoreError::CasIdempotencyOutcomeUnavailable)),
            Response::DeleteFenced(Err(StoreError::BackendOperationOutcomeUnavailable)),
            Response::RefreshTtl(Err(StoreError::BackendOperationOutcomeUnavailable)),
            Response::Batch(Err(StoreError::BackendOperationOutcomeUnavailable)),
            Response::ScanRestoreRecords(Err(store_response_limit_error())),
            Response::MaxReplicationSequence(Err(store_response_limit_error())),
            Response::GetReplicationLog(Err(store_response_limit_error())),
            Response::ReplicateEntry(Err(StoreError::BackendOperationOutcomeUnavailable)),
            Response::RebuildReplicationState(Err(StoreError::BackendOperationOutcomeUnavailable)),
            Response::WatchEntry(Err(StoreError::BackendUnavailable(
                WATCH_RESPONSE_LIMIT_MESSAGE.to_string(),
            ))),
            Response::WatchStream,
            Response::NextLeaseInfo(Err(store_response_limit_error())),
            Response::AcquireLease(Err(LeaseError::OperationOutcomeUnavailable)),
            Response::RenewLease(Err(LeaseError::OperationOutcomeUnavailable)),
            Response::ReleaseLease(Err(LeaseError::OperationOutcomeUnavailable)),
        ];

        for response in responses {
            ensure_frame_fits(&response, crate::protocol::MIN_NEGOTIATED_FRAME_SIZE)
                .expect("fixed same-family fallback must fit the protocol minimum");
        }
    }

    #[test]
    fn replication_log_response_keeps_the_largest_fitting_prefix() {
        let entries = vec![
            replication_log_entry(1, 4096),
            replication_log_entry(2, 4096),
            replication_log_entry(3, 4096),
        ];
        let one_entry_budget =
            serde_json::to_vec(&Response::GetReplicationLog(Ok(vec![entries[0].clone()])))
                .expect("encode one log entry")
                .len();
        assert!(one_entry_budget >= crate::protocol::MIN_NEGOTIATED_FRAME_SIZE);
        assert!(
            serde_json::to_vec(&Response::GetReplicationLog(Ok(entries[..2].to_vec())))
                .expect("encode two log entries")
                .len()
                > one_entry_budget
        );

        let response = bounded_replication_log_response(
            Ok(entries),
            one_entry_budget,
            response_write_deadline(std::time::Duration::from_secs(1)).expect("deadline"),
            &TEST_NOT_CANCELLED,
        )
        .expect("shape bounded log response");
        assert!(matches!(
            response,
            Response::GetReplicationLog(Ok(entries))
                if entries.len() == 1 && entries[0].sequence == 1
        ));
    }

    #[test]
    fn pageable_response_shaping_honours_an_expired_write_deadline() {
        let deadline = tokio::time::Instant::now();
        let restore_error = bounded_restore_scan_response(
            Ok(RestoreScanPage::new(
                vec![restore_record(b"restore", 2048)],
                0,
                None,
            )),
            &RestoreScanRequest::all(1),
            MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE,
            deadline,
            &TEST_NOT_CANCELLED,
        )
        .expect_err("restore shaping must stop at the response deadline");
        assert!(matches!(
            restore_error,
            ProtocolError::Io(error) if error.kind() == std::io::ErrorKind::TimedOut
        ));

        let log_error = bounded_replication_log_response(
            Ok(vec![replication_log_entry(1, 2048)]),
            MIN_NEGOTIATED_FRAME_SIZE,
            deadline,
            &TEST_NOT_CANCELLED,
        )
        .expect_err("log shaping must stop at the response deadline");
        assert!(matches!(
            log_error,
            ProtocolError::Io(error) if error.kind() == std::io::ErrorKind::TimedOut
        ));
    }

    #[test]
    fn capabilities_clamp_to_both_request_and_response_envelopes() {
        let mut capabilities = opc_session_store::BackendCapabilities::all_enabled();
        capabilities.max_value_bytes = usize::MAX;
        let request_frame_size = MIN_NEGOTIATED_FRAME_SIZE * 4;
        let response_frame_size = MIN_NEGOTIATED_FRAME_SIZE * 2;

        let capabilities =
            capabilities_for_transport(capabilities, request_frame_size, response_frame_size);

        assert_eq!(
            capabilities.max_value_bytes,
            conservative_payload_budget(response_frame_size)
        );
    }

    #[test]
    fn capabilities_mask_legacy_or_unspecified_restore_profiles() {
        let capabilities = opc_session_store::BackendCapabilities::all_enabled();
        assert!(
            !capabilities_for_restore_profile(
                capabilities,
                Some(RestoreScanCursorProfile::LegacyCompatibility)
            )
            .restore_scan
        );
        assert!(!capabilities_for_restore_profile(capabilities, None).restore_scan);
        assert!(
            capabilities_for_restore_profile(
                capabilities,
                Some(RestoreScanCursorProfile::DurableOpaqueV1)
            )
            .restore_scan
        );
    }

    #[tokio::test]
    async fn oversized_batch_and_watch_keep_their_response_family() {
        use crate::protocol::read_frame;

        let budget = crate::protocol::MIN_NEGOTIATED_FRAME_SIZE;
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        let record = restore_record(b"large", 8192);
        write_post_auth_response_with_fallback(
            &mut writer,
            Response::Batch(Ok(vec![opc_session_store::SessionOpResult::Get(Ok(Some(
                record,
            )))])),
            Response::Batch(Err(store_response_limit_error())),
            budget,
            std::time::Duration::from_secs(1),
            ResponseFamily::Batch,
            &TEST_SERVER_NOT_CANCELLED,
        )
        .await
        .expect("write bounded batch fallback");
        let response: Response = read_frame(&mut reader, budget)
            .await
            .expect("read batch fallback");
        assert!(matches!(
            response,
            Response::Batch(Err(StoreError::BackendUnavailable(message)))
                if message == "backend unavailable"
        ));

        let ambiguity_before = METRICS
            .session_net_backend_ambiguous_outcomes
            .load(Ordering::Relaxed);
        write_post_auth_response_with_fallback(
            &mut writer,
            Response::Batch(Ok(vec![opc_session_store::SessionOpResult::Get(Ok(Some(
                restore_record(b"large-mutation", 8192),
            )))])),
            Response::Batch(Err(StoreError::BackendOperationOutcomeUnavailable)),
            budget,
            std::time::Duration::from_secs(1),
            ResponseFamily::Batch,
            &TEST_SERVER_NOT_CANCELLED,
        )
        .await
        .expect("write ambiguous mutation fallback");
        let response: Response = read_frame(&mut reader, budget)
            .await
            .expect("read ambiguous mutation fallback");
        assert!(matches!(
            response,
            Response::Batch(Err(StoreError::BackendOperationOutcomeUnavailable))
        ));
        assert!(
            METRICS
                .session_net_backend_ambiguous_outcomes
                .load(Ordering::Relaxed)
                > ambiguity_before,
            "selecting a typed ambiguity fallback must be observable"
        );

        let terminate = write_watch_response(
            &mut writer,
            Response::WatchEntry(Ok(replication_log_entry(1, 8192))),
            budget,
            std::time::Duration::from_secs(1),
            &TEST_SERVER_NOT_CANCELLED,
        )
        .await
        .expect("write bounded watch fallback");
        assert!(terminate);
        let response: Response = read_frame(&mut reader, budget)
            .await
            .expect("read watch fallback");
        assert!(matches!(
            response,
            Response::WatchEntry(Err(StoreError::BackendUnavailable(message)))
                if message == "backend unavailable"
        ));
    }

    #[tokio::test]
    async fn watch_writer_iteratively_discards_malformed_backend_operation_trees() {
        let mut operation = ReplicationOp::Batch { ops: Vec::new() };
        for _ in 0..50_000 {
            operation = ReplicationOp::Batch {
                ops: vec![operation],
            };
        }
        let response = Response::WatchEntry(Ok(ReplicationEntry {
            sequence: 1,
            tx_id: "malformed-watch-tree"
                .try_into()
                .expect("valid transaction ID"),
            op: operation,
            timestamp: opc_types::Timestamp::now_utc(),
        }));
        let (mut writer, _reader) = tokio::io::duplex(MIN_NEGOTIATED_FRAME_SIZE + 4);
        let error = write_watch_response_until(
            &mut writer,
            response,
            MIN_NEGOTIATED_FRAME_SIZE,
            response_write_deadline(std::time::Duration::from_secs(1)).expect("deadline"),
            &TEST_SERVER_NOT_CANCELLED,
        )
        .await
        .expect_err("an over-depth backend watch item must fail closed");
        assert!(matches!(error, ProtocolError::Serialization(_)));
    }

    #[tokio::test]
    async fn every_non_pageable_fallback_honours_exact_and_one_over_boundaries() {
        use crate::protocol::read_frame;

        let store_error = || StoreError::BackendUnavailable("x".repeat(MIN_NEGOTIATED_FRAME_SIZE));
        let lease_error = || LeaseError::Backend("x".repeat(MIN_NEGOTIATED_FRAME_SIZE));
        let cases = vec![
            (
                Response::Get(Err(store_error())),
                Response::Get(Err(store_response_limit_error())),
                ResponseFamily::Get,
            ),
            (
                Response::CompareAndSet(Err(store_error())),
                Response::CompareAndSet(Err(StoreError::CasIdempotencyOutcomeUnavailable)),
                ResponseFamily::CompareAndSet,
            ),
            (
                Response::DeleteFenced(Err(store_error())),
                Response::DeleteFenced(Err(StoreError::BackendOperationOutcomeUnavailable)),
                ResponseFamily::DeleteFenced,
            ),
            (
                Response::RefreshTtl(Err(store_error())),
                Response::RefreshTtl(Err(StoreError::BackendOperationOutcomeUnavailable)),
                ResponseFamily::RefreshTtl,
            ),
            (
                Response::Batch(Err(store_error())),
                Response::Batch(Err(StoreError::BackendOperationOutcomeUnavailable)),
                ResponseFamily::Batch,
            ),
            (
                Response::MaxReplicationSequence(Err(store_error())),
                Response::MaxReplicationSequence(Err(store_response_limit_error())),
                ResponseFamily::MaxReplicationSequence,
            ),
            (
                Response::ReplicateEntry(Err(store_error())),
                Response::ReplicateEntry(Err(StoreError::BackendOperationOutcomeUnavailable)),
                ResponseFamily::ReplicateEntry,
            ),
            (
                Response::RebuildReplicationState(Err(store_error())),
                Response::RebuildReplicationState(Err(
                    StoreError::BackendOperationOutcomeUnavailable,
                )),
                ResponseFamily::RebuildReplicationState,
            ),
            (
                Response::NextLeaseInfo(Err(store_error())),
                Response::NextLeaseInfo(Err(store_response_limit_error())),
                ResponseFamily::NextLeaseInfo,
            ),
            (
                Response::AcquireLease(Err(lease_error())),
                Response::AcquireLease(Err(LeaseError::OperationOutcomeUnavailable)),
                ResponseFamily::AcquireLease,
            ),
            (
                Response::RenewLease(Err(lease_error())),
                Response::RenewLease(Err(LeaseError::OperationOutcomeUnavailable)),
                ResponseFamily::RenewLease,
            ),
            (
                Response::ReleaseLease(Err(lease_error())),
                Response::ReleaseLease(Err(LeaseError::OperationOutcomeUnavailable)),
                ResponseFamily::ReleaseLease,
            ),
        ];

        for (primary, fallback, family) in cases {
            let exact = serde_json::to_vec(&primary)
                .expect("encode exact response")
                .len();
            if exact <= MIN_NEGOTIATED_FRAME_SIZE {
                ensure_frame_fits(&primary, MIN_NEGOTIATED_FRAME_SIZE)
                    .expect("fixed sanitized response must fit the protocol minimum");
                continue;
            }

            let (mut writer, mut reader) = tokio::io::duplex(exact + 4);
            write_post_auth_response_with_fallback(
                &mut writer,
                primary.clone(),
                fallback.clone(),
                exact,
                std::time::Duration::from_secs(1),
                family,
                &TEST_SERVER_NOT_CANCELLED,
            )
            .await
            .expect("exact response must fit");
            let exact_response: Response = read_frame(&mut reader, exact)
                .await
                .expect("read exact response");
            assert_eq!(
                std::mem::discriminant(&exact_response),
                std::mem::discriminant(&primary)
            );

            let one_over_budget = exact - 1;
            let (mut writer, mut reader) = tokio::io::duplex(one_over_budget + 4);
            write_post_auth_response_with_fallback(
                &mut writer,
                primary,
                fallback.clone(),
                one_over_budget,
                std::time::Duration::from_secs(1),
                family,
                &TEST_SERVER_NOT_CANCELLED,
            )
            .await
            .expect("one-over response must use the same-family fallback");
            let one_over_response: Response = read_frame(&mut reader, one_over_budget)
                .await
                .expect("read one-over fallback");
            assert_eq!(
                std::mem::discriminant(&one_over_response),
                std::mem::discriminant(&fallback)
            );
        }
    }

    #[test]
    fn very_wide_malformed_log_and_watch_outputs_are_disposed_iteratively() {
        fn wide_entry(sequence: u64) -> ReplicationEntry {
            ReplicationEntry {
                sequence,
                tx_id: format!("wide-{sequence}")
                    .try_into()
                    .expect("valid transaction ID"),
                op: ReplicationOp::Batch {
                    ops: (0..100_000)
                        .map(|_| ReplicationOp::Batch { ops: Vec::new() })
                        .collect(),
                },
                timestamp: opc_types::Timestamp::now_utc(),
            }
        }

        discard_response_iteratively(Response::GetReplicationLog(Ok(vec![wide_entry(1)])));
        discard_watch_response_iteratively(Response::WatchEntry(Ok(wide_entry(2))));
    }

    #[tokio::test]
    async fn oversized_primary_is_disposed_before_repeated_slow_fallback_writes() {
        for sequence in 1..=3 {
            let (mut writer, _reader) = tokio::io::duplex(1);
            let error = write_post_auth_response_with_fallback(
                &mut writer,
                Response::GetReplicationLog(Ok(vec![replication_log_entry(sequence, 32 * 1024)])),
                Response::GetReplicationLog(Err(store_response_limit_error())),
                MIN_NEGOTIATED_FRAME_SIZE,
                std::time::Duration::from_millis(25),
                ResponseFamily::ReplicationLog,
                &TEST_SERVER_NOT_CANCELLED,
            )
            .await
            .expect_err("a non-reading peer must time out the fallback write");
            assert!(matches!(
                error,
                ProtocolError::Io(ref error)
                    if error.kind() == std::io::ErrorKind::TimedOut
            ));
        }
    }
}
