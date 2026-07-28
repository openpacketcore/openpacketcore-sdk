//! Durable, tamper-evident implementation of [`opc_mgmt_audit::AuditSink`].
//!
//! [`DurableAuditSink`] serializes management audit work onto one bounded
//! worker queue backed by the asynchronous [`opc_persist::SqliteBackend`].
//! Both [`opc_mgmt_audit::AuditSink::record`] and its native
//! [`opc_mgmt_audit::AuditSink::record_async`] override report success only
//! after the event, retention update, and authenticated anchor commit in one
//! SQLite transaction. Queue pressure fails immediately. Cancellation after
//! async admission cannot retract the append, so timeout, error, or caller drop
//! can leave its outcome unknown. Verification, querying, and final sink drop
//! remain bounded synchronous operations.
//!
//! Construction performs durable-storage preflight and complete retained-chain
//! verification before the sink can accept an event. Ephemeral or unsafe
//! storage, a wrong audit key, and any broken retained link fail closed.
//!
//! The authenticated local anchor detects retained-row/anchor disagreement. A
//! coherent rollback of the whole database cannot be detected without an
//! external monotonic checkpoint; deployments needing storage anti-rollback
//! must provide that authority through their KMS/platform controls.

#![forbid(unsafe_code)]

use std::{
    fmt,
    future::Future,
    panic::{catch_unwind, AssertUnwindSafe},
    path::PathBuf,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Mutex,
    },
    thread,
    time::Duration,
};

use opc_config_model::TransportType;
use opc_mgmt_audit::{
    AuditError, AuditEvent, AuditOperation, AuditOutcome, AuditSink, AuditTimeSource,
};
use opc_persist::{
    AuditKey, ConfigStore, ManagementAuditEventRecord, ManagementAuditInstant,
    ManagementAuditOperationCode, ManagementAuditOutcomeCode, ManagementAuditPage,
    ManagementAuditPageRequest, ManagementAuditRecordError, ManagementAuditRetention,
    ManagementAuditStoreError, ManagementAuditTimeSourceCode, ManagementAuditTransportCode,
    ManagementAuditVerification, PersistError, SqliteBackend,
};
use thiserror::Error;

/// Fixed number of requests admitted ahead of the durable worker.
///
/// A full queue rejects either sync or async admission immediately, preserving
/// the fail-closed `AuditSink` contract without unbounded memory or silent loss.
pub const DURABLE_AUDIT_QUEUE_CAPACITY: usize = 64;
/// Maximum time a sync or async caller waits for durable acknowledgement.
///
/// Expiry is a fail-closed, outcome-unknown result: the atomic append may
/// subsequently commit, but the caller never receives manufactured success.
pub const DURABLE_AUDIT_ACKNOWLEDGEMENT_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum time shutdown waits for queued work and worker teardown.
pub const DURABLE_AUDIT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(any(test, feature = "testing"))]
const DURABLE_AUDIT_TESTING_HOLD_MAX_DURATION: Duration = Duration::from_secs(30);

static DURABLE_AUDIT_WORKER_DETACHMENTS: AtomicU64 = AtomicU64::new(0);

/// Workers detached after they could not complete within the shutdown bound.
pub fn durable_audit_worker_detachments() -> u64 {
    DURABLE_AUDIT_WORKER_DETACHMENTS.load(Ordering::Relaxed)
}

/// Production SQLite-backed management audit sink.
pub struct DurableAuditSink {
    sender: Option<mpsc::SyncSender<WorkerRequest>>,
    worker: Option<thread::JoinHandle<()>>,
    completion: Mutex<Option<mpsc::Receiver<()>>>,
    retention: ManagementAuditRetention,
    acknowledgement_timeout: Duration,
    shutdown_timeout: Duration,
}

impl DurableAuditSink {
    /// Open a production SQLite backend and verify/configure its audit trail.
    ///
    /// `audit_key` must come from deployment-owned secret/KMS material. The
    /// constructor always selects the non-ephemeral backend profile.
    pub async fn open(
        path: impl Into<PathBuf>,
        min_free_bytes: u64,
        audit_key: AuditKey,
        retention: ManagementAuditRetention,
    ) -> Result<Self, DurableAuditSinkError> {
        let backend =
            SqliteBackend::open_with_audit_key(path.into(), false, min_free_bytes, audit_key)
                .await
                .map_err(DurableAuditSinkError::Backend)?;
        Self::from_backend(backend, retention).await
    }

    /// Verify/configure a caller-owned reference backend and start the worker.
    ///
    /// This rejects ephemeral backends even when their development preflight
    /// says they are writable. Existing retained records are fully verified
    /// before this method returns.
    pub async fn from_backend(
        backend: SqliteBackend,
        retention: ManagementAuditRetention,
    ) -> Result<Self, DurableAuditSinkError> {
        Self::start(
            backend,
            retention,
            DURABLE_AUDIT_ACKNOWLEDGEMENT_TIMEOUT,
            DURABLE_AUDIT_SHUTDOWN_TIMEOUT,
        )
        .await
    }

    async fn start(
        backend: SqliteBackend,
        retention: ManagementAuditRetention,
        acknowledgement_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> Result<Self, DurableAuditSinkError> {
        let capabilities = backend
            .preflight()
            .await
            .map_err(DurableAuditSinkError::Backend)?;
        if capabilities.ephemeral_mode || !capabilities.is_safe_for_writes() {
            return Err(DurableAuditSinkError::UnsafeStorage);
        }
        backend
            .configure_management_audit(retention)
            .await
            .map_err(DurableAuditSinkError::Store)?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(DurableAuditSinkError::WorkerStart)?;
        let (sender, receiver) = mpsc::sync_channel(DURABLE_AUDIT_QUEUE_CAPACITY);
        let (completion_sender, completion_receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("opc-mgmt-durable-audit".to_string())
            .spawn(move || {
                run_worker(backend, retention, runtime, receiver);
                let _ = completion_sender.send(());
            })
            .map_err(DurableAuditSinkError::WorkerStart)?;
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
            completion: Mutex::new(Some(completion_receiver)),
            retention,
            acknowledgement_timeout,
            shutdown_timeout,
        })
    }

    /// Start a sink with caller-selected acknowledgement and shutdown bounds.
    ///
    /// This seam is available only with the non-default `testing` feature and
    /// exists for deterministic timeout and cancellation tests. Both bounds
    /// are clamped to 30 seconds; zero-duration bounds remain available.
    ///
    /// # Warning
    ///
    /// Never enable the `testing` feature in production. It intentionally
    /// exposes worker-stalling behavior for adversarial integration tests.
    #[cfg(any(test, feature = "testing"))]
    pub async fn from_backend_with_timeouts(
        backend: SqliteBackend,
        retention: ManagementAuditRetention,
        acknowledgement_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> Result<Self, DurableAuditSinkError> {
        Self::start(
            backend,
            retention,
            clamp_testing_timeout(acknowledgement_timeout),
            clamp_testing_timeout(shutdown_timeout),
        )
        .await
    }

    /// Hold the durable worker after it acknowledges starting.
    ///
    /// This deterministic testing seam is available only with the non-default
    /// `testing` feature. Dropping or explicitly releasing the returned guard
    /// unblocks the worker. The worker also self-releases after a fixed 30
    /// seconds, so forgetting the guard cannot wedge it indefinitely. The
    /// caller-selected start timeout is likewise clamped to 30 seconds.
    ///
    /// # Warning
    ///
    /// Never enable the `testing` feature in production. This method is an
    /// intentional denial-of-service seam for controlled tests.
    #[cfg(any(test, feature = "testing"))]
    pub async fn hold_worker_for_testing(
        &self,
        start_timeout: Duration,
    ) -> Result<DurableAuditWorkerHold, DurableAuditSinkError> {
        tokio::runtime::Handle::try_current()
            .map_err(|_| DurableAuditSinkError::WorkerUnavailable)?;
        let deadline = tokio::time::Instant::now()
            .checked_add(clamp_testing_timeout(start_timeout))
            .ok_or(DurableAuditSinkError::WorkerUnavailable)?;
        let deadline_wait = catch_unwind(AssertUnwindSafe(|| tokio::time::sleep_until(deadline)))
            .map_err(|_| DurableAuditSinkError::WorkerUnavailable)?;

        let sender = self
            .sender
            .as_ref()
            .ok_or(DurableAuditSinkError::WorkerUnavailable)?;
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let guard = DurableAuditWorkerHold {
            release_sender: Some(release_sender),
        };
        let (reply_sender, _reply_receiver) = tokio::sync::oneshot::channel();
        sender
            .try_send(WorkerRequest {
                command: WorkerCommand::HoldWithStart {
                    started_sender,
                    release_receiver,
                },
                reply_sender: WorkerReplySender::Asynchronous(reply_sender),
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => DurableAuditSinkError::QueueFull,
                mpsc::TrySendError::Disconnected(_) => DurableAuditSinkError::WorkerUnavailable,
            })?;

        tokio::pin!(deadline_wait);
        tokio::select! {
            biased;
            started = started_receiver => {
                started.map_err(|_| DurableAuditSinkError::WorkerUnavailable)?;
                Ok(guard)
            }
            () = &mut deadline_wait => Err(DurableAuditSinkError::AcknowledgementTimeout),
        }
    }

    /// Re-authenticate every retained link and return its durable boundaries.
    pub fn verify(&self) -> Result<ManagementAuditVerification, DurableAuditSinkError> {
        match self.request(WorkerCommand::Verify)? {
            WorkerReply::Verified(verification) => Ok(verification),
            _ => Err(DurableAuditSinkError::WorkerProtocol),
        }
    }

    /// Retrieve one fixed-bounded page after complete chain authentication.
    pub fn query_page(
        &self,
        request: ManagementAuditPageRequest,
    ) -> Result<ManagementAuditPage, DurableAuditSinkError> {
        match self.request(WorkerCommand::QueryPage(request))? {
            WorkerReply::Page(page) => Ok(page),
            _ => Err(DurableAuditSinkError::WorkerProtocol),
        }
    }

    fn request(&self, command: WorkerCommand) -> Result<WorkerReply, DurableAuditSinkError> {
        let sender = self
            .sender
            .as_ref()
            .ok_or(DurableAuditSinkError::WorkerUnavailable)?;
        let (reply_sender, reply_receiver) = mpsc::sync_channel(1);
        sender
            .try_send(WorkerRequest {
                command,
                reply_sender: WorkerReplySender::Synchronous(reply_sender),
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => DurableAuditSinkError::QueueFull,
                mpsc::TrySendError::Disconnected(_) => DurableAuditSinkError::WorkerUnavailable,
            })?;
        reply_receiver
            .recv_timeout(self.acknowledgement_timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => DurableAuditSinkError::AcknowledgementTimeout,
                mpsc::RecvTimeoutError::Disconnected => DurableAuditSinkError::WorkerUnavailable,
            })?
    }

    async fn request_async(
        &self,
        command: WorkerCommand,
    ) -> Result<WorkerReply, DurableAuditSinkError> {
        self.request_async_inner(command, None).await
    }

    async fn request_async_inner(
        &self,
        command: WorkerCommand,
        #[cfg(test)] admitted: Option<tokio::sync::oneshot::Sender<()>>,
        #[cfg(not(test))] _admitted: Option<()>,
    ) -> Result<WorkerReply, DurableAuditSinkError> {
        // A Tokio timer is part of the fail-closed acknowledgement bound.
        // Prove that both runtime and timer capabilities exist before admitting
        // the request, so a missing driver cannot strand an admitted append.
        tokio::runtime::Handle::try_current()
            .map_err(|_| DurableAuditSinkError::WorkerUnavailable)?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.acknowledgement_timeout)
            .ok_or(DurableAuditSinkError::WorkerUnavailable)?;
        let deadline_wait = catch_unwind(AssertUnwindSafe(|| tokio::time::sleep_until(deadline)))
            .map_err(|_| DurableAuditSinkError::WorkerUnavailable)?;

        let sender = self
            .sender
            .as_ref()
            .ok_or(DurableAuditSinkError::WorkerUnavailable)?;
        let (reply_sender, reply_receiver) = tokio::sync::oneshot::channel();
        sender
            .try_send(WorkerRequest {
                command,
                reply_sender: WorkerReplySender::Asynchronous(reply_sender),
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => DurableAuditSinkError::QueueFull,
                mpsc::TrySendError::Disconnected(_) => DurableAuditSinkError::WorkerUnavailable,
            })?;
        #[cfg(test)]
        if let Some(admitted) = admitted {
            let _ = admitted.send(());
        }

        tokio::pin!(deadline_wait);
        tokio::select! {
            // At the deadline boundary, prefer an acknowledgement that is
            // already available over manufacturing an outcome-unknown error.
            biased;
            reply = reply_receiver => {
                reply.map_err(|_| DurableAuditSinkError::WorkerUnavailable)?
            }
            () = &mut deadline_wait => Err(DurableAuditSinkError::AcknowledgementTimeout),
        }
    }

    #[cfg(test)]
    fn stall_worker(&self, duration: Duration) -> Result<(), DurableAuditSinkError> {
        match self.request(WorkerCommand::Stall(duration))? {
            WorkerReply::Stalled => Ok(()),
            _ => Err(DurableAuditSinkError::WorkerProtocol),
        }
    }

    #[cfg(test)]
    async fn record_async_with_admission(
        &self,
        event: &AuditEvent,
        admitted: tokio::sync::oneshot::Sender<()>,
    ) -> Result<(), AuditError> {
        let event = convert_event(event).map_err(|_| {
            AuditError::failed("durable management audit rejected the structured event")
        })?;
        map_append_reply(
            self.request_async_inner(WorkerCommand::Append(event), Some(admitted))
                .await,
        )
    }
}

#[cfg(any(test, feature = "testing"))]
fn clamp_testing_timeout(timeout: Duration) -> Duration {
    timeout.min(DURABLE_AUDIT_TESTING_HOLD_MAX_DURATION)
}

/// RAII release token returned by
/// [`DurableAuditSink::hold_worker_for_testing`].
#[cfg(any(test, feature = "testing"))]
#[must_use = "dropping the guard releases the durable audit worker"]
pub struct DurableAuditWorkerHold {
    release_sender: Option<mpsc::SyncSender<()>>,
}

#[cfg(any(test, feature = "testing"))]
impl DurableAuditWorkerHold {
    /// Release the held worker immediately.
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if let Some(sender) = self.release_sender.take() {
            let _ = sender.try_send(());
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Drop for DurableAuditWorkerHold {
    fn drop(&mut self) {
        self.release_inner();
    }
}

impl AuditSink for DurableAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let event = convert_event(event).map_err(|_| {
            AuditError::failed("durable management audit rejected the structured event")
        })?;
        map_append_reply(self.request(WorkerCommand::Append(event)))
    }

    fn record_async<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuditError>> + Send + 'a>> {
        let event = match convert_event(event) {
            Ok(event) => event,
            Err(_) => {
                return Box::pin(std::future::ready(Err(AuditError::failed(
                    "durable management audit rejected the structured event",
                ))));
            }
        };
        Box::pin(
            async move { map_append_reply(self.request_async(WorkerCommand::Append(event)).await) },
        )
    }
}

fn map_append_reply(result: Result<WorkerReply, DurableAuditSinkError>) -> Result<(), AuditError> {
    match result {
        Ok(WorkerReply::Appended) => Ok(()),
        Ok(_) => Err(AuditError::unavailable(
            "durable management audit worker protocol failure",
        )),
        Err(DurableAuditSinkError::QueueFull) => Err(AuditError::unavailable(
            "durable management audit queue is full",
        )),
        Err(DurableAuditSinkError::AcknowledgementTimeout) => Err(AuditError::unavailable(
            "durable management audit outcome is unknown after acknowledgement timeout",
        )),
        Err(
            DurableAuditSinkError::WorkerUnavailable
            | DurableAuditSinkError::WorkerPanicked
            | DurableAuditSinkError::WorkerProtocol
            | DurableAuditSinkError::WorkerStart(_),
        ) => Err(AuditError::unavailable(
            "durable management audit worker unavailable",
        )),
        Err(
            DurableAuditSinkError::Backend(_)
            | DurableAuditSinkError::Store(_)
            | DurableAuditSinkError::UnsafeStorage,
        ) => Err(AuditError::failed(
            "durable management audit persistence failed",
        )),
    }
}

impl fmt::Debug for DurableAuditSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableAuditSink")
            .field("worker_available", &self.sender.is_some())
            .field("retention_max_records", &self.retention.max_records())
            .field("queue_capacity", &DURABLE_AUDIT_QUEUE_CAPACITY)
            .field("acknowledgement_timeout", &self.acknowledgement_timeout)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .finish()
    }
}

impl Drop for DurableAuditSink {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let (reply_sender, _reply_receiver) = mpsc::sync_channel(1);
            let _ = sender.try_send(WorkerRequest {
                command: WorkerCommand::Shutdown,
                reply_sender: WorkerReplySender::Synchronous(reply_sender),
            });
            drop(sender);
        }

        let completed = self
            .completion
            .get_mut()
            .ok()
            .and_then(Option::take)
            .is_some_and(|receiver| receiver.recv_timeout(self.shutdown_timeout).is_ok());
        if completed {
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        } else if self.worker.take().is_some() {
            DURABLE_AUDIT_WORKER_DETACHMENTS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Construction, worker, storage, or authenticated-chain failure.
#[derive(Error)]
pub enum DurableAuditSinkError {
    /// Reference backend open/preflight failed.
    #[error("durable management audit backend failed")]
    Backend(#[source] PersistError),
    /// Audit append/query/verification failed.
    #[error("durable management audit store failed")]
    Store(#[source] ManagementAuditStoreError),
    /// Backend was ephemeral or did not pass production durable-write preflight.
    #[error("durable management audit storage is unsafe")]
    UnsafeStorage,
    /// Worker runtime or operating-system thread could not be created.
    #[error("durable management audit worker could not start")]
    WorkerStart(#[source] std::io::Error),
    /// Worker stopped before acknowledging the request.
    #[error("durable management audit worker is unavailable")]
    WorkerUnavailable,
    /// Bounded worker queue is full; the request was not admitted.
    #[error("durable management audit queue is full")]
    QueueFull,
    /// Durable acknowledgement was not received before the fixed deadline.
    #[error("durable management audit outcome is unknown")]
    AcknowledgementTimeout,
    /// A dependency panicked while the worker was handling a request.
    #[error("durable management audit worker failed")]
    WorkerPanicked,
    /// Worker returned a response for a different operation.
    #[error("durable management audit worker protocol failed")]
    WorkerProtocol,
}

impl fmt::Debug for DurableAuditSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self {
            Self::Backend(_) => "Backend",
            Self::Store(_) => "Store",
            Self::UnsafeStorage => "UnsafeStorage",
            Self::WorkerStart(_) => "WorkerStart",
            Self::WorkerUnavailable => "WorkerUnavailable",
            Self::QueueFull => "QueueFull",
            Self::AcknowledgementTimeout => "AcknowledgementTimeout",
            Self::WorkerPanicked => "WorkerPanicked",
            Self::WorkerProtocol => "WorkerProtocol",
        };
        formatter
            .debug_struct("DurableAuditSinkError")
            .field("class", &class)
            .finish()
    }
}

struct WorkerRequest {
    command: WorkerCommand,
    reply_sender: WorkerReplySender,
}

enum WorkerReplySender {
    Synchronous(mpsc::SyncSender<Result<WorkerReply, DurableAuditSinkError>>),
    Asynchronous(tokio::sync::oneshot::Sender<Result<WorkerReply, DurableAuditSinkError>>),
}

impl WorkerReplySender {
    fn send(self, reply: Result<WorkerReply, DurableAuditSinkError>) {
        match self {
            Self::Synchronous(sender) => {
                let _ = sender.send(reply);
            }
            Self::Asynchronous(sender) => {
                let _ = sender.send(reply);
            }
        }
    }
}

enum WorkerCommand {
    Append(ManagementAuditEventRecord),
    Verify,
    QueryPage(ManagementAuditPageRequest),
    Shutdown,
    #[cfg(test)]
    Stall(Duration),
    #[cfg(any(test, feature = "testing"))]
    HoldWithStart {
        started_sender: tokio::sync::oneshot::Sender<()>,
        release_receiver: mpsc::Receiver<()>,
    },
}

enum WorkerReply {
    Appended,
    Verified(ManagementAuditVerification),
    Page(ManagementAuditPage),
    Shutdown,
    #[cfg(any(test, feature = "testing"))]
    Stalled,
}

fn run_worker(
    backend: SqliteBackend,
    retention: ManagementAuditRetention,
    runtime: tokio::runtime::Runtime,
    receiver: mpsc::Receiver<WorkerRequest>,
) {
    for request in receiver {
        if matches!(request.command, WorkerCommand::Shutdown) {
            request.reply_sender.send(Ok(WorkerReply::Shutdown));
            break;
        }
        let result = catch_unwind(AssertUnwindSafe(|| match request.command {
            WorkerCommand::Append(event) => runtime
                .block_on(backend.append_management_audit(&event, retention))
                .map(|_| WorkerReply::Appended)
                .map_err(DurableAuditSinkError::Store),
            WorkerCommand::Verify => runtime
                .block_on(backend.verify_management_audit())
                .map(WorkerReply::Verified)
                .map_err(DurableAuditSinkError::Store),
            WorkerCommand::QueryPage(page_request) => runtime
                .block_on(backend.query_management_audits_page(page_request))
                .map(WorkerReply::Page)
                .map_err(DurableAuditSinkError::Store),
            WorkerCommand::Shutdown => Err(DurableAuditSinkError::WorkerProtocol),
            #[cfg(test)]
            WorkerCommand::Stall(duration) => {
                thread::sleep(duration);
                Ok(WorkerReply::Stalled)
            }
            #[cfg(any(test, feature = "testing"))]
            WorkerCommand::HoldWithStart {
                started_sender,
                release_receiver,
            } => {
                let _ = started_sender.send(());
                let _ = release_receiver.recv_timeout(DURABLE_AUDIT_TESTING_HOLD_MAX_DURATION);
                Ok(WorkerReply::Stalled)
            }
        }))
        .unwrap_or(Err(DurableAuditSinkError::WorkerPanicked));
        request.reply_sender.send(result);
    }
}

fn convert_event(
    event: &AuditEvent,
) -> Result<ManagementAuditEventRecord, opc_persist::ManagementAuditRecordError> {
    let time_source = match event.occurred_at.source() {
        AuditTimeSource::NodeClock => ManagementAuditTimeSourceCode::NodeClock,
        AuditTimeSource::SynchronisedNodeClock => {
            ManagementAuditTimeSourceCode::SynchronisedNodeClock
        }
    };
    let occurred_at = ManagementAuditInstant::try_new(
        event.occurred_at.utc_seconds(),
        event.occurred_at.nanosecond(),
        event.occurred_at.monotonic_sequence(),
        time_source,
    )
    .map_err(|_| ManagementAuditRecordError::Timestamp)?;
    let transport = match event.transport {
        TransportType::Gnmi => ManagementAuditTransportCode::Gnmi,
        TransportType::NetconfSsh => ManagementAuditTransportCode::NetconfSsh,
        TransportType::NetconfTls => ManagementAuditTransportCode::NetconfTls,
        TransportType::RestconfHttps => ManagementAuditTransportCode::RestconfHttps,
        TransportType::Internal => ManagementAuditTransportCode::Internal,
    };
    let operation = match event.operation {
        AuditOperation::Capabilities => ManagementAuditOperationCode::Capabilities,
        AuditOperation::Read => ManagementAuditOperationCode::Read,
        AuditOperation::Subscribe => ManagementAuditOperationCode::Subscribe,
        AuditOperation::Create => ManagementAuditOperationCode::Create,
        AuditOperation::Update => ManagementAuditOperationCode::Update,
        AuditOperation::Replace => ManagementAuditOperationCode::Replace,
        AuditOperation::Delete => ManagementAuditOperationCode::Delete,
        AuditOperation::Commit => ManagementAuditOperationCode::Commit,
        AuditOperation::Rollback => ManagementAuditOperationCode::Rollback,
        AuditOperation::Validate => ManagementAuditOperationCode::Validate,
        AuditOperation::Exec => ManagementAuditOperationCode::Exec,
    };
    let outcome = match event.outcome {
        AuditOutcome::Intent => ManagementAuditOutcomeCode::Intent,
        AuditOutcome::Success => ManagementAuditOutcomeCode::Success,
        AuditOutcome::Denied(_) => ManagementAuditOutcomeCode::Denied,
        AuditOutcome::Failed(_) => ManagementAuditOutcomeCode::Failed,
    };
    ManagementAuditEventRecord::try_new(
        *event.request_id.as_uuid().as_bytes(),
        occurred_at,
        event.tenant.as_str(),
        event.principal.as_str(),
        transport,
        operation,
        outcome,
        event.outcome.code(),
        event.schema_paths.iter().map(|path| path.as_str()),
        event.tx_id.as_ref().map(|tx_id| tx_id.as_str()),
    )
}

#[cfg(test)]
mod tests {
    use std::{
        path::Path,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    use opc_config_model::RequestId;
    use opc_mgmt_audit::{
        AuditInstant, AuditReasonCode, AuditTimeSource, AuditTxId, SchemaNodePath,
    };
    use opc_persist::{
        ManagementAuditCursorError, ManagementAuditPageRequest, ManagementAuditStoreError,
        ManagementAuditVerificationFailure,
    };
    use rusqlite::Connection;
    use tempfile::TempDir;

    use super::*;

    const RETAIN_ALL: u64 = 32;

    fn key(byte: u8) -> AuditKey {
        AuditKey::new([byte; 32]).expect("non-zero audit key")
    }

    fn event(operation: AuditOperation, outcome: AuditOutcome, suffix: u8) -> AuditEvent {
        AuditEvent {
            request_id: RequestId::new(),
            occurred_at: AuditInstant::try_from_parts(
                1_700_000_000 + i64::from(suffix),
                u32::from(suffix),
                u64::from(suffix) + 1,
                if suffix.is_multiple_of(2) {
                    AuditTimeSource::NodeClock
                } else {
                    AuditTimeSource::SynchronisedNodeClock
                },
            )
            .expect("audit instant"),
            tenant: "tenant-a".to_string(),
            principal: format!("user:operator-{suffix}"),
            transport: TransportType::Gnmi,
            operation,
            schema_paths: vec![SchemaNodePath::new("/ietf-system:system").expect("schema path")],
            outcome,
            tx_id: Some(AuditTxId::new(format!("tx-{suffix}")).expect("transaction id")),
        }
    }

    fn database(tempdir: &TempDir) -> PathBuf {
        tempdir.path().join("management.db")
    }

    async fn open_sink(path: &Path, key_byte: u8, retention: u64) -> DurableAuditSink {
        DurableAuditSink::open(
            path,
            0,
            key(key_byte),
            ManagementAuditRetention::try_new(retention).expect("retention"),
        )
        .await
        .expect("durable audit sink")
    }

    async fn create_records(path: &Path, count: u8, retention: u64) {
        let sink = open_sink(path, 0x51, retention).await;
        for suffix in 0..count {
            sink.record(&event(AuditOperation::Read, AuditOutcome::Success, suffix))
                .expect("durable record");
        }
    }

    fn expect_verification_failure(
        result: Result<DurableAuditSink, DurableAuditSinkError>,
        expected: ManagementAuditVerificationFailure,
    ) {
        match result {
            Err(DurableAuditSinkError::Store(ManagementAuditStoreError::Verification(error))) => {
                assert_eq!(error.failure(), expected);
            }
            Err(other) => panic!("unexpected open error: {other:?}"),
            Ok(_) => panic!("tampered audit store unexpectedly opened"),
        }
    }

    fn expect_verification_failure_at(
        result: Result<DurableAuditSink, DurableAuditSinkError>,
        expected: ManagementAuditVerificationFailure,
        sequence: Option<u64>,
    ) {
        match result {
            Err(DurableAuditSinkError::Store(ManagementAuditStoreError::Verification(error))) => {
                assert_eq!(error.failure(), expected);
                assert_eq!(error.sequence(), sequence);
            }
            Err(other) => panic!("unexpected open error: {other:?}"),
            Ok(_) => panic!("tampered audit store unexpectedly opened"),
        }
    }

    #[tokio::test]
    async fn records_all_outcomes_survives_restart_and_rejects_wrong_key() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = database(&tempdir);
        let sink = open_sink(&path, 0x51, RETAIN_ALL).await;
        let events = [
            event(AuditOperation::Read, AuditOutcome::Intent, 1),
            event(AuditOperation::Read, AuditOutcome::Success, 2),
            event(
                AuditOperation::Subscribe,
                AuditOutcome::denied_code(AuditReasonCode::ACCESS_DENIED),
                3,
            ),
            event(
                AuditOperation::Exec,
                AuditOutcome::failed_code(AuditReasonCode::OPERATION_FAILED),
                4,
            ),
        ];
        for audit_event in &events {
            sink.record(audit_event).expect("durable record");
        }
        let verification = sink.verify().expect("verified trail");
        assert_eq!(verification.total_count, 4);
        assert_eq!(verification.retained_count, 4);

        let page = sink
            .query_page(ManagementAuditPageRequest::try_new(None, 8).expect("page request"))
            .expect("authenticated page");
        assert_eq!(page.records().len(), 4);
        assert_eq!(
            page.records()
                .iter()
                .map(|record| record.event().outcome())
                .collect::<Vec<_>>(),
            vec![
                ManagementAuditOutcomeCode::Intent,
                ManagementAuditOutcomeCode::Success,
                ManagementAuditOutcomeCode::Denied,
                ManagementAuditOutcomeCode::Failed,
            ]
        );
        assert_eq!(page.records()[2].event().reason(), Some("access-denied"));
        assert_eq!(page.records()[3].event().reason(), Some("operation-failed"));
        assert_eq!(
            page.records()[0].event().schema_paths(),
            &["/ietf-system:system".to_string()]
        );
        let occurred_at = page.records()[0].event().occurred_at();
        assert_eq!(occurred_at.utc_seconds(), 1_700_000_001);
        assert_eq!(occurred_at.nanosecond(), 1);
        assert_eq!(occurred_at.monotonic_sequence(), 2);
        assert_eq!(
            occurred_at.source(),
            ManagementAuditTimeSourceCode::SynchronisedNodeClock
        );
        drop(sink);

        let reopened = open_sink(&path, 0x51, RETAIN_ALL).await;
        assert_eq!(
            reopened.verify().expect("restart verification").total_count,
            4
        );
        drop(reopened);

        let wrong_key = DurableAuditSink::open(
            &path,
            0,
            key(0x52),
            ManagementAuditRetention::try_new(RETAIN_ALL).expect("retention"),
        )
        .await;
        expect_verification_failure(
            wrong_key,
            ManagementAuditVerificationFailure::AnchorAuthentication,
        );
    }

    #[tokio::test]
    async fn retention_uses_authenticated_low_water_and_typed_cursor_failure() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = database(&tempdir);
        create_records(&path, 5, 2).await;

        let sink = open_sink(&path, 0x51, 2).await;
        let verification = sink.verify().expect("verified trail");
        assert_eq!(verification.total_count, 5);
        assert_eq!(verification.retained_count, 2);
        assert_eq!(verification.low_water_sequence, 3);
        assert_eq!(verification.terminal_sequence, Some(4));
        let result =
            sink.query_page(ManagementAuditPageRequest::try_new(Some(2), 1).expect("page request"));
        assert!(matches!(
            result,
            Err(DurableAuditSinkError::Store(
                ManagementAuditStoreError::Cursor(ManagementAuditCursorError::Pruned {
                    requested: 2,
                    low_water_sequence: 3
                })
            ))
        ));
    }

    #[tokio::test]
    async fn rejects_ephemeral_and_failed_storage_preflight() {
        let ephemeral = SqliteBackend::open(":memory:", true, 0)
            .await
            .expect("ephemeral backend");
        let result = DurableAuditSink::from_backend(
            ephemeral,
            ManagementAuditRetention::try_new(2).expect("retention"),
        )
        .await;
        assert!(matches!(result, Err(DurableAuditSinkError::UnsafeStorage)));

        let tempdir = tempfile::tempdir().expect("tempdir");
        let result = DurableAuditSink::open(
            database(&tempdir),
            u64::MAX,
            key(0x51),
            ManagementAuditRetention::try_new(2).expect("retention"),
        )
        .await;
        assert!(matches!(result, Err(DurableAuditSinkError::Backend(_))));
    }

    #[tokio::test]
    async fn malformed_input_fails_without_reflecting_values() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let sink = open_sink(&database(&tempdir), 0x51, RETAIN_ALL).await;
        let canary = "customer-secret-canary";
        let mut audit_event = event(AuditOperation::Read, AuditOutcome::Success, 1);
        audit_event.tenant = format!("{canary}{}", "x".repeat(300));
        let error = sink.record(&audit_event).expect_err("oversized tenant");
        assert!(!error.to_string().contains(canary));
        assert!(!error.detail().contains(canary));
        assert_eq!(sink.verify().expect("empty verified trail").total_count, 0);
    }

    #[tokio::test]
    async fn detects_interior_deletion_tail_deletion_alteration_and_reorder() {
        for (scenario, expected_failure, expected_sequence) in [
            (
                "interior-delete",
                ManagementAuditVerificationFailure::Sequence,
                Some(1),
            ),
            (
                "tail-delete",
                ManagementAuditVerificationFailure::Sequence,
                Some(2),
            ),
            (
                "alter",
                ManagementAuditVerificationFailure::RecordAuthentication,
                Some(1),
            ),
            (
                "reorder",
                ManagementAuditVerificationFailure::RecordAuthentication,
                Some(0),
            ),
        ] {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let path = database(&tempdir);
            create_records(&path, 3, RETAIN_ALL).await;
            let connection = Connection::open(&path).expect("open database");
            connection
                .pragma_update(None, "foreign_keys", "ON")
                .expect("foreign keys");
            match scenario {
                "interior-delete" => {
                    connection
                        .execute("DELETE FROM management_audit_event WHERE sequence = 1", [])
                        .expect("delete interior");
                }
                "tail-delete" => {
                    connection
                        .execute("DELETE FROM management_audit_event WHERE sequence = 2", [])
                        .expect("delete tail");
                }
                "alter" => {
                    connection
                        .execute(
                            "UPDATE management_audit_event SET principal = 'user:altered' WHERE sequence = 1",
                            [],
                        )
                        .expect("alter record");
                }
                "reorder" => {
                    connection
                        .pragma_update(None, "foreign_keys", "OFF")
                        .expect("disable foreign keys for adversarial reorder");
                    connection
                        .execute(
                            "UPDATE management_audit_event SET sequence = 99 WHERE sequence = 0",
                            [],
                        )
                        .expect("move first record aside");
                    connection
                        .execute(
                            "UPDATE management_audit_event SET sequence = 0 WHERE sequence = 1",
                            [],
                        )
                        .expect("move second record first");
                    connection
                        .execute(
                            "UPDATE management_audit_event SET sequence = 1 WHERE sequence = 99",
                            [],
                        )
                        .expect("move first record second");
                }
                _ => unreachable!("fixed scenario set"),
            }
            drop(connection);

            let result = DurableAuditSink::open(
                &path,
                0,
                key(0x51),
                ManagementAuditRetention::try_new(RETAIN_ALL).expect("retention"),
            )
            .await;
            expect_verification_failure_at(result, expected_failure, expected_sequence);
        }
    }

    #[tokio::test]
    async fn every_persisted_event_field_is_authenticated_at_the_record_boundary() {
        let scenarios = [
            (
                "request-id",
                "UPDATE management_audit_event SET request_id = zeroblob(16) WHERE sequence = 1",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            (
                "occurred-at-utc-seconds",
                "UPDATE management_audit_event SET occurred_at_utc_seconds = occurred_at_utc_seconds + 1 WHERE sequence = 1",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            (
                "occurred-at-nanosecond",
                "UPDATE management_audit_event SET occurred_at_nanosecond = occurred_at_nanosecond + 1 WHERE sequence = 1",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            (
                "occurred-at-monotonic-sequence",
                "UPDATE management_audit_event SET occurred_at_monotonic_sequence = occurred_at_monotonic_sequence + 1 WHERE sequence = 1",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            (
                "occurred-at-time-source",
                "UPDATE management_audit_event SET occurred_at_time_source = 'node-clock' WHERE sequence = 1",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            (
                "tenant",
                "UPDATE management_audit_event SET tenant = 'tenant-tampered' WHERE sequence = 1",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            (
                "principal",
                "UPDATE management_audit_event SET principal = 'user:tampered' WHERE sequence = 1",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            (
                "transport",
                "UPDATE management_audit_event SET transport = 'netconf-tls' WHERE sequence = 1",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            (
                "operation",
                "UPDATE management_audit_event SET operation = 'exec' WHERE sequence = 1",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            (
                "outcome",
                "UPDATE management_audit_event SET outcome = 'denied' WHERE sequence = 1",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            (
                "reason",
                "UPDATE management_audit_event SET reason = 'invalid-value' WHERE sequence = 1",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            (
                "schema-path",
                "UPDATE management_audit_schema_path SET schema_path = '/ietf-interfaces:interfaces' WHERE event_sequence = 1 AND path_index = 0",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            (
                "transaction-id",
                "UPDATE management_audit_event SET tx_id = 'tx-tampered' WHERE sequence = 1",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            (
                "previous-hash",
                "UPDATE management_audit_event SET previous_hash = zeroblob(32) WHERE sequence = 1",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            (
                "entry-hmac",
                "UPDATE management_audit_event SET entry_hmac = zeroblob(32) WHERE sequence = 1",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            (
                "schema-path-count",
                "UPDATE management_audit_event SET schema_path_count = 0 WHERE sequence = 1",
                ManagementAuditVerificationFailure::MalformedRecord,
            ),
            (
                "schema-path-index",
                "UPDATE management_audit_schema_path SET path_index = 1 WHERE event_sequence = 1 AND path_index = 0",
                ManagementAuditVerificationFailure::MalformedRecord,
            ),
        ];

        for (scenario, mutation, expected_failure) in scenarios {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let path = database(&tempdir);
            let sink = open_sink(&path, 0x51, RETAIN_ALL).await;
            sink.record(&event(AuditOperation::Read, AuditOutcome::Success, 0))
                .expect("first durable record");
            sink.record(&event(
                AuditOperation::Read,
                AuditOutcome::failed_code(AuditReasonCode::OPERATION_FAILED),
                1,
            ))
            .expect("second durable record");
            drop(sink);

            let connection = Connection::open(&path).expect("open database");
            connection
                .execute(mutation, [])
                .unwrap_or_else(|error| panic!("scenario {scenario} mutation failed: {error}"));
            drop(connection);

            let result = DurableAuditSink::open(
                &path,
                0,
                key(0x51),
                ManagementAuditRetention::try_new(RETAIN_ALL).expect("retention"),
            )
            .await;
            expect_verification_failure_at(result, expected_failure, Some(1));
        }
    }

    #[tokio::test]
    async fn retention_reconfiguration_cannot_prune_away_prior_tampering() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = database(&tempdir);
        create_records(&path, 4, RETAIN_ALL).await;
        let connection = Connection::open(&path).expect("open database");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("foreign keys");
        connection
            .execute("DELETE FROM management_audit_event WHERE sequence = 0", [])
            .expect("delete record that a lower cap would prune");
        drop(connection);

        let result = DurableAuditSink::open(
            &path,
            0,
            key(0x51),
            ManagementAuditRetention::try_new(1).expect("lower retention"),
        )
        .await;
        expect_verification_failure_at(
            result,
            ManagementAuditVerificationFailure::Sequence,
            Some(0),
        );
    }

    #[tokio::test]
    async fn one_at_a_time_retention_cannot_hide_post_open_interior_tampering() {
        for (scenario, expected_failure) in [
            (
                "alter",
                ManagementAuditVerificationFailure::RecordAuthentication,
            ),
            ("delete", ManagementAuditVerificationFailure::Sequence),
        ] {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let path = database(&tempdir);
            let sink = open_sink(&path, 0x51, 3).await;
            for suffix in 0..3 {
                sink.record(&event(AuditOperation::Read, AuditOutcome::Success, suffix))
                    .expect("initial durable record");
            }

            let connection = Connection::open(&path).expect("open database");
            connection
                .pragma_update(None, "foreign_keys", "ON")
                .expect("foreign keys");
            match scenario {
                "alter" => connection
                    .execute(
                        "UPDATE management_audit_event SET principal = 'user:altered' WHERE sequence = 1",
                        [],
                    )
                    .expect("alter next interior row"),
                "delete" => connection
                    .execute("DELETE FROM management_audit_event WHERE sequence = 1", [])
                    .expect("delete next interior row"),
                _ => unreachable!("fixed scenario set"),
            };
            drop(connection);

            // Boundary authentication permits only the already-authenticated
            // sequence zero to be pruned. Sequence one is now low-water and
            // remains present (or detectably absent) for the next append.
            sink.record(&event(AuditOperation::Read, AuditOutcome::Success, 3))
                .expect("first boundary append");
            let connection = Connection::open(&path).expect("inspect database");
            let anchor = connection
                .query_row(
                    "SELECT total_count, retained_count, low_water_sequence FROM management_audit_anchor WHERE id = 1",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
                )
                .expect("anchor");
            assert_eq!(anchor, (4, 3, 1));
            let sequence_zero_exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM management_audit_event WHERE sequence = 0)",
                    [],
                    |row| row.get(0),
                )
                .expect("sequence zero state");
            assert!(!sequence_zero_exists);
            drop(connection);

            let error = sink
                .record(&event(AuditOperation::Read, AuditOutcome::Success, 4))
                .expect_err("tampered low-water must reject the next append");
            assert!(error.detail().contains("persistence failed"));
            match sink.verify() {
                Err(DurableAuditSinkError::Store(ManagementAuditStoreError::Verification(
                    error,
                ))) => {
                    assert_eq!(error.failure(), expected_failure);
                    assert_eq!(error.sequence(), Some(1));
                }
                other => panic!("unexpected verification result for {scenario}: {other:?}"),
            }
            let connection = Connection::open(&path).expect("inspect rejected append");
            let anchor = connection
                .query_row(
                    "SELECT total_count, retained_count, low_water_sequence FROM management_audit_anchor WHERE id = 1",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
                )
                .expect("unchanged anchor");
            assert_eq!(anchor, (4, 3, 1));
            let sequence_four_exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM management_audit_event WHERE sequence = 4)",
                    [],
                    |row| row.get(0),
                )
                .expect("rejected sequence state");
            assert!(!sequence_four_exists);
        }
    }

    #[tokio::test]
    async fn orphan_schema_paths_fail_reopen_verify_query_and_append() {
        for operation in ["reopen", "verify", "query", "append"] {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let path = database(&tempdir);
            create_records(&path, 2, RETAIN_ALL).await;
            let sink = if operation == "reopen" {
                None
            } else {
                Some(open_sink(&path, 0x51, RETAIN_ALL).await)
            };
            let connection = Connection::open(&path).expect("open database");
            connection
                .pragma_update(None, "foreign_keys", "OFF")
                .expect("disable foreign keys");
            connection
                .execute(
                    "INSERT INTO management_audit_schema_path (event_sequence, path_index, schema_path) VALUES (99, 0, '/ietf-system:system')",
                    [],
                )
                .expect("insert orphan path");
            drop(connection);

            match operation {
                "reopen" => expect_verification_failure_at(
                    DurableAuditSink::open(
                        &path,
                        0,
                        key(0x51),
                        ManagementAuditRetention::try_new(RETAIN_ALL).expect("retention"),
                    )
                    .await,
                    ManagementAuditVerificationFailure::MalformedRecord,
                    Some(99),
                ),
                "verify" => match sink.as_ref().expect("sink").verify() {
                    Err(DurableAuditSinkError::Store(ManagementAuditStoreError::Verification(
                        error,
                    ))) => {
                        assert_eq!(
                            error.failure(),
                            ManagementAuditVerificationFailure::MalformedRecord
                        );
                        assert_eq!(error.sequence(), Some(99));
                    }
                    other => panic!("unexpected verify result: {other:?}"),
                },
                "query" => {
                    match sink.as_ref().expect("sink").query_page(
                        ManagementAuditPageRequest::try_new(None, 1).expect("page request"),
                    ) {
                        Err(DurableAuditSinkError::Store(
                            ManagementAuditStoreError::Verification(error),
                        )) => {
                            assert_eq!(
                                error.failure(),
                                ManagementAuditVerificationFailure::MalformedRecord
                            );
                            assert_eq!(error.sequence(), Some(99));
                        }
                        other => panic!("unexpected query result: {other:?}"),
                    }
                }
                "append" => {
                    let sink = sink.as_ref().expect("sink");
                    let error = sink
                        .record(&event(AuditOperation::Read, AuditOutcome::Success, 3))
                        .expect_err("orphan path must reject append");
                    assert!(error.detail().contains("persistence failed"));
                    match sink.verify() {
                        Err(DurableAuditSinkError::Store(
                            ManagementAuditStoreError::Verification(error),
                        )) => {
                            assert_eq!(
                                error.failure(),
                                ManagementAuditVerificationFailure::MalformedRecord
                            );
                            assert_eq!(error.sequence(), Some(99));
                        }
                        other => panic!("unexpected post-append verification: {other:?}"),
                    }
                }
                _ => unreachable!("fixed operation set"),
            }
        }
    }

    #[tokio::test]
    async fn malformed_sqlite_values_report_typed_first_breaks() {
        let scenarios = [
            (
                "blob-as-event-text",
                "UPDATE management_audit_event SET tenant = x'74656e616e742d61' WHERE sequence = 1",
                ManagementAuditVerificationFailure::MalformedRecord,
                Some(1),
            ),
            (
                "blob-as-utc-seconds",
                "UPDATE management_audit_event SET occurred_at_utc_seconds = x'01' WHERE sequence = 1",
                ManagementAuditVerificationFailure::MalformedRecord,
                Some(1),
            ),
            (
                "nanosecond-out-of-range",
                "UPDATE management_audit_event SET occurred_at_nanosecond = 1000000000 WHERE sequence = 1",
                ManagementAuditVerificationFailure::MalformedRecord,
                Some(1),
            ),
            (
                "negative-monotonic-sequence",
                "UPDATE management_audit_event SET occurred_at_monotonic_sequence = -1 WHERE sequence = 1",
                ManagementAuditVerificationFailure::MalformedRecord,
                Some(1),
            ),
            (
                "blob-as-time-source",
                "UPDATE management_audit_event SET occurred_at_time_source = x'6e6f64652d636c6f636b' WHERE sequence = 1",
                ManagementAuditVerificationFailure::MalformedRecord,
                Some(1),
            ),
            (
                "unknown-time-source",
                "UPDATE management_audit_event SET occurred_at_time_source = 'unknown-clock' WHERE sequence = 1",
                ManagementAuditVerificationFailure::MalformedRecord,
                Some(1),
            ),
            (
                "text-as-event-hash",
                "UPDATE management_audit_event SET previous_hash = CAST(zeroblob(32) AS TEXT) WHERE sequence = 1",
                ManagementAuditVerificationFailure::MalformedRecord,
                Some(1),
            ),
            (
                "invalid-event-utf8",
                "UPDATE management_audit_event SET tenant = CAST(x'80' AS TEXT) WHERE sequence = 1",
                ManagementAuditVerificationFailure::MalformedRecord,
                Some(1),
            ),
            (
                "oversized-event-text",
                "UPDATE management_audit_event SET tenant = CAST(zeroblob(257) AS TEXT) WHERE sequence = 1",
                ManagementAuditVerificationFailure::MalformedRecord,
                Some(1),
            ),
            (
                "blob-as-path-text",
                "UPDATE management_audit_schema_path SET schema_path = x'2f61' WHERE event_sequence = 1 AND path_index = 0",
                ManagementAuditVerificationFailure::MalformedRecord,
                Some(1),
            ),
            (
                "invalid-path-utf8",
                "UPDATE management_audit_schema_path SET schema_path = CAST(x'80' AS TEXT) WHERE event_sequence = 1 AND path_index = 0",
                ManagementAuditVerificationFailure::MalformedRecord,
                Some(1),
            ),
            (
                "oversized-path-text",
                "UPDATE management_audit_schema_path SET schema_path = CAST(zeroblob(4097) AS TEXT) WHERE event_sequence = 1 AND path_index = 0",
                ManagementAuditVerificationFailure::MalformedRecord,
                Some(1),
            ),
            (
                "negative-sequence",
                "UPDATE management_audit_event SET sequence = -1 WHERE sequence = 0; UPDATE management_audit_schema_path SET event_sequence = -1 WHERE event_sequence = 0",
                ManagementAuditVerificationFailure::Sequence,
                Some(0),
            ),
            (
                "text-as-anchor-hash",
                "UPDATE management_audit_anchor SET terminal_hash = CAST(zeroblob(32) AS TEXT) WHERE id = 1",
                ManagementAuditVerificationFailure::MalformedAnchor,
                None,
            ),
            (
                "blob-as-anchor-format-version",
                "UPDATE management_audit_anchor SET format_version = x'01' WHERE id = 1",
                ManagementAuditVerificationFailure::MalformedAnchor,
                None,
            ),
            (
                "blob-as-anchor-integer",
                "UPDATE management_audit_anchor SET total_count = x'02' WHERE id = 1",
                ManagementAuditVerificationFailure::MalformedAnchor,
                None,
            ),
            (
                "oversized-anchor-hash",
                "UPDATE management_audit_anchor SET anchor_hmac = zeroblob(33) WHERE id = 1",
                ManagementAuditVerificationFailure::MalformedAnchor,
                None,
            ),
        ];

        for (scenario, mutation, expected_failure, expected_sequence) in scenarios {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let path = database(&tempdir);
            create_records(&path, 2, RETAIN_ALL).await;
            let connection = Connection::open(&path).expect("open database");
            connection
                .execute_batch(&format!(
                    "PRAGMA foreign_keys = OFF; PRAGMA ignore_check_constraints = ON; {mutation};"
                ))
                .unwrap_or_else(|error| panic!("scenario {scenario} mutation failed: {error}"));
            drop(connection);

            expect_verification_failure_at(
                DurableAuditSink::open(
                    &path,
                    0,
                    key(0x51),
                    ManagementAuditRetention::try_new(RETAIN_ALL).expect("retention"),
                )
                .await,
                expected_failure,
                expected_sequence,
            );
        }
    }

    #[tokio::test]
    async fn detects_anchor_mutation_and_anchor_row_disagreement() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = database(&tempdir);
        create_records(&path, 2, RETAIN_ALL).await;
        let connection = Connection::open(&path).expect("open database");
        connection
            .execute(
                "UPDATE management_audit_anchor SET key_epoch = key_epoch + 1 WHERE id = 1",
                [],
            )
            .expect("mutate anchor");
        drop(connection);
        let result = DurableAuditSink::open(
            &path,
            0,
            key(0x51),
            ManagementAuditRetention::try_new(RETAIN_ALL).expect("retention"),
        )
        .await;
        expect_verification_failure(
            result,
            ManagementAuditVerificationFailure::AnchorAuthentication,
        );

        let rollback_dir = tempfile::tempdir().expect("tempdir");
        let rollback_path = database(&rollback_dir);
        create_records(&rollback_path, 2, RETAIN_ALL).await;
        let connection = Connection::open(&rollback_path).expect("open database");
        let saved_anchor = connection
            .query_row(
                "SELECT format_version, retention_max_records, key_epoch, total_count, retained_count, low_water_sequence, low_water_hash, terminal_sequence, terminal_hash, anchor_hmac \
                 FROM management_audit_anchor WHERE id = 1",
                [],
                |row| {
                    (0..10)
                        .map(|index| row.get::<_, rusqlite::types::Value>(index))
                        .collect::<Result<Vec<_>, _>>()
                },
            )
            .expect("save anchor");
        drop(connection);
        let sink = open_sink(&rollback_path, 0x51, RETAIN_ALL).await;
        sink.record(&event(AuditOperation::Read, AuditOutcome::Success, 9))
            .expect("append after saved anchor");
        drop(sink);
        let connection = Connection::open(&rollback_path).expect("open database");
        connection
            .execute("DELETE FROM management_audit_anchor", [])
            .expect("remove current anchor");
        connection
            .execute(
                "INSERT INTO management_audit_anchor \
                 (id, format_version, retention_max_records, key_epoch, total_count, retained_count, low_water_sequence, low_water_hash, terminal_sequence, terminal_hash, anchor_hmac) \
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params_from_iter(saved_anchor),
            )
            .expect("restore prior authenticated anchor");
        drop(connection);
        let result = DurableAuditSink::open(
            &rollback_path,
            0,
            key(0x51),
            ManagementAuditRetention::try_new(RETAIN_ALL).expect("retention"),
        )
        .await;
        assert!(matches!(
            result,
            Err(DurableAuditSinkError::Store(
                ManagementAuditStoreError::Verification(_)
            ))
        ));
    }

    #[test]
    fn public_error_debug_redacts_backend_sources() {
        use std::error::Error as _;

        let canary = "customer-secret-path-canary";
        let error = DurableAuditSinkError::Backend(PersistError::sqlite(format!(
            "/var/lib/{canary}/management.db"
        )));
        let rendered = format!("{error:?}");
        assert!(!rendered.contains(canary));
        assert!(!rendered.contains("/var/lib"));
        assert!(rendered.contains("Backend"));
        assert!(error.source().is_some(), "typed source remains available");
    }

    #[tokio::test]
    async fn stalled_worker_bounds_acknowledgement_and_shutdown() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = database(&tempdir);
        let retention = ManagementAuditRetention::try_new(RETAIN_ALL).expect("retention");
        let backend = SqliteBackend::open_with_audit_key(&path, false, 0, key(0x51))
            .await
            .expect("durable backend");
        let short_bound = Duration::from_millis(25);
        let sink = DurableAuditSink::from_backend_with_timeouts(
            backend,
            retention,
            short_bound,
            short_bound,
        )
        .await
        .expect("durable sink");

        let stall_started = std::time::Instant::now();
        assert!(matches!(
            sink.stall_worker(Duration::from_millis(200)),
            Err(DurableAuditSinkError::AcknowledgementTimeout)
        ));
        assert!(stall_started.elapsed() < Duration::from_millis(150));

        let record_started = std::time::Instant::now();
        let error = sink
            .record(&event(AuditOperation::Read, AuditOutcome::Success, 7))
            .expect_err("stalled acknowledgement must fail closed");
        assert!(error.detail().contains("outcome is unknown"));
        assert!(record_started.elapsed() < Duration::from_millis(150));

        let detachments_before = durable_audit_worker_detachments();
        let shutdown_started = std::time::Instant::now();
        drop(sink);
        assert!(shutdown_started.elapsed() < Duration::from_millis(150));
        assert!(durable_audit_worker_detachments() > detachments_before);

        // The timed-out append was already admitted. It is allowed to commit,
        // but the caller correctly received no success acknowledgement.
        thread::sleep(Duration::from_millis(250));
        let reopened = open_sink(&path, 0x51, RETAIN_ALL).await;
        assert_eq!(
            reopened
                .verify()
                .expect("verify admitted timed-out append")
                .total_count,
            1
        );
    }

    #[tokio::test]
    async fn bounded_worker_queue_reports_queue_full_deterministically() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = database(&tempdir);
        let retention = ManagementAuditRetention::try_new(RETAIN_ALL).expect("retention");
        let backend = SqliteBackend::open_with_audit_key(&path, false, 0, key(0x51))
            .await
            .expect("durable backend");
        let sink = DurableAuditSink::from_backend_with_timeouts(
            backend,
            retention,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .expect("durable sink");
        let sender = sink.sender.as_ref().expect("worker sender").clone();
        let hold = sink
            .hold_worker_for_testing(Duration::from_secs(1))
            .await
            .expect("worker hold");

        let mut verification_receivers = Vec::with_capacity(DURABLE_AUDIT_QUEUE_CAPACITY);
        for _ in 0..DURABLE_AUDIT_QUEUE_CAPACITY {
            let (reply_sender, reply_receiver) = mpsc::sync_channel(1);
            assert!(sender
                .try_send(WorkerRequest {
                    command: WorkerCommand::Verify,
                    reply_sender: WorkerReplySender::Synchronous(reply_sender),
                })
                .is_ok());
            verification_receivers.push(reply_receiver);
        }

        let error = sink
            .record(&event(AuditOperation::Read, AuditOutcome::Success, 9))
            .expect_err("full queue must reject admission");
        assert!(error.detail().contains("queue is full"));
        let async_error = sink
            .record_async(&event(AuditOperation::Read, AuditOutcome::Success, 10))
            .await
            .expect_err("full queue must reject async admission");
        assert_eq!(async_error, error);

        hold.release();
        for reply_receiver in verification_receivers {
            assert!(matches!(
                reply_receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("verification reply"),
                Ok(WorkerReply::Verified(_))
            ));
        }
        assert_eq!(sink.verify().expect("worker drained").total_count, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_async_record_keeps_current_thread_runtime_live() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let sink = open_sink(&database(&tempdir), 0x51, RETAIN_ALL).await;
        let hold = sink
            .hold_worker_for_testing(Duration::from_secs(1))
            .await
            .expect("worker hold");
        let heartbeat = Arc::new(AtomicBool::new(false));
        let audit_event = event(AuditOperation::Read, AuditOutcome::Success, 11);

        let record = async {
            sink.record_async(&audit_event)
                .await
                .expect("durable async acknowledgement");
            assert!(
                heartbeat.load(Ordering::Acquire),
                "record_async parked the current-thread runtime"
            );
        };
        let release = {
            let heartbeat = Arc::clone(&heartbeat);
            async move {
                tokio::task::yield_now().await;
                heartbeat.store(true, Ordering::Release);
                hold.release();
            }
        };
        tokio::join!(record, release);

        assert_eq!(sink.verify().expect("verified async append").total_count, 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_after_admission_does_not_retract_append() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let sink = Arc::new(open_sink(&database(&tempdir), 0x51, RETAIN_ALL).await);
        let hold = sink
            .hold_worker_for_testing(Duration::from_secs(1))
            .await
            .expect("worker hold");
        let (admitted_sender, admitted_receiver) = tokio::sync::oneshot::channel();
        let task_sink = Arc::clone(&sink);
        let task = tokio::spawn(async move {
            let audit_event = event(AuditOperation::Update, AuditOutcome::Success, 12);
            task_sink
                .record_async_with_admission(&audit_event, admitted_sender)
                .await
        });

        admitted_receiver.await.expect("append admitted");
        task.abort();
        assert!(task.await.expect_err("cancelled task").is_cancelled());
        hold.release();

        assert_eq!(
            sink.verify()
                .expect("cancelled caller's admitted append persisted")
                .total_count,
            1
        );
        sink.record_async(&event(AuditOperation::Read, AuditOutcome::Success, 13))
            .await
            .expect("worker remains usable after acknowledgement receiver drop");
        assert_eq!(sink.verify().expect("verified follow-up").total_count, 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_async_acknowledgements_are_request_unique() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let sink = Arc::new(open_sink(&database(&tempdir), 0x51, RETAIN_ALL).await);
        let mut tasks = Vec::new();
        for suffix in 0..16 {
            let task_sink = Arc::clone(&sink);
            tasks.push(tokio::spawn(async move {
                let audit_event = event(AuditOperation::Read, AuditOutcome::Success, suffix);
                let request_id = *audit_event.request_id.as_uuid().as_bytes();
                task_sink
                    .record_async(&audit_event)
                    .await
                    .expect("request-specific acknowledgement");
                request_id
            }));
        }
        let mut expected = Vec::new();
        for task in tasks {
            expected.push(task.await.expect("async record task"));
        }

        let page = sink
            .query_page(ManagementAuditPageRequest::try_new(None, 32).expect("page request"))
            .expect("authenticated page");
        let actual = page
            .records()
            .iter()
            .map(|record| *record.event().request_id())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(actual.len(), expected.len());
        assert!(expected
            .into_iter()
            .all(|request_id| actual.contains(&request_id)));
    }

    #[tokio::test]
    async fn malformed_event_failure_matches_sync_and_async_paths() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let sink = open_sink(&database(&tempdir), 0x51, RETAIN_ALL).await;
        let mut malformed = event(AuditOperation::Read, AuditOutcome::Success, 14);
        malformed.tenant = "x".repeat(301);

        let sync_error = sink.record(&malformed).expect_err("sync rejection");
        let async_error = sink
            .record_async(&malformed)
            .await
            .expect_err("async rejection");
        assert_eq!(async_error, sync_error);
        assert_eq!(sink.verify().expect("no malformed records").total_count, 0);
    }

    #[test]
    fn async_record_without_tokio_runtime_fails_before_admission() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("bootstrap runtime");
        let sink = runtime.block_on(open_sink(&database(&tempdir), 0x51, RETAIN_ALL));
        drop(runtime);

        let audit_event = event(AuditOperation::Read, AuditOutcome::Success, 15);
        let error = futures_executor::block_on(sink.record_async(&audit_event))
            .expect_err("missing Tokio runtime must fail closed");
        assert!(error.detail().contains("worker unavailable"));
        assert_eq!(
            sink.verify().expect("request was not admitted").total_count,
            0
        );
    }

    #[test]
    fn async_record_without_time_driver_fails_before_admission() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let bootstrap = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("bootstrap runtime");
        let sink = bootstrap.block_on(open_sink(&database(&tempdir), 0x51, RETAIN_ALL));
        drop(bootstrap);
        let runtime_without_time = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime without time");
        let audit_event = event(AuditOperation::Read, AuditOutcome::Success, 16);

        let error = runtime_without_time
            .block_on(sink.record_async(&audit_event))
            .expect_err("missing time driver must fail closed");
        assert!(error.detail().contains("worker unavailable"));
        assert_eq!(
            sink.verify().expect("request was not admitted").total_count,
            0
        );
    }

    #[tokio::test]
    async fn testing_timeouts_are_clamped_but_zero_is_preserved() {
        assert_eq!(
            clamp_testing_timeout(Duration::MAX),
            DURABLE_AUDIT_TESTING_HOLD_MAX_DURATION
        );
        assert_eq!(clamp_testing_timeout(Duration::ZERO), Duration::ZERO);

        let tempdir = tempfile::tempdir().expect("tempdir");
        let backend = SqliteBackend::open_with_audit_key(database(&tempdir), false, 0, key(0x51))
            .await
            .expect("durable backend");
        let sink = DurableAuditSink::from_backend_with_timeouts(
            backend,
            ManagementAuditRetention::try_new(RETAIN_ALL).expect("retention"),
            Duration::MAX,
            Duration::MAX,
        )
        .await
        .expect("durable sink");
        assert_eq!(
            sink.acknowledgement_timeout,
            DURABLE_AUDIT_TESTING_HOLD_MAX_DURATION
        );
        assert_eq!(
            sink.shutdown_timeout,
            DURABLE_AUDIT_TESTING_HOLD_MAX_DURATION
        );
    }

    #[tokio::test]
    async fn acknowledgement_timeout_matches_sync_and_async_outcome_unknown_semantics() {
        let sync_tempdir = tempfile::tempdir().expect("sync tempdir");
        let sync_path = database(&sync_tempdir);
        let sync_backend = SqliteBackend::open_with_audit_key(&sync_path, false, 0, key(0x51))
            .await
            .expect("sync durable backend");
        let sync_sink = DurableAuditSink::from_backend_with_timeouts(
            sync_backend,
            ManagementAuditRetention::try_new(RETAIN_ALL).expect("retention"),
            Duration::from_millis(20),
            Duration::from_secs(1),
        )
        .await
        .expect("sync sink");
        let sync_hold = sync_sink
            .hold_worker_for_testing(Duration::from_secs(1))
            .await
            .expect("sync worker hold");
        let sync_error = sync_sink
            .record(&event(AuditOperation::Read, AuditOutcome::Success, 17))
            .expect_err("sync acknowledgement timeout");
        sync_hold.release();
        drop(sync_sink);
        let sync_reopened = open_sink(&sync_path, 0x51, RETAIN_ALL).await;
        assert_eq!(
            sync_reopened
                .verify()
                .expect("sync timed-out append eventually persisted")
                .total_count,
            1
        );

        let async_tempdir = tempfile::tempdir().expect("async tempdir");
        let async_path = database(&async_tempdir);
        let async_backend = SqliteBackend::open_with_audit_key(&async_path, false, 0, key(0x52))
            .await
            .expect("async durable backend");
        let async_sink = DurableAuditSink::from_backend_with_timeouts(
            async_backend,
            ManagementAuditRetention::try_new(RETAIN_ALL).expect("retention"),
            Duration::from_millis(20),
            Duration::from_secs(1),
        )
        .await
        .expect("async sink");
        let async_hold = async_sink
            .hold_worker_for_testing(Duration::from_secs(1))
            .await
            .expect("async worker hold");
        let async_error = async_sink
            .record_async(&event(AuditOperation::Read, AuditOutcome::Success, 18))
            .await
            .expect_err("async acknowledgement timeout");
        async_hold.release();
        drop(async_sink);
        let async_reopened = open_sink(&async_path, 0x52, RETAIN_ALL).await;
        assert_eq!(
            async_reopened
                .verify()
                .expect("async timed-out append eventually persisted")
                .total_count,
            1
        );

        assert_eq!(async_error, sync_error);
        assert!(async_error.detail().contains("outcome is unknown"));
    }

    #[tokio::test]
    async fn durable_schema_has_no_payload_or_free_form_error_column() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = database(&tempdir);
        create_records(&path, 1, RETAIN_ALL).await;
        let connection = Connection::open(path).expect("open database");
        let mut statement = connection
            .prepare("PRAGMA table_info(management_audit_event)")
            .expect("table info");
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .expect("column query")
            .collect::<Result<Vec<_>, _>>()
            .expect("columns");
        assert_eq!(
            columns,
            vec![
                "sequence",
                "request_id",
                "tenant",
                "principal",
                "transport",
                "operation",
                "outcome",
                "reason",
                "schema_path_count",
                "tx_id",
                "previous_hash",
                "entry_hmac",
                "occurred_at_utc_seconds",
                "occurred_at_nanosecond",
                "occurred_at_monotonic_sequence",
                "occurred_at_time_source",
            ]
        );

        let mut path_statement = connection
            .prepare("PRAGMA table_info(management_audit_schema_path)")
            .expect("path table info");
        let path_columns = path_statement
            .query_map([], |row| row.get::<_, String>(1))
            .expect("path column query")
            .collect::<Result<Vec<_>, _>>()
            .expect("path columns");
        assert_eq!(
            path_columns,
            vec!["event_sequence", "path_index", "schema_path"]
        );

        let persisted_time: (String, i64, String, i64, String, i64, String, String) = connection
            .query_row(
                "SELECT typeof(occurred_at_utc_seconds), occurred_at_utc_seconds, \
                        typeof(occurred_at_nanosecond), occurred_at_nanosecond, \
                        typeof(occurred_at_monotonic_sequence), occurred_at_monotonic_sequence, \
                        typeof(occurred_at_time_source), occurred_at_time_source \
                 FROM management_audit_event WHERE sequence = 0",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .expect("persisted time fields");
        assert_eq!(
            persisted_time,
            (
                "integer".to_string(),
                1_700_000_000,
                "integer".to_string(),
                0,
                "integer".to_string(),
                1,
                "text".to_string(),
                "node-clock".to_string(),
            )
        );
        let format_version: i64 = connection
            .query_row(
                "SELECT format_version FROM management_audit_anchor WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .expect("format version");
        assert_eq!(format_version, 2);
    }
}
