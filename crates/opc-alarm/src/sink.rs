//! External fault-management sink integration per RFC 013 §14: the pluggable
//! async `AlarmSink` trait, test (`RecordingSink`) and log-based
//! (`TracingSink`) adapters, and `BoundedAlarmSink`, a bounded-queue wrapper
//! with retries that fails closed (`QueueFull` / `RetryExhausted` /
//! `Shutdown`) instead of blocking, so a sink outage never stalls packet or
//! request handling. Error text surfaced by this module is scrubbed through
//! `opc_redaction` before exposure.

use crate::model::Alarm;
use async_trait::async_trait;
use serde::Serialize;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;
use tokio::sync::mpsc;

/// Errors returned by the alarm delivery sink subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum AlarmSinkError {
    /// Bounded queue has reached its maximum capacity.
    QueueFull,

    /// The downstream sink failed to deliver the alarm event.
    DeliveryFailed(String),

    /// The alarm sink has been shut down or is no longer accepting writes.
    Shutdown,

    /// The retry budget has been exhausted.
    RetryExhausted(String),
}

impl fmt::Display for AlarmSinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull => f.write_str("Sink queue is full"),
            Self::DeliveryFailed(msg) => {
                write!(f, "Sink delivery failed: {}", sanitize_sink_message(msg))
            }
            Self::Shutdown => f.write_str("Sink has shutdown"),
            Self::RetryExhausted(msg) => {
                write!(f, "Retry exhaustion: {}", sanitize_sink_message(msg))
            }
        }
    }
}

impl std::error::Error for AlarmSinkError {}

/// Pluggable asynchronous alarm sink interface per RFC 013 §7.
#[async_trait]
pub trait AlarmSink: Send + Sync {
    /// Publishes a single alarm event.
    async fn send(&self, alarm: Alarm) -> Result<(), AlarmSinkError>;
}

/// An in-memory, concurrent-safe sink for capturing alarms in test scenarios.
#[derive(Debug, Default, Clone)]
pub struct RecordingSink {
    alarms: Arc<Mutex<Vec<Alarm>>>,
}

impl RecordingSink {
    /// Creates a new empty recording sink.
    pub fn new() -> Self {
        Self {
            alarms: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Retrieves all recorded alarms.
    pub fn get_alarms(&self) -> Vec<Alarm> {
        mutex_guard(&self.alarms).clone()
    }

    /// Clears the recorded history.
    pub fn clear(&self) {
        mutex_guard(&self.alarms).clear();
    }
}

#[async_trait]
impl AlarmSink for RecordingSink {
    async fn send(&self, alarm: Alarm) -> Result<(), AlarmSinkError> {
        mutex_guard(&self.alarms).push(alarm);
        Ok(())
    }
}

/// Production-shaped sink adapter that formats alarms as JSON and logs them via `tracing`.
#[derive(Debug, Default)]
pub struct TracingSink;

impl TracingSink {
    /// Creates a new tracing sink.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AlarmSink for TracingSink {
    async fn send(&self, alarm: Alarm) -> Result<(), AlarmSinkError> {
        let serialized = serde_json::to_string(&alarm.redacted_for_export())
            .map_err(|e| AlarmSinkError::DeliveryFailed(e.to_string()))?;
        tracing::warn!(target: "opc_alarm::sink::tracing", alarm = %serialized, "Alarm published");
        Ok(())
    }
}

/// Lifecycle status of the bounded alarm sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkStatus {
    /// Acceptable operations.
    Ok,
    /// Permanent failure because of retry exhaustion.
    Failed,
    /// The sink has shut down.
    Shutdown,
}

/// A wrapper sink that provides bounded queue buffering, backpressure, retries,
/// and fail-closed behavior on queue exhaustion or sink failures.
pub struct BoundedAlarmSink<S: AlarmSink> {
    _inner: Arc<S>,
    tx: mpsc::Sender<Alarm>,
    status: Arc<RwLock<SinkStatus>>,
    last_error: Arc<RwLock<Option<String>>>,
    dropped: Arc<AtomicU64>,
}

impl<S: AlarmSink + 'static> BoundedAlarmSink<S> {
    /// Spawns a background worker thread and initializes the bounded queue.
    pub fn new(inner: S, capacity: usize, max_retries: usize, retry_backoff: Duration) -> Self {
        let inner = Arc::new(inner);
        let capacity = capacity.max(1);
        let (tx, mut rx) = mpsc::channel::<Alarm>(capacity);
        let status = Arc::new(RwLock::new(SinkStatus::Ok));
        let last_error = Arc::new(RwLock::new(None));
        let dropped = Arc::new(AtomicU64::new(0));

        let worker_inner = Arc::clone(&inner);
        let worker_status = Arc::clone(&status);
        let worker_last_error = Arc::clone(&last_error);
        let worker_dropped = Arc::clone(&dropped);

        let worker = async move {
            while let Some(alarm) = rx.recv().await {
                let mut retries = 0;
                loop {
                    match worker_inner.send(alarm.clone()).await {
                        Ok(()) => {
                            break;
                        }
                        Err(e) => {
                            let err_msg = sanitize_sink_error(&e);
                            if retries >= max_retries {
                                record_drop(&worker_last_error, &worker_dropped, err_msg);
                                break;
                            }
                            retries += 1;
                            tokio::time::sleep(retry_backoff).await;
                        }
                    }
                }
            }
            // If the loop finished cleanly (channel closed), set status to Shutdown.
            let mut guard = rw_write(&worker_status);
            if *guard == SinkStatus::Ok {
                *guard = SinkStatus::Shutdown;
            }
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(worker);
        } else {
            let spawn_error_status = Arc::clone(&status);
            let spawn_error_last_error = Arc::clone(&last_error);
            let runtime_error_status = Arc::clone(&status);
            let runtime_error_last_error = Arc::clone(&last_error);
            let spawn_result = std::thread::Builder::new()
                .name("opc-alarm-bounded-sink".to_string())
                .spawn(move || {
                    match tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .build()
                    {
                        Ok(rt) => rt.block_on(worker),
                        Err(err) => record_failure(
                            &runtime_error_status,
                            &runtime_error_last_error,
                            format!("failed to start alarm sink runtime: {err}"),
                        ),
                    }
                });
            if let Err(err) = spawn_result {
                record_failure(
                    &spawn_error_status,
                    &spawn_error_last_error,
                    format!("failed to spawn alarm sink worker: {err}"),
                );
            }
        }

        Self {
            _inner: inner,
            tx,
            status,
            last_error,
            dropped,
        }
    }

    /// Gets the current status of the sink.
    pub fn status(&self) -> SinkStatus {
        *rw_read(&self.status)
    }

    /// Gets the last error that caused a permanent failure.
    pub fn last_error(&self) -> Option<String> {
        rw_read(&self.last_error).clone()
    }

    /// Returns the number of alarms dropped after exhausting their retry budget.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Triggers immediate shutdown of the sink and refuses new write requests.
    pub fn shutdown(&self) {
        let mut guard = rw_write(&self.status);
        if *guard == SinkStatus::Ok {
            *guard = SinkStatus::Shutdown;
        }
    }
}

#[async_trait]
impl<S: AlarmSink + 'static> AlarmSink for BoundedAlarmSink<S> {
    async fn send(&self, alarm: Alarm) -> Result<(), AlarmSinkError> {
        let current_status = *rw_read(&self.status);
        match current_status {
            SinkStatus::Failed => {
                let err_msg = rw_read(&self.last_error).clone().unwrap_or_default();
                return Err(AlarmSinkError::RetryExhausted(err_msg));
            }
            SinkStatus::Shutdown => {
                return Err(AlarmSinkError::Shutdown);
            }
            SinkStatus::Ok => {}
        }

        // Bounded buffering/backpressure: if full, fail-closed.
        match self.tx.try_send(alarm) {
            Ok(()) => match self.status() {
                SinkStatus::Ok => Ok(()),
                SinkStatus::Failed => Err(AlarmSinkError::RetryExhausted(
                    self.last_error().unwrap_or_default(),
                )),
                SinkStatus::Shutdown => Err(AlarmSinkError::Shutdown),
            },
            Err(mpsc::error::TrySendError::Full(_)) => Err(AlarmSinkError::QueueFull),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let current_status = *rw_read(&self.status);
                if current_status == SinkStatus::Failed {
                    let err_msg = rw_read(&self.last_error).clone().unwrap_or_default();
                    Err(AlarmSinkError::RetryExhausted(err_msg))
                } else {
                    Err(AlarmSinkError::Shutdown)
                }
            }
        }
    }
}

fn mutex_guard<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn rw_read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn rw_write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn record_failure(
    status: &RwLock<SinkStatus>,
    last_error: &RwLock<Option<String>>,
    error_message: String,
) {
    *rw_write(last_error) = Some(sanitize_sink_message(&error_message));
    let mut guard = rw_write(status);
    if *guard != SinkStatus::Shutdown {
        *guard = SinkStatus::Failed;
    }
}

fn record_drop(last_error: &RwLock<Option<String>>, dropped: &AtomicU64, error_message: String) {
    *rw_write(last_error) = Some(sanitize_sink_message(&error_message));
    dropped.fetch_add(1, Ordering::Relaxed);
}

fn sanitize_sink_error(error: &AlarmSinkError) -> String {
    sanitize_sink_message(&error.to_string())
}

fn sanitize_sink_message(raw: &str) -> String {
    let mut summary = opc_redaction::RedactionSummary::default();
    let redacted = opc_redaction::redact_text(raw, &mut summary);
    let trimmed = redacted.trim();
    if trimmed.is_empty() {
        "<redacted>".to_string()
    } else {
        trimmed.to_string()
    }
}
