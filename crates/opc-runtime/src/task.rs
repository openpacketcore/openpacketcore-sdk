//! Task model for supervised CNF workers.

use thiserror::Error;

/// Task name identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaskName(pub String);

impl TaskName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

impl std::fmt::Display for TaskName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Task kind per RFC 008 section 7.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskKind {
    /// Long-lived listener (e.g., HTTP server, gRPC server).
    Listener,
    /// Protocol worker handling requests.
    ProtocolWorker,
    /// Session worker managing state.
    SessionWorker,
    /// Management-plane worker.
    ManagementWorker,
    /// Background synchronization.
    BackgroundSync,
    /// Metrics exporter.
    MetricsExporter,
    /// Watcher (config watcher, peer watcher).
    Watcher,
    /// Timer-based worker.
    Timer,
}

impl std::fmt::Display for TaskKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskKind::Listener => write!(f, "listener"),
            TaskKind::ProtocolWorker => write!(f, "protocol-worker"),
            TaskKind::SessionWorker => write!(f, "session-worker"),
            TaskKind::ManagementWorker => write!(f, "management-worker"),
            TaskKind::BackgroundSync => write!(f, "background-sync"),
            TaskKind::MetricsExporter => write!(f, "metrics-exporter"),
            TaskKind::Watcher => write!(f, "watcher"),
            TaskKind::Timer => write!(f, "timer"),
        }
    }
}

/// Criticality level for task failure per RFC 008 table in section 7.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Criticality {
    /// Transition CNF to fatal shutdown.
    Fatal,
    /// Mark degraded and optionally restart.
    #[default]
    Degrade,
    /// Log/metric and continue.
    BestEffort,
}

impl std::fmt::Display for Criticality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Criticality::Fatal => write!(f, "fatal"),
            Criticality::Degrade => write!(f, "degrade"),
            Criticality::BestEffort => write!(f, "best-effort"),
        }
    }
}

/// Restart policy for supervised tasks.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RestartPolicy {
    /// Max restarts per time window.
    pub max_restarts: u32,
    /// Window in seconds.
    pub window_secs: u64,
    /// Base backoff in milliseconds.
    pub base_backoff_ms: u64,
    /// Max backoff in milliseconds.
    pub max_backoff_ms: u64,
    /// Jitter factor [0.0, 1.0).
    pub jitter: f64,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_restarts: 3,
            window_secs: 60,
            base_backoff_ms: 100,
            max_backoff_ms: 30_000,
            jitter: 0.1,
        }
    }
}

impl RestartPolicy {
    /// No restart policy — tasks that fail are not restarted.
    pub fn no_restart() -> Self {
        Self {
            max_restarts: 0,
            ..Default::default()
        }
    }

    /// Aggressive restart for critical tasks.
    pub fn aggressive() -> Self {
        Self {
            max_restarts: 10,
            window_secs: 300,
            base_backoff_ms: 50,
            max_backoff_ms: 5_000,
            jitter: 0.15,
        }
    }

    /// Validate the restart policy is bounded and safe in production.
    pub fn validate(&self) -> Result<(), RuntimeError> {
        if self.max_restarts > 50 {
            return Err(RuntimeError::Supervisor(format!(
                "invalid restart policy: max_restarts {} exceeds limit of 50",
                self.max_restarts
            )));
        }
        if self.max_restarts > 0 {
            if self.window_secs == 0 {
                return Err(RuntimeError::Supervisor(
                    "invalid restart policy: window_secs cannot be 0 when max_restarts > 0"
                        .to_string(),
                ));
            }
            if self.base_backoff_ms < 10 {
                return Err(RuntimeError::Supervisor(format!(
                    "invalid restart policy: base_backoff_ms {} must be >= 10ms",
                    self.base_backoff_ms
                )));
            }
        }
        Ok(())
    }
}

/// Shutdown policy for a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShutdownPolicy {
    /// Wait for graceful drain.
    #[default]
    Drain,
    /// Immediate cancellation.
    Immediate,
    /// Wait with a timeout.
    DrainWithTimeout(std::time::Duration),
}

/// Task specification registered with the supervisor.
///
/// `TaskSpec` owns a single future. Use `Supervisor::spawn()` with a task
/// factory for restartable tasks.
pub struct TaskSpec {
    /// Unique task name.
    pub name: TaskName,
    /// Task kind.
    pub kind: TaskKind,
    /// Criticality on failure.
    pub criticality: Criticality,
    /// Restart policy.
    pub restart: RestartPolicy,
    /// Shutdown policy.
    pub shutdown: ShutdownPolicy,
    /// Optional timeout for periodic progress/heartbeat validation.
    pub heartbeat_timeout: Option<std::time::Duration>,
    /// The actual task future.
    pub task_fn: std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TaskError>> + Send>>,
}

impl std::fmt::Debug for TaskSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskSpec")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("criticality", &self.criticality)
            .field("restart", &self.restart)
            .field("shutdown", &self.shutdown)
            .field("heartbeat_timeout", &self.heartbeat_timeout)
            .finish()
    }
}

impl TaskSpec {
    /// Create a new supervised task spec.
    pub fn new(
        name: impl Into<String>,
        kind: TaskKind,
        criticality: Criticality,
        task_fn: impl std::future::Future<Output = Result<(), TaskError>> + Send + 'static,
    ) -> Self {
        Self {
            name: TaskName::new(name),
            kind,
            criticality,
            restart: RestartPolicy::no_restart(),
            shutdown: ShutdownPolicy::default(),
            heartbeat_timeout: None,
            task_fn: Box::pin(task_fn),
        }
    }

    /// Builder-style method to set restart policy.
    pub fn with_restart(mut self, restart: RestartPolicy) -> Self {
        self.restart = restart;
        self
    }

    /// Builder-style method to set shutdown policy.
    pub fn with_shutdown(mut self, shutdown: ShutdownPolicy) -> Self {
        self.shutdown = shutdown;
        self
    }

    /// Builder-style method to set heartbeat timeout.
    pub fn with_heartbeat_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.heartbeat_timeout = Some(timeout);
        self
    }
}

/// Handle to a supervised task.
#[derive(Debug, Clone)]
pub struct TaskHandle {
    pub name: TaskName,
    abort_handle: tokio::task::AbortHandle,
    pub(crate) exit_rx: tokio::sync::watch::Receiver<bool>,
}

impl TaskHandle {
    pub fn new(
        name: TaskName,
        abort_handle: tokio::task::AbortHandle,
        exit_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Self {
        Self {
            name,
            abort_handle,
            exit_rx,
        }
    }

    /// Abort the task.
    pub fn abort(&self) {
        self.abort_handle.abort();
    }

    /// Check if task is still running.
    pub fn is_running(&self) -> bool {
        !self.abort_handle.is_finished()
    }
}

/// Task execution error.
#[derive(Debug, Error)]
pub enum TaskError {
    #[error("task {0} failed: {1}")]
    Failed(
        String,
        #[source] std::sync::Arc<dyn std::error::Error + Send + Sync>,
    ),

    #[error("task {0} was aborted")]
    Aborted(String),

    #[error("task {0} panicked: {1}")]
    Panicked(String, String),
}

impl Clone for TaskError {
    fn clone(&self) -> Self {
        match self {
            TaskError::Failed(task, source) => {
                TaskError::Failed(task.clone(), std::sync::Arc::clone(source))
            }
            TaskError::Aborted(task) => TaskError::Aborted(task.clone()),
            TaskError::Panicked(task, message) => {
                TaskError::Panicked(task.clone(), message.clone())
            }
        }
    }
}

/// Runtime-level errors.
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("bootstrap error: {0}")]
    Bootstrap(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("supervisor error: {0}")]
    Supervisor(String),

    #[error("phase transition error: {0}")]
    PhaseTransition(String),

    #[error("task {0} failed critically: {1}")]
    TaskCriticalFailure(String, TaskError),
}
