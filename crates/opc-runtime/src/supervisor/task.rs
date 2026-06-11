use crate::shutdown::ShutdownToken;
use crate::task::{Criticality, RestartPolicy, TaskError, TaskHandle, TaskKind};
use std::time::{Duration, Instant};

/// Task metadata stored by supervisor (task_fn is consumed at spawn time).
#[derive(Debug, Clone)]
pub(crate) struct TaskMetadata {
    pub(crate) kind: TaskKind,
    pub(crate) criticality: Criticality,
    pub(crate) restart: RestartPolicy,
    pub(crate) readiness_gated: bool,
    pub(crate) heartbeat_timeout: Option<Duration>,
}

/// Task state tracked by supervisor.
#[derive(Debug, Clone)]
pub(crate) struct TaskState {
    pub(crate) metadata: TaskMetadata,
    pub(crate) handle: Option<TaskHandle>,
    pub(crate) failures_in_window: u32,
    pub(crate) window_start: Instant,
    pub(crate) last_failure: Option<Instant>,
    pub(crate) last_error: Option<TaskError>,
    pub(crate) is_failed: bool,
    pub(crate) is_ready: bool,
    pub(crate) readiness_gated: bool,
    pub(crate) shutdown: ShutdownToken,
    pub(crate) last_heartbeat: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct TaskStateView {
    pub kind: String,
    pub criticality: String,
    pub running: bool,
    pub restart_count: u32,
}
