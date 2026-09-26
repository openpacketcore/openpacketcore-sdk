//! Cancellation-safe joining of the one existing ConfigBus worker.
//!
//! This retains a supplied JoinHandle; it never spawns a task or controls a
//! second worker. The worker must already implement close/drain semantics and
//! return a truthful exit value. Requesting shutdown is separate from joining.

use std::sync::Arc;

use tokio::{sync::Mutex, task::JoinHandle};

/// The worker determines this from its original operation/cleanup state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerExit {
    /// All owned work and required completion were reconciled before exit.
    Drained,
    /// Retained recovery must fence serving after an incomplete shutdown.
    RecoveryRequired,
}

/// The task did not return an accounting of its owned work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerLost;

struct JoinState {
    task: Option<JoinHandle<WorkerExit>>,
    result: Option<Result<WorkerExit, WorkerLost>>,
}

/// Shared only by control handles, never by the task it is joining. A cancelled
/// waiter releases the mutex while leaving the task handle in this state.
#[derive(Clone)]
pub(crate) struct WorkerJoin(Arc<Mutex<JoinState>>);

impl WorkerJoin {
    pub(crate) fn new(task: JoinHandle<WorkerExit>) -> Self {
        Self(Arc::new(Mutex::new(JoinState {
            task: Some(task),
            result: None,
        })))
    }

    /// Wait for the actual task, preserving its handle across waiter timeout or
    /// cancellation. Do not take the handle out before awaiting: dropping that
    /// future would then detach the worker and lose the join outcome.
    pub(crate) async fn join(&self) -> Result<WorkerExit, WorkerLost> {
        let mut state = self.0.lock().await;
        if let Some(result) = state.result {
            return result;
        }
        let result = match state.task.as_mut() {
            Some(task) => task.await.map_err(|_| WorkerLost),
            None => Err(WorkerLost),
        };
        state.task = None;
        state.result = Some(result);
        result
    }
}
