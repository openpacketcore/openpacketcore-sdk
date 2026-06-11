use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::supervisor::metrics::raise_fatal_task_alarm;
use crate::supervisor::{FatalTaskFailure, Supervisor, SupervisorRuntimeCtx, TaskState};
use crate::task::{Criticality, RestartPolicy, TaskError, TaskName};

pub(crate) async fn compute_backoff_impl(
    name: &TaskName,
    restart: &RestartPolicy,
    tasks: &Arc<RwLock<HashMap<TaskName, TaskState>>>,
    jitter_source: &RandomState,
) -> Duration {
    let failures = {
        let t = tasks.read().await;
        t.get(name).map(|s| s.failures_in_window).unwrap_or(0)
    };

    // Exponential backoff: base * 2^failures, capped at max_backoff
    let attempts = failures.min(restart.max_restarts);
    let mut backoff_ms = restart.base_backoff_ms;
    for _ in 0..attempts {
        backoff_ms = backoff_ms.saturating_mul(2).min(restart.max_backoff_ms);
    }

    // Apply jitter using a hash-based pseudo-random factor.
    let mut hasher = jitter_source.build_hasher();
    name.hash(&mut hasher);
    (failures as u64).hash(&mut hasher);
    let hash = hasher.finish();
    let jitter = if restart.jitter.is_finite() {
        restart.jitter.clamp(0.0, 0.99)
    } else {
        0.0
    };
    debug_assert!((0.0..1.0).contains(&jitter), "jitter must be in [0.0, 1.0)");
    let jitter_range = jitter * 2.0;
    let jitter_factor = 1.0 - jitter + ((hash as f64 / u64::MAX as f64) * jitter_range);
    let backoff_ms = (backoff_ms as f64 * jitter_factor) as u64;
    Duration::from_millis(backoff_ms.max(1))
}

pub(crate) async fn handle_task_failure_impl(
    supervisor: &Supervisor,
    name: &TaskName,
    criticality: Criticality,
    restart: RestartPolicy,
    error: &TaskError,
    ctx: &SupervisorRuntimeCtx,
) {
    tracing::error!(task = %name, error = %error, criticality = %criticality, "task failed");

    let mut t = ctx.tasks.write().await;
    let state = match t.get_mut(name) {
        Some(s) => s,
        None => return,
    };

    let now = ctx.clock.monotonic();

    // Track failures
    let elapsed = now.duration_since(state.window_start);
    let expired = if restart.window_secs == 0 {
        elapsed > Duration::ZERO
    } else {
        elapsed.as_secs() >= restart.window_secs
    };
    if expired {
        state.failures_in_window = 0;
        state.window_start = now;
    }
    state.failures_in_window += 1;
    state.last_failure = Some(now);
    state.last_error = Some(error.clone());
    let was_failed = state.is_failed;
    state.is_failed = true; // Mark as failed
    state.is_ready = false; // Reset ready status on failure

    drop(t); // Drop the tasks write guard before acquiring fatal_failure locks to prevent lock inversion/deadlocks

    if !was_failed {
        match criticality {
            Criticality::Fatal => {
                let mut ff = ctx.fatal_failure.write().await;
                *ff = true;
                let mut fatal = ctx.fatal_failure_error.write().await;
                if fatal.is_none() {
                    *fatal = Some(FatalTaskFailure {
                        task: name.clone(),
                        error: error.clone(),
                    });
                }
                raise_fatal_task_alarm(&ctx.alarm_manager, &supervisor.profile, name, error);
                tracing::error!(task = %name, "fatal task failure - runtime will shutdown");
                ctx.shutdown.cancel();
            }
            Criticality::Degrade => {
                ctx.degrade_count.fetch_add(1, Ordering::SeqCst);
            }
            Criticality::BestEffort => {
                // Just log - no health impact
            }
        }
    }

    supervisor.notify_state_change();
}
