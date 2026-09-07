//! Acceptance tests for issue #633 (`opc-runtime: prevent shutdown log
//! amplification`).
//!
//! Shutdown request state is monotonic and idempotent, and observability must
//! reflect effective transitions rather than API call counts. Token mutations
//! ([`ShutdownToken::request_shutdown`] / [`ShutdownToken::cancel`]) are
//! silent and return a closed, value-free [`ShutdownDisposition`]; the
//! supervisor owns the initiation record: the first non-immediate aggregate
//! drain emits exactly one aggregate `shutdown requested` event through a
//! linearized gate, regardless of task count, racing callers, or prior token
//! requests.
//!
//! Every test here installs a value-free recording [`tracing::Subscriber`]
//! and asserts FIXED event counts. The recorder captures only event metadata
//! (level, target, message, and field name/value strings) — no task payload,
//! peer, subscriber, address, key, packet, mutation, or descriptor value is
//! required to assert the contract. Tests additionally plant canary markers in
//! task names and assert the canary never reaches a shutdown initiation
//! record.

use opc_runtime::shutdown::DrainGuard;
use opc_runtime::{
    Builder, Criticality, RestartPolicy, RuntimeProfile, ShutdownDisposition, ShutdownPhase,
    ShutdownPolicy, ShutdownToken, Supervisor, TaskKind, TaskName,
};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SHUTDOWN_REQUESTED: &str = "shutdown requested";
const OLD_CANCELLATION_EVENT: &str = "shutdown cancellation requested";
const DRAIN_TRANSITION_EVENT: &str = "drain phase transition";

// =============================================================================
// Value-free event recording harness
// =============================================================================

/// One captured tracing event: metadata plus rendered field name/value pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedEvent {
    level: String,
    target: String,
    message: String,
    fields: Vec<(String, String)>,
}

/// Records every event dispatched to it. A cheap clone handle around shared
/// state, so one recorder can be installed as a thread-local default (which
/// takes ownership) while races on other threads and the test assertions all
/// audit the same capture.
#[derive(Clone, Default)]
struct EventRecorder {
    events: Arc<Mutex<Vec<RecordedEvent>>>,
}

struct FieldVisitor {
    message: String,
    fields: Vec<(String, String)>,
}

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let rendered = normalize_debug(&format!("{value:?}"));
        if field.name() == "message" {
            self.message = rendered;
        } else {
            self.fields.push((field.name().to_string(), rendered));
        }
    }
}

/// `Debug` rendering of `format_args!` and display-wrapped values is already
/// unquoted, but string values recorded through `record_debug` carry quotes;
/// strip them so assertions compare against plain text.
fn normalize_debug(rendered: &str) -> String {
    let trimmed = rendered.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

impl tracing::Subscriber for EventRecorder {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        // Spans are irrelevant to event-count assertions; hand back a
        // constant id and never track span lifecycles.
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = FieldVisitor {
            message: String::new(),
            fields: Vec::new(),
        };
        event.record(&mut visitor);
        let recorded = RecordedEvent {
            level: event.metadata().level().to_string(),
            target: event.metadata().target().to_string(),
            message: visitor.message,
            fields: visitor.fields,
        };
        self.events
            .lock()
            .expect("recorder lock is never held across panics")
            .push(recorded);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }
}

impl EventRecorder {
    fn events(&self) -> Vec<RecordedEvent> {
        self.events
            .lock()
            .expect("recorder lock is never held across panics")
            .clone()
    }

    fn events_with_message(&self, message: &str) -> Vec<RecordedEvent> {
        self.events()
            .into_iter()
            .filter(|event| event.message == message)
            .collect()
    }
}

/// Run a synchronous body with the recorder installed as the thread-local
/// default subscriber.
fn record_sync<T>(body: impl FnOnce(EventRecorder) -> T) -> T {
    let recorder = EventRecorder::default();
    let body_recorder = recorder.clone();
    tracing::subscriber::with_default(recorder, move || body(body_recorder))
}

/// Run an async body on a current-thread runtime with the recorder installed
/// as the thread-local default subscriber. The current-thread runtime keeps
/// every spawned task on the test thread, so all emitted events are captured.
fn record_async<Fut, T>(body: impl FnOnce(EventRecorder) -> Fut) -> T
where
    Fut: Future<Output = T>,
{
    let recorder = EventRecorder::default();
    let body_recorder = recorder.clone();
    tracing::subscriber::with_default(recorder, move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        runtime.block_on(body(body_recorder))
    })
}

/// Assert no shutdown initiation record (aggregate or drain-phase) carries the
/// canary in its message, target, or any field. Pre-existing supervisor debug
/// records outside the initiation contract are not part of this audit.
fn assert_no_initiation_value_leaks(recorder: &EventRecorder, canary: &str) {
    for event in recorder.events() {
        if event.message != SHUTDOWN_REQUESTED && event.message != DRAIN_TRANSITION_EVENT {
            continue;
        }
        assert!(
            !event.message.contains(canary),
            "initiation record message must stay value-free: {event:?}"
        );
        assert!(
            !event.target.contains(canary),
            "initiation record target must stay value-free: {event:?}"
        );
        for (name, value) in &event.fields {
            assert!(
                !name.contains(canary) && !value.contains(canary),
                "initiation record fields must stay value-free: {event:?}"
            );
        }
    }
}

// =============================================================================
// Supervisor test helpers
// =============================================================================

fn make_supervisor() -> (Supervisor, ShutdownToken) {
    let token = ShutdownToken::new();
    let supervisor = Supervisor::new(RuntimeProfile::conformance("test-nf"), token.clone());
    (supervisor, token)
}

/// Spawn an inert task that exits cleanly as soon as its own task shutdown
/// token is requested — the cooperative drain shape used across the runtime.
async fn spawn_inert_task(supervisor: &Supervisor, name: &str) {
    let lookup = supervisor.clone();
    let task_name = TaskName::new(name);
    let spawned = task_name.clone();
    supervisor
        .spawn(
            task_name,
            TaskKind::ProtocolWorker,
            Criticality::Degrade,
            RestartPolicy::no_restart(),
            move || {
                let lookup = lookup.clone();
                let spawned = spawned.clone();
                Box::pin(async move {
                    let token = lookup
                        .task_shutdown_token(&spawned)
                        .await
                        .expect("task token exists while its task runs");
                    token.shutdown_acknowledged().await;
                    Ok(())
                }) as _
            },
        )
        .await
        .expect("inert task spawns");
}

// =============================================================================
// Token level: silent mutations, one initiation per effective transition
// =============================================================================

#[test]
fn repeated_and_concurrent_token_requests_are_silent_with_one_initiation() {
    record_sync(|recorder| {
        let token = ShutdownToken::new();
        let initiated = Arc::new(AtomicUsize::new(0));

        // Sequential repeats on one clone.
        for _ in 0..8 {
            if token.request_shutdown() == ShutdownDisposition::Initiated {
                initiated.fetch_add(1, Ordering::SeqCst);
            }
        }

        // Concurrent mix of request_shutdown and cancel across token clones;
        // every thread captures into the same recorder, so any regression
        // that re-adds per-call events is caught on any thread.
        std::thread::scope(|scope| {
            for thread in 0..8 {
                let token = token.clone();
                let initiated = Arc::clone(&initiated);
                let recorder = recorder.clone();
                scope.spawn(move || {
                    tracing::subscriber::with_default(recorder, move || {
                        for iteration in 0..250 {
                            let disposition = if (thread + iteration) % 2 == 0 {
                                token.request_shutdown()
                            } else {
                                token.cancel()
                            };
                            if disposition == ShutdownDisposition::Initiated {
                                initiated.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    })
                });
            }
        });

        assert_eq!(
            initiated.load(Ordering::SeqCst),
            1,
            "exactly one invocation may win the effective transition"
        );
        assert!(token.is_shutdown_requested());
        assert_eq!(*token.subscribe().borrow(), ShutdownPhase::Draining);
        assert!(
            recorder.events().is_empty(),
            "token mutations must emit no events, got {:?}",
            recorder.events()
        );
    });
}

#[test]
fn token_cancel_is_silent_and_reports_disposition() {
    record_sync(|recorder| {
        let token = ShutdownToken::new();

        assert_eq!(token.cancel(), ShutdownDisposition::Initiated);
        assert_eq!(token.cancel(), ShutdownDisposition::AlreadyRequested);
        assert_eq!(*token.subscribe().borrow(), ShutdownPhase::Draining);
        assert!(
            recorder.events().is_empty(),
            "cancel must emit no events, got {:?}",
            recorder.events()
        );
    });
}

// =============================================================================
// Supervisor level: one aggregate record per effective shutdown wave
// =============================================================================

#[test]
fn aggregate_drain_emits_exactly_one_initiation_record_regardless_of_task_count() {
    record_async(|recorder| async move {
        let (supervisor, _token) = make_supervisor();
        for index in 0..4 {
            spawn_inert_task(&supervisor, &format!("canary-worker-{index}")).await;
        }
        tokio::task::yield_now().await;

        supervisor.shutdown_all(ShutdownPolicy::Drain).await;

        let records = recorder.events_with_message(SHUTDOWN_REQUESTED);
        assert_eq!(
            records.len(),
            1,
            "one aggregate drain must emit exactly one initiation record, got {records:?}"
        );
        assert_eq!(records[0].level, "INFO");
        assert_eq!(
            records[0].fields,
            vec![("task_count".to_string(), "4".to_string())],
            "the aggregate record carries only the closed task-count field"
        );
        assert_no_initiation_value_leaks(&recorder, "canary");
        assert!(
            recorder
                .events_with_message(OLD_CANCELLATION_EVENT)
                .is_empty(),
            "the legacy per-call cancellation event must be gone"
        );
        // Drains completed within the stock conformance timeouts — the fix
        // does not rely on raising or retuning any deadline.
        assert!(recorder
            .events_with_message("task did not drain gracefully within timeout, aborting")
            .is_empty());
        assert!(recorder
            .events_with_message("task drain timeout exceeded, aborting")
            .is_empty());

        let health = supervisor.health().await;
        assert_eq!(health.task_states.len(), 4);
        assert!(
            health.task_states.values().all(|state| !state.running),
            "every task must have drained"
        );
    });
}

#[test]
fn repeated_aggregate_drains_do_not_emit_further_records() {
    record_async(|recorder| async move {
        let (supervisor, _token) = make_supervisor();
        spawn_inert_task(&supervisor, "worker-0").await;
        spawn_inert_task(&supervisor, "worker-1").await;
        tokio::task::yield_now().await;

        supervisor.shutdown_all(ShutdownPolicy::Drain).await;
        supervisor.shutdown_all(ShutdownPolicy::Drain).await;
        supervisor.shutdown_all(ShutdownPolicy::Drain).await;

        assert_eq!(
            recorder.events_with_message(SHUTDOWN_REQUESTED).len(),
            1,
            "repeat drains that initiate nothing must emit no further records"
        );
    });
}

#[test]
fn aggregate_drain_records_once_even_when_every_token_pre_requested() {
    record_async(|recorder| async move {
        let (supervisor, token) = make_supervisor();
        spawn_inert_task(&supervisor, "worker-0").await;
        spawn_inert_task(&supervisor, "worker-1").await;
        tokio::task::yield_now().await;

        // Pre-initiate every token the aggregate drain would touch: the
        // global token (as `enter_draining` does in the runtime flow) and
        // both task tokens (as standalone drains do).
        token.request_shutdown();
        supervisor
            .shutdown_task(&TaskName::new("worker-0"), ShutdownPolicy::Drain)
            .await;
        supervisor
            .shutdown_task(&TaskName::new("worker-1"), ShutdownPolicy::Drain)
            .await;
        assert_eq!(
            recorder.events_with_message(SHUTDOWN_REQUESTED).len(),
            2,
            "the two standalone task drains record their own initiations"
        );

        supervisor.shutdown_all(ShutdownPolicy::Drain).await;

        let records = recorder.events_with_message(SHUTDOWN_REQUESTED);
        assert_eq!(
            records.len(),
            3,
            "the aggregate drain must record its primary initiation even though \
             every token was already requested, got {records:?}"
        );
        assert_eq!(
            records[2].fields,
            vec![("task_count".to_string(), "2".to_string())]
        );
    });
}

#[test]
fn aggregate_drain_with_no_tasks_records_initiation() {
    record_async(|recorder| async move {
        let (supervisor, _token) = make_supervisor();

        supervisor.shutdown_all(ShutdownPolicy::Drain).await;

        let records = recorder.events_with_message(SHUTDOWN_REQUESTED);
        assert_eq!(
            records.len(),
            1,
            "a zero-task aggregate drain still records its initiation, got {records:?}"
        );
        assert_eq!(
            records[0].fields,
            vec![("task_count".to_string(), "0".to_string())]
        );
    });
}

#[test]
fn concurrent_aggregate_drains_record_exactly_once() {
    record_async(|recorder| async move {
        let (supervisor, _token) = make_supervisor();
        for index in 0..4 {
            spawn_inert_task(&supervisor, &format!("worker-{index}")).await;
        }
        tokio::task::yield_now().await;

        let drains: Vec<_> = (0..3)
            .map(|_| {
                let supervisor = supervisor.clone();
                tokio::spawn(async move {
                    supervisor.shutdown_all(ShutdownPolicy::Drain).await;
                })
            })
            .collect();
        for drain in drains {
            tokio::time::timeout(Duration::from_secs(5), drain)
                .await
                .expect("concurrent drain completes")
                .expect("drain task does not panic");
        }

        let records = recorder.events_with_message(SHUTDOWN_REQUESTED);
        assert_eq!(
            records.len(),
            1,
            "racing aggregate drains must share one initiation record, got {records:?}"
        );
        assert_eq!(
            records[0].fields,
            vec![("task_count".to_string(), "4".to_string())]
        );
    });
}

#[test]
fn aggregate_drain_wakes_phase_subscribers_without_lost_wakeup() {
    record_async(|recorder| async move {
        let (supervisor, token) = make_supervisor();
        spawn_inert_task(&supervisor, "worker-0").await;
        tokio::task::yield_now().await;

        let acknowledged = {
            let token = token.clone();
            tokio::spawn(async move {
                token.shutdown_acknowledged().await;
            })
        };
        let drain_waiter = {
            let token = token.clone();
            tokio::spawn(async move {
                token.wait_for_phase(ShutdownPhase::Draining).await;
            })
        };
        tokio::task::yield_now().await;
        assert!(!acknowledged.is_finished());
        assert!(!drain_waiter.is_finished());

        supervisor.shutdown_all(ShutdownPolicy::Drain).await;

        tokio::time::timeout(Duration::from_secs(2), acknowledged)
            .await
            .expect("shutdown_acknowledged must wake after the aggregate drain")
            .expect("shutdown_acknowledged waiter must not panic");
        tokio::time::timeout(Duration::from_secs(2), drain_waiter)
            .await
            .expect("Draining phase waiters must wake after the aggregate drain")
            .expect("phase waiter must not panic");

        let mut phase_rx = token.subscribe();
        assert_eq!(*phase_rx.borrow_and_update(), ShutdownPhase::Draining);
        assert_eq!(recorder.events_with_message(SHUTDOWN_REQUESTED).len(), 1);
    });
}

#[test]
fn standalone_task_shutdown_records_once_and_needs_no_second_transition() {
    record_async(|recorder| async move {
        let (supervisor, _token) = make_supervisor();
        let name = TaskName::new("worker-0");
        spawn_inert_task(&supervisor, &name.0).await;
        tokio::task::yield_now().await;

        supervisor.shutdown_task(&name, ShutdownPolicy::Drain).await;

        let records = recorder.events_with_message(SHUTDOWN_REQUESTED);
        assert_eq!(
            records.len(),
            1,
            "a standalone task shutdown must record exactly one initiation, got {records:?}"
        );
        assert!(
            records[0].fields.is_empty(),
            "the standalone record must stay value-free"
        );

        let health = supervisor.health().await;
        assert!(
            health.task_states.values().all(|state| !state.running),
            "the task must have drained"
        );

        // Requesting the same task again must not require — or produce — a
        // second effective transition.
        supervisor.shutdown_task(&name, ShutdownPolicy::Drain).await;
        assert_eq!(
            recorder.events_with_message(SHUTDOWN_REQUESTED).len(),
            1,
            "repeat standalone shutdown must not emit further records"
        );
    });
}

#[test]
fn immediate_shutdown_emits_no_initiation_record() {
    record_async(|recorder| async move {
        let (supervisor, _token) = make_supervisor();
        spawn_inert_task(&supervisor, "worker-0").await;
        tokio::task::yield_now().await;

        supervisor.shutdown_all(ShutdownPolicy::Immediate).await;

        assert!(
            recorder.events_with_message(SHUTDOWN_REQUESTED).is_empty(),
            "immediate shutdown requests nothing and must record nothing"
        );
    });
}

// =============================================================================
// Runtime level: one primary shutdown record end to end
// =============================================================================

/// Runtime-level tests register process-wide signal handlers through
/// `Builder::build`; serialize them so only one runtime exists at a time.
static RUNTIME_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn runtime_shutdown_produces_one_primary_initiation_record() {
    let _serial = RUNTIME_SERIAL
        .lock()
        .expect("runtime serial lock is never held across panics");

    record_async(|recorder| async move {
        let handle = Builder::new(RuntimeProfile::conformance("test-nf"))
            .try_with_init(move |supervisor, _shutdown| {
                Box::pin(async move {
                    spawn_inert_task(&supervisor, "worker-0").await;
                    spawn_inert_task(&supervisor, "worker-1").await;
                    Ok(())
                })
            })
            .build()
            .await
            .expect("runtime builds");

        handle.shutdown().await;

        let records = recorder.events_with_message(SHUTDOWN_REQUESTED);
        assert_eq!(
            records.len(),
            1,
            "one full runtime shutdown must yield exactly one primary shutdown record, got {records:?}"
        );
        assert_eq!(
            records[0].fields,
            vec![("task_count".to_string(), "2".to_string())],
            "the primary record carries only the closed task-count field"
        );
        assert!(recorder
            .events_with_message(OLD_CANCELLATION_EVENT)
            .is_empty());

        handle.wait_stopped().await;
    });
}

#[test]
fn runtime_shutdown_with_no_tasks_records_primary_initiation() {
    let _serial = RUNTIME_SERIAL
        .lock()
        .expect("runtime serial lock is never held across panics");

    record_async(|recorder| async move {
        let handle = Builder::new(RuntimeProfile::conformance("test-nf"))
            .build()
            .await
            .expect("runtime builds");

        // The runtime pre-initiates its own shutdown token in `enter_draining`
        // before the supervisor drains, and there are no task tokens at all —
        // the aggregate record must still exist for this initiation.
        handle.shutdown().await;

        let records = recorder.events_with_message(SHUTDOWN_REQUESTED);
        assert_eq!(
            records.len(),
            1,
            "a zero-task runtime shutdown must still yield one primary shutdown record, got {records:?}"
        );
        assert_eq!(
            records[0].fields,
            vec![("task_count".to_string(), "0".to_string())]
        );

        handle.wait_stopped().await;
    });
}

// =============================================================================
// DrainGuard: transition events only for effective transitions
// =============================================================================

#[test]
fn drain_guard_records_only_effective_transitions() {
    record_sync(|recorder| {
        let token = ShutdownToken::new();
        let mut guard = DrainGuard::new(token.clone());

        guard.transition(ShutdownPhase::Draining); // effective
        guard.transition(ShutdownPhase::Draining); // repeat: no transition
        guard.transition(ShutdownPhase::Running); // backwards: ignored
        assert_eq!(
            guard.phase(),
            ShutdownPhase::Draining,
            "the guard's observable phase must not regress"
        );
        guard.transition(ShutdownPhase::Stopped); // effective

        let events = recorder.events_with_message(DRAIN_TRANSITION_EVENT);
        assert_eq!(
            events.len(),
            2,
            "only effective transitions may record, got {events:?}"
        );
        assert_eq!(
            events[0].fields,
            vec![
                ("from".to_string(), "Running".to_string()),
                ("to".to_string(), "Draining".to_string()),
            ]
        );
        assert_eq!(
            events[1].fields,
            vec![
                ("from".to_string(), "Draining".to_string()),
                ("to".to_string(), "Stopped".to_string()),
            ]
        );
        assert_eq!(guard.phase(), ShutdownPhase::Stopped);
    });
}
