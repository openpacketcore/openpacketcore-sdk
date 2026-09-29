//! Bounded observations for one explicitly selected scoped-read test future.
//!
//! No keys, identities, SQL, backend error strings or worker ownership escape
//! into a trace. A caller deadline observation is not proof that a timeout
//! fired: only the actual outer `Elapsed` result receives that classification.
//! Task-local context is deliberately not propagated into spawned workers.

use std::future::Future;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::time::{error::Elapsed, Instant};

use super::{LinearizableBarrierFailure, SessionConsumerRejection, StoreError};

const MAX_SPANS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    ConsumerGet,
    InitialAdmission,
    TopologyGate,
    DurableScope,
    SqlScopeConnection,
    SqlScopeGuardAndQuery,
    InitialAuthority,
    ApplicationAuthority,
    ReadBarrier,
    ReadAdmission,
    CommittedLogicalTime,
    CommittedRecord,
    FastReturnAuthority,
    LogicalTime,
    LogicalPermit,
    LogicalSend,
    LogicalReply,
    LogicalResponse,
    LogicalApplied,
    ReadbackAdmission,
    Readback,
    FinalAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    InFlight,
    Ready,
    Rejected,
    InnerError,
    GuardError,
    DeadlineElapsed,
    BackendUnavailable,
    OperationOutcomeUnavailable,
    TopologyRevoked,
    ScopeMismatch,
    RecoveryRequired,
    OtherStoreError,
    Dropped,
}

#[derive(Debug, Clone, Serialize)]
struct Observation {
    phase: Phase,
    started_us: u64,
    finished_us: Option<u64>,
    caller_deadline_elapsed_at_finish: Option<bool>,
    outcome: Outcome,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct Snapshot {
    caller_budget_remaining_at_trace_start_us: u64,
    omitted_spans: u64,
    spans: Vec<Observation>,
}

impl Snapshot {
    pub(super) fn assert_complete(&self) {
        assert_eq!(
            self.omitted_spans, 0,
            "scoped-read trace exceeded its bound"
        );
        assert!(self.spans.iter().all(|span| span.finished_us.is_some()));
        assert!(self
            .spans
            .iter()
            .all(|span| span.outcome != Outcome::InFlight));
    }

    pub(super) fn has_phase(&self, phase: Phase) -> bool {
        self.spans.iter().any(|span| span.phase == phase)
    }

    pub(super) fn assert_observed(&self, phase: Phase, outcome: Outcome) {
        assert!(
            self.spans
                .iter()
                .any(|span| span.phase == phase && span.outcome == outcome),
            "missing scoped-read observation {phase:?}/{outcome:?}: {self:?}"
        );
    }
}

struct State {
    started: Instant,
    deadline: Instant,
    snapshot: Snapshot,
}

#[derive(Clone)]
pub(super) struct Trace(Arc<Mutex<State>>);

tokio::task_local! {
    static ACTIVE: Trace;
}

fn micros(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

impl Trace {
    pub(super) fn new(deadline: Instant) -> Self {
        let started = Instant::now();
        Self(Arc::new(Mutex::new(State {
            started,
            deadline,
            snapshot: Snapshot {
                caller_budget_remaining_at_trace_start_us: micros(
                    deadline.saturating_duration_since(started),
                ),
                omitted_spans: 0,
                spans: Vec::with_capacity(MAX_SPANS),
            },
        })))
    }

    async fn scope<F: Future>(&self, future: F) -> F::Output {
        ACTIVE.scope(self.clone(), future).await
    }

    pub(super) async fn run<T>(
        &self,
        future: impl Future<Output = Result<T, StoreError>>,
    ) -> Result<T, StoreError> {
        self.scope(observe(Phase::ConsumerGet, future, store_result))
            .await
    }

    pub(super) fn snapshot(&self) -> Snapshot {
        self.0.lock().expect("scoped-read trace").snapshot.clone()
    }

    pub(super) fn emit(&self, case: &'static str) {
        eprintln!(
            "scoped_read_diagnostic={}",
            serde_json::json!({"case": case, "trace": self.snapshot()}),
        );
    }
}

// A span captures only its bounded trace row. Dropping the observed future
// records incomplete work even when its task-local scope is already gone.
pub(crate) struct Span(Option<(Trace, usize)>);

impl Span {
    pub(crate) fn start(phase: Phase) -> Self {
        let Ok(trace) = ACTIVE.try_with(Clone::clone) else {
            return Self(None);
        };
        let mut state = trace.0.lock().expect("scoped-read trace");
        if state.snapshot.spans.len() == MAX_SPANS {
            state.snapshot.omitted_spans = state.snapshot.omitted_spans.saturating_add(1);
            return Self(None);
        }
        let index = state.snapshot.spans.len();
        let started_us = micros(Instant::now().saturating_duration_since(state.started));
        state.snapshot.spans.push(Observation {
            phase,
            started_us,
            finished_us: None,
            caller_deadline_elapsed_at_finish: None,
            outcome: Outcome::InFlight,
        });
        drop(state);
        Self(Some((trace, index)))
    }

    pub(crate) fn finish(mut self, outcome: Outcome) {
        self.record(outcome);
    }

    fn record(&mut self, outcome: Outcome) {
        if let Some((trace, index)) = self.0.take() {
            let mut state = trace.0.lock().expect("scoped-read trace");
            let now = Instant::now();
            let finished_us = micros(now.saturating_duration_since(state.started));
            let deadline_elapsed = now >= state.deadline;
            let span = &mut state.snapshot.spans[index];
            span.finished_us = Some(finished_us);
            span.caller_deadline_elapsed_at_finish = Some(deadline_elapsed);
            span.outcome = outcome;
        }
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        self.record(Outcome::Dropped);
    }
}

pub(super) async fn observe<F: Future>(
    phase: Phase,
    future: F,
    classify: impl FnOnce(&F::Output) -> Outcome,
) -> F::Output {
    let span = Span::start(phase);
    let value = future.await;
    span.finish(classify(&value));
    value
}

pub(super) fn completed(phase: Phase, outcome: Outcome) {
    Span::start(phase).finish(outcome);
}

pub(super) fn result<T, E>(value: &Result<T, E>) -> Outcome {
    match value {
        Ok(_) => Outcome::Ready,
        Err(_) => Outcome::InnerError,
    }
}

pub(super) fn elapsed_result<T>(value: &Result<T, Elapsed>) -> Outcome {
    match value {
        Ok(_) => Outcome::Ready,
        Err(_) => Outcome::DeadlineElapsed,
    }
}

pub(super) fn timed_result<T, E>(value: &Result<Result<T, E>, Elapsed>) -> Outcome {
    match value {
        Ok(value) => result(value),
        Err(_) => Outcome::DeadlineElapsed,
    }
}

pub(super) fn timed_bool<E>(value: &Result<Result<bool, E>, Elapsed>) -> Outcome {
    match value {
        Ok(Ok(true)) => Outcome::Ready,
        Ok(Ok(false)) => Outcome::Rejected,
        Ok(Err(_)) => Outcome::InnerError,
        Err(_) => Outcome::DeadlineElapsed,
    }
}

pub(crate) fn guarded_result<T, E>(value: &std::io::Result<Result<T, E>>) -> Outcome {
    match value {
        Ok(value) => result(value),
        Err(_) => Outcome::GuardError,
    }
}

pub(super) fn store_result<T>(value: &Result<T, StoreError>) -> Outcome {
    match value {
        Ok(_) => Outcome::Ready,
        Err(StoreError::BackendUnavailable(_)) => Outcome::BackendUnavailable,
        Err(StoreError::BackendOperationOutcomeUnavailable) => Outcome::OperationOutcomeUnavailable,
        Err(StoreError::TopologyAuthorityRevoked) => Outcome::TopologyRevoked,
        Err(_) => Outcome::OtherStoreError,
    }
}

pub(super) fn timed_store_result<T>(value: &Result<Result<T, StoreError>, Elapsed>) -> Outcome {
    match value {
        Ok(value) => store_result(value),
        Err(_) => Outcome::DeadlineElapsed,
    }
}

type TimedStoreReply<T, E> = Result<Result<Result<T, StoreError>, E>, Elapsed>;

pub(super) fn timed_store_reply<T, E>(value: &TimedStoreReply<T, E>) -> Outcome {
    match value {
        Ok(Ok(value)) => store_result(value),
        Ok(Err(_)) => Outcome::InnerError,
        Err(_) => Outcome::DeadlineElapsed,
    }
}

pub(super) fn scope_result<T>(value: &Result<T, SessionConsumerRejection>) -> Outcome {
    match value {
        Ok(_) => Outcome::Ready,
        Err(SessionConsumerRejection::ScopeMismatch) => Outcome::ScopeMismatch,
        Err(SessionConsumerRejection::Unavailable) => Outcome::BackendUnavailable,
        Err(_) => Outcome::InnerError,
    }
}

pub(super) fn barrier_result<T>(value: &Result<T, LinearizableBarrierFailure>) -> Outcome {
    match value {
        Ok(_) => Outcome::Ready,
        Err(LinearizableBarrierFailure::RecoveryRequired) => Outcome::RecoveryRequired,
        Err(LinearizableBarrierFailure::Unavailable) => Outcome::BackendUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;
    use std::future::{pending, ready};
    use std::time::Duration;
    use tokio::time::timeout_at;

    #[tokio::test(start_paused = true)]
    async fn scoped_read_diagnostics_distinguish_inner_errors_rejections_and_elapsed() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let trace = Trace::new(deadline);
        trace
            .scope(async {
                let inner_error = observe(
                    Phase::DurableScope,
                    timeout_at(deadline, ready(Err::<bool, ()>(()))),
                    timed_bool,
                )
                .await;
                assert!(matches!(inner_error, Ok(Err(()))));
                let rejected = observe(
                    Phase::ApplicationAuthority,
                    timeout_at(deadline, ready(Ok::<bool, ()>(false))),
                    timed_bool,
                )
                .await;
                assert!(matches!(rejected, Ok(Ok(false))));
                let timeout = observe(
                    Phase::LogicalPermit,
                    timeout_at(deadline, pending::<Result<(), ()>>()),
                    timed_result,
                )
                .await;
                assert!(timeout.is_err());
                let late_error = observe(
                    Phase::Readback,
                    ready(Err::<(), _>(StoreError::BackendUnavailable(
                        "synthetic".into(),
                    ))),
                    store_result,
                )
                .await;
                assert!(matches!(late_error, Err(StoreError::BackendUnavailable(_))));
                let guard_error = observe(
                    Phase::SqlScopeGuardAndQuery,
                    ready(Err::<Result<(), ()>, _>(std::io::Error::other("synthetic"))),
                    guarded_result,
                )
                .await;
                assert!(guard_error.is_err());
                let query_error = observe(
                    Phase::SqlScopeGuardAndQuery,
                    ready(Ok::<Result<(), ()>, std::io::Error>(Err(()))),
                    guarded_result,
                )
                .await;
                assert!(matches!(query_error, Ok(Err(()))));
            })
            .await;
        // Assertions follow the real distinct future results. Clock expiry
        // alone must not rewrite a completed inner error into outer Elapsed.
        let snapshot = trace.snapshot();
        snapshot.assert_complete();
        snapshot.assert_observed(Phase::DurableScope, Outcome::InnerError);
        snapshot.assert_observed(Phase::ApplicationAuthority, Outcome::Rejected);
        snapshot.assert_observed(Phase::LogicalPermit, Outcome::DeadlineElapsed);
        snapshot.assert_observed(Phase::Readback, Outcome::BackendUnavailable);
        snapshot.assert_observed(Phase::SqlScopeGuardAndQuery, Outcome::GuardError);
        snapshot.assert_observed(Phase::SqlScopeGuardAndQuery, Outcome::InnerError);
        assert_eq!(
            snapshot.spans[0].caller_deadline_elapsed_at_finish,
            Some(false)
        );
        assert_eq!(
            snapshot.spans[2].caller_deadline_elapsed_at_finish,
            Some(true)
        );
        assert_eq!(
            snapshot.spans[3].caller_deadline_elapsed_at_finish,
            Some(true)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn scoped_read_diagnostics_keep_cancellation_distinct_from_completion() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let trace = Trace::new(deadline);
        let mut future = Box::pin(trace.run(pending::<Result<(), StoreError>>()));
        assert!(future.as_mut().now_or_never().is_none());
        let partial = trace.snapshot();
        assert_eq!(partial.spans.len(), 1);
        assert_eq!(partial.spans[0].outcome, Outcome::InFlight);
        assert_eq!(partial.spans[0].finished_us, None);
        tokio::time::advance(Duration::from_secs(2)).await;
        drop(future);
        let snapshot = trace.snapshot();
        snapshot.assert_complete();
        snapshot.assert_observed(Phase::ConsumerGet, Outcome::Dropped);
        assert_eq!(
            snapshot.spans[0].caller_deadline_elapsed_at_finish,
            Some(true)
        );
        assert_eq!(partial.spans[0].outcome, Outcome::InFlight);
    }

    #[tokio::test]
    async fn scoped_read_diagnostics_bound_and_isolate_interleaved_callers() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let first = Trace::new(deadline);
        let second = Trace::new(deadline);
        tokio::join!(
            first.scope(async {
                // Spawned work has no selected caller context; it cannot populate
                // either caller's trace or claim a worker has drained.
                tokio::spawn(observe(
                    Phase::SqlScopeConnection,
                    ready(Ok::<_, ()>(())),
                    result,
                ))
                .await
                .expect("unscoped task")
                .expect("unscoped result");
                for _ in 0..MAX_SPANS + 7 {
                    observe(Phase::CommittedRecord, ready(Ok::<_, ()>(())), result)
                        .await
                        .expect("first result");
                    tokio::task::yield_now().await;
                }
            }),
            second.scope(async {
                for _ in 0..3 {
                    observe(Phase::Readback, ready(Err::<(), _>(())), result)
                        .await
                        .expect_err("second result");
                    tokio::task::yield_now().await;
                }
            })
        );
        let first = first.snapshot();
        let second = second.snapshot();
        assert_eq!(first.spans.len(), MAX_SPANS);
        assert_eq!(first.omitted_spans, 7);
        assert!(first
            .spans
            .iter()
            .all(|span| span.phase == Phase::CommittedRecord && span.outcome == Outcome::Ready));
        second.assert_complete();
        assert_eq!(second.spans.len(), 3);
        assert!(second
            .spans
            .iter()
            .all(|span| span.phase == Phase::Readback && span.outcome == Outcome::InnerError));
    }
}
