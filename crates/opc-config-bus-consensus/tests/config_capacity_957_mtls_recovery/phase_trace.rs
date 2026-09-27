//! Bounded observations of the existing integration calls, never payload decoding.
//!
//! Only the ordinary control and the two existing audited snapshot writes activate this
//! recorder. It runs in their existing isolated child, uses no background task,
//! and stops before snapshot construction/transfer or ordinary response loss. A returned
//! wire success is not a decoded engine success. Missing terminal events at the
//! cutoff are censored; only dropping a polled wrapper records cancellation.

use std::future::{poll_fn, Future};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use opc_consensus::{
    ConsensusNodeId, ConsensusPeerError, ConsensusRpcFamily, ConsensusWireRequest,
    ConsensusWireResponse,
};
use opc_persist::audit_authority::{AuditAdmission, AuditAuthorityError, AuditOperationState};
use opc_persist::{ConsensusConfigStore, PersistError, PersistErrorKind};

const EVENT_LIMIT: usize = 4096;
static ENABLED: AtomicBool = AtomicBool::new(false);
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
static ACTIVE: Mutex<Option<Trace>> = Mutex::new(None);

#[derive(Clone, Copy, Debug)]
enum Boundary {
    Api,
    Outbound,
    Handler,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ResultClass {
    Ok,
    PersistUnknown,
    PersistUnavailable,
    PersistOther,
    AuditUnknown,
    // Initialization errors do not prove that no mutation was admitted.
    AuditUnavailable,
    AuditError,
    AuditRejected,
    AuditIntent,
    AuditCommitted,
    AuditRejectedReceipt,
    AuditObserved,
    WireOk,
    TransportError,
    ServiceError,
    // This is a drop observation, not a claim about accepted native work.
    Cancelled,
    Unwound,
}

#[derive(Clone, Copy, Debug)]
struct Returned {
    class: ResultClass,
    peer_error: Option<ConsensusPeerError>,
    response_bytes: usize,
}

impl Returned {
    fn api(class: ResultClass) -> Self {
        Self {
            class,
            peer_error: None,
            response_bytes: 0,
        }
    }

    fn wire(response: &ConsensusWireResponse) -> Self {
        match &response.result {
            Ok(bytes) => Self {
                class: ResultClass::WireOk,
                peer_error: None,
                response_bytes: bytes.len(),
            },
            Err(error) => Self {
                class: ResultClass::ServiceError,
                peer_error: Some(*error),
                response_bytes: 0,
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Event {
    at_us: u64,
    span: u64,
    boundary: Boundary,
    phase: &'static str,
    source: Option<usize>,
    target: Option<usize>,
    family: Option<ConsensusRpcFamily>,
    request_bytes: usize,
    caller_timeout_us: Option<u64>,
    returned: Option<Returned>,
    duration_us: u64,
    polls: u64,
    poll_us: u64,
    max_poll_us: u64,
}

struct Trace {
    generation: u64,
    origin: Instant,
    nodes: [ConsensusNodeId; 3],
    next_span: u64,
    started: u64,
    completed: u64,
    cancelled: u64,
    unwound: u64,
    overflow: u64,
    events: Vec<Event>,
}

impl Trace {
    fn push(&mut self, event: Event) {
        if self.events.len() < EVENT_LIMIT {
            self.events.push(event);
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
    }
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[derive(Clone, Copy)]
struct StatusSnapshot {
    term: u64,
    leader: Option<usize>,
    applied: Option<u64>,
    committed: Option<u64>,
    admitted: bool,
}

/// Holds only existing borrowed stores, no additional storage/handler owners.
pub(super) struct Session<'a> {
    generation: u64,
    scenario: &'static str,
    stores: &'a [ConsensusConfigStore],
    initial: [StatusSnapshot; 3],
    finished: bool,
}

impl<'a> Session<'a> {
    pub(super) fn start(scenario: &'static str, stores: &'a [ConsensusConfigStore]) -> Self {
        assert_eq!(stores.len(), 3, "fixed observed native fixture");
        let statuses = [stores[0].status(), stores[1].status(), stores[2].status()];
        let nodes = statuses.map(|status| status.node_id);
        let initial = statuses.map(|status| StatusSnapshot {
            term: status.term,
            leader: status
                .leader_id
                .and_then(|node| nodes.iter().position(|value| *value == node)),
            applied: status.applied_index,
            committed: status.committed_index,
            admitted: status.admitted,
        });
        // Allocate once before the observed API starts. No event grows this buffer.
        let events = Vec::with_capacity(EVENT_LIMIT);
        let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        let mut active = ACTIVE.lock().expect("bounded diagnostic registry");
        assert!(active.is_none(), "one observed operation scope at a time");
        *active = Some(Trace {
            generation,
            origin: Instant::now(),
            nodes,
            next_span: 0,
            started: 0,
            completed: 0,
            cancelled: 0,
            unwound: 0,
            overflow: 0,
            events,
        });
        ENABLED.store(true, Ordering::Release);
        Self {
            generation,
            scenario,
            stores,
            initial,
            finished: false,
        }
    }

    pub(super) fn finish(mut self) {
        self.dump();
    }

    fn dump(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        // Stop the trace before reading public status or printing. Events that
        // finish later belong to the cutoff's pending count, not cancellation.
        ENABLED.store(false, Ordering::Release);
        let trace = {
            let mut active = ACTIVE
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if active
                .as_ref()
                .is_none_or(|trace| trace.generation != self.generation)
            {
                return;
            }
            active.take().expect("matching bounded diagnostic trace")
        };
        let cutoff_us = micros(trace.origin.elapsed());
        let final_status = [0, 1, 2].map(|index| {
            let entered_us = micros(trace.origin.elapsed());
            let status = self.stores[index].status();
            (entered_us, status, micros(trace.origin.elapsed()))
        });
        eprintln!(
            "CONFIG_CAPACITY_MTLS_PHASE scenario={} cutoff_us={cutoff_us} events={} overflow={} started={} completed={} cancelled={} unwound={} pending={} record_bytes={} capacity={} unwinding={}",
            self.scenario, trace.events.len(), trace.overflow, trace.started, trace.completed,
            trace.cancelled, trace.unwound, trace.started.saturating_sub(trace.completed + trace.cancelled + trace.unwound),
            std::mem::size_of::<Event>(), trace.events.capacity(), std::thread::panicking(),
        );
        for (node, (initial, (status_begin_us, status, status_end_us))) in
            self.initial.iter().zip(final_status).enumerate()
        {
            let leader = status
                .leader_id
                .and_then(|id| trace.nodes.iter().position(|node| *node == id));
            eprintln!(
                "CONFIG_CAPACITY_MTLS_STATUS node={node} status_begin_us={status_begin_us} status_end_us={status_end_us} before_term={} before_leader={:?} before_applied={:?} before_committed={:?} before_admitted={} after_term={} after_leader={leader:?} after_applied={:?} after_committed={:?} after_admitted={}",
                initial.term, initial.leader, initial.applied, initial.committed, initial.admitted, status.term,
                status.applied_index, status.committed_index, status.admitted,
            );
        }
        // Fixed labels, scalar ordinals/timings/counts, and redaction-safe enum
        // values only. Never print identities, payloads, receipts or error text.
        for event in trace.events {
            eprintln!(
                "CONFIG_CAPACITY_MTLS_EVENT at_us={} span={} boundary={:?} phase={} source={:?} target={:?} family={:?} request_bytes={} caller_timeout_us={:?} terminal={} class={:?} peer_error={:?} response_bytes={} duration_us={} polls={} poll_us={} max_poll_us={}",
                event.at_us, event.span, event.boundary, event.phase, event.source,
                event.target, event.family, event.request_bytes, event.caller_timeout_us,
                event.returned.is_some(), event.returned.map(|value| value.class),
                event.returned.and_then(|value| value.peer_error),
                event.returned.map_or(0, |value| value.response_bytes), event.duration_us,
                event.polls, event.poll_us, event.max_poll_us,
            );
        }
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        self.dump();
    }
}

pub(super) struct Span {
    token: Option<(u64, Instant, Event)>,
}

impl Span {
    fn begin(
        boundary: Boundary,
        phase: &'static str,
        request: Option<&ConsensusWireRequest>,
        target: Option<ConsensusNodeId>,
        timeout: Option<Duration>,
    ) -> Self {
        if !ENABLED.load(Ordering::Acquire) {
            return Self { token: None };
        }
        let mut active = ACTIVE.lock().expect("bounded diagnostic registry");
        let Some(trace) = active.as_mut() else {
            return Self { token: None };
        };
        let started = Instant::now();
        trace.next_span += 1;
        trace.started += 1;
        let event = Event {
            at_us: micros(started.duration_since(trace.origin)),
            span: trace.next_span,
            boundary,
            phase,
            source: request
                .and_then(|request| trace.nodes.iter().position(|node| *node == request.sender)),
            target: target.and_then(|target| trace.nodes.iter().position(|node| *node == target)),
            family: request.map(|request| request.family),
            request_bytes: request.map_or(0, |request| request.payload.len()),
            caller_timeout_us: timeout.map(micros),
            returned: None,
            duration_us: 0,
            polls: 0,
            poll_us: 0,
            max_poll_us: 0,
        };
        trace.push(event);
        Self {
            token: Some((trace.generation, started, event)),
        }
    }

    pub(super) fn api(phase: &'static str) -> Self {
        Self::begin(Boundary::Api, phase, None, None, None)
    }

    pub(super) fn outbound(
        request: &ConsensusWireRequest,
        target: ConsensusNodeId,
        timeout: Option<Duration>,
    ) -> Self {
        Self::begin(
            Boundary::Outbound,
            "transport_delegate",
            Some(request),
            Some(target),
            timeout,
        )
    }

    pub(super) fn handler(request: &ConsensusWireRequest, target: ConsensusNodeId) -> Self {
        Self::begin(
            Boundary::Handler,
            "authenticated_handler",
            Some(request),
            Some(target),
            None,
        )
    }

    pub(super) async fn track<F: Future>(&mut self, future: F) -> F::Output {
        if self.token.is_none() {
            return future.await;
        }
        tokio::pin!(future);
        poll_fn(|context| {
            let entered = Instant::now();
            let result = future.as_mut().poll(context);
            let busy_us = micros(entered.elapsed());
            if let Some((_, _, event)) = self.token.as_mut() {
                event.polls = event.polls.saturating_add(1);
                event.poll_us = event.poll_us.saturating_add(busy_us);
                event.max_poll_us = event.max_poll_us.max(busy_us);
            }
            result
        })
        .await
    }

    fn end(&mut self, returned: Returned) {
        let Some((generation, started, mut event)) = self.token.take() else {
            return;
        };
        let mut active = ACTIVE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(trace) = active
            .as_mut()
            .filter(|trace| trace.generation == generation)
        else {
            return;
        };
        event.at_us = micros(trace.origin.elapsed());
        event.duration_us = micros(started.elapsed());
        event.returned = Some(returned);
        match returned.class {
            ResultClass::Cancelled => trace.cancelled += 1,
            ResultClass::Unwound => trace.unwound += 1,
            _ => trace.completed += 1,
        }
        trace.push(event);
    }

    pub(super) fn returned(&mut self, class: ResultClass) {
        self.end(Returned::api(class));
    }

    pub(super) fn peer_returned(
        &mut self,
        result: &Result<ConsensusWireResponse, ConsensusPeerError>,
    ) {
        self.end(match result {
            Ok(response) => Returned::wire(response),
            Err(error) => Returned {
                class: ResultClass::TransportError,
                peer_error: Some(*error),
                response_bytes: 0,
            },
        });
    }

    pub(super) fn handler_returned(&mut self, result: &ConsensusWireResponse) {
        self.end(Returned::wire(result));
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        self.end(Returned::api(if std::thread::panicking() {
            ResultClass::Unwound
        } else {
            ResultClass::Cancelled
        }));
    }
}

pub(super) fn persist<T>(result: &Result<T, PersistError>) -> ResultClass {
    match result {
        Ok(_) => ResultClass::Ok,
        Err(error) => match error.kind() {
            PersistErrorKind::OutcomeUnknown => ResultClass::PersistUnknown,
            PersistErrorKind::Unavailable => ResultClass::PersistUnavailable,
            _ => ResultClass::PersistOther,
        },
    }
}

// Initialization may report unavailability after submission or checkpoint work.
// Keep this Result API separate from definite AuditAdmission::Rejected.
pub(super) fn audit_initialization(result: &Result<(), AuditAuthorityError>) -> ResultClass {
    match result {
        Ok(()) => ResultClass::Ok,
        Err(AuditAuthorityError::Unavailable) => ResultClass::AuditUnavailable,
        Err(_) => ResultClass::AuditError,
    }
}

pub(super) fn audit(result: &AuditAdmission) -> ResultClass {
    match result {
        AuditAdmission::Unknown(_) => ResultClass::AuditUnknown,
        AuditAdmission::Rejected(_) => ResultClass::AuditRejected,
        AuditAdmission::Applied(receipt) => match receipt.state() {
            AuditOperationState::Intent => ResultClass::AuditIntent,
            AuditOperationState::Committed { .. } => ResultClass::AuditCommitted,
            AuditOperationState::Rejected => ResultClass::AuditRejectedReceipt,
            AuditOperationState::Observed { .. } => ResultClass::AuditObserved,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll, Waker};

    use super::*;

    #[test]
    fn phase_trace_initialization_uncertainty_is_not_admission_rejection() {
        assert!(matches!(audit_initialization(&Ok(())), ResultClass::Ok));
        assert!(matches!(
            audit_initialization(&Err(AuditAuthorityError::Unavailable)),
            ResultClass::AuditUnavailable
        ));
        assert!(matches!(
            audit_initialization(&Err(AuditAuthorityError::InvalidInput)),
            ResultClass::AuditError
        ));
        // Preserve the distinct contract when the API actually returns the
        // no-admission variant, even with the same underlying error category.
        assert!(matches!(
            audit(&AuditAdmission::Rejected(AuditAuthorityError::Unavailable)),
            ResultClass::AuditRejected
        ));
    }

    // Recorder control only. The existing native scenarios, not this test,
    // establish whether transport/API events occur around a real operation.
    #[test]
    fn phase_trace_records_ready_dropped_pending_and_bounded_overflow() {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                ENABLED.store(false, Ordering::Release);
                ACTIVE
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take();
            }
        }
        let _reset = Reset;
        let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        let mut active = ACTIVE.lock().expect("exclusive recorder control");
        assert!(active.is_none());
        *active = Some(Trace {
            generation,
            origin: Instant::now(),
            nodes: [1, 2, 3].map(|value| ConsensusNodeId::new(value).expect("synthetic node")),
            next_span: 0,
            started: 0,
            completed: 0,
            cancelled: 0,
            unwound: 0,
            overflow: 0,
            events: Vec::with_capacity(EVENT_LIMIT),
        });
        drop(active);
        ENABLED.store(true, Ordering::Release);
        let mut context = Context::from_waker(Waker::noop());
        let mut ready = Span::api("ready_control");
        {
            let future = ready.track(std::future::ready(7));
            tokio::pin!(future);
            assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(7));
        }
        ready.returned(ResultClass::Ok);
        drop(ready);
        let mut cancelled = Span::api("pending_control");
        {
            let future = cancelled.track(std::future::pending::<()>());
            tokio::pin!(future);
            assert_eq!(future.as_mut().poll(&mut context), Poll::Pending);
        }
        drop(cancelled);
        {
            let active = ACTIVE.lock().expect("completed recorder controls");
            let trace = active.as_ref().expect("active recorder");
            assert_eq!((trace.started, trace.completed, trace.cancelled), (2, 1, 1));
            assert_eq!(trace.events.len(), 4);
            assert_eq!(trace.events[1].polls, 1);
            assert!(matches!(
                trace.events[1]
                    .returned
                    .expect("ready terminal event")
                    .class,
                ResultClass::Ok
            ));
            assert_eq!(trace.events[3].polls, 1);
            assert!(matches!(
                trace.events[3].returned.expect("drop terminal event").class,
                ResultClass::Cancelled
            ));
            assert!(trace
                .events
                .windows(2)
                .all(|events| events[0].at_us <= events[1].at_us));
        }
        // Exhaust only the recorder; outcomes continue to be counted without
        // allocating or claiming a complete trace after the fixed bound.
        for _ in 0..EVENT_LIMIT {
            Span::api("overflow_control").returned(ResultClass::Ok);
        }
        let active = ACTIVE.lock().expect("bounded recorder control");
        let trace = active.as_ref().expect("active recorder");
        assert_eq!(trace.events.len(), EVENT_LIMIT);
        assert_eq!(trace.events.capacity(), EVENT_LIMIT);
        assert_eq!(trace.overflow, (4 + 2 * EVENT_LIMIT - EVENT_LIMIT) as u64);
        assert_eq!(trace.started, (2 + EVENT_LIMIT) as u64);
        assert_eq!(trace.completed, (1 + EVENT_LIMIT) as u64);
        assert_eq!(trace.cancelled, 1);
    }
}
