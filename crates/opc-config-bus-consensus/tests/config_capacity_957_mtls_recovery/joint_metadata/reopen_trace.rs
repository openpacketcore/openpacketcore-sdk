//! Bounded, field-free spans locate an unresolved reopen readiness timeout.
//! Diagnostic only: durations include awaits, and no timing verdict is inferred.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

const MAX_ACTIVE: usize = 64;
const MAX_COMPLETED: usize = 128;

struct Active {
    kind: &'static str,
    created: Instant,
    references: usize,
    polls: usize,
}

struct Completed {
    kind: &'static str,
    start_ms: u128,
    elapsed_ms: u128,
    polls: usize,
}

struct Window {
    started: Instant,
    active: BTreeMap<u64, Active>,
    completed: Vec<Completed>,
    omitted: usize,
}

static WINDOW: OnceLock<Arc<Mutex<Option<Window>>>> = OnceLock::new();
static NEXT_SPAN: AtomicU64 = AtomicU64::new(1);

struct ApplyTrace(Arc<Mutex<Option<Window>>>);

fn kind(metadata: &Metadata<'_>) -> Option<&'static str> {
    match (metadata.target(), metadata.name(), metadata.is_span()) {
        ("openraft::core::sm::worker", "apply", true) => Some("state_machine_apply"),
        ("openraft::core::raft_core", "run_engine_commands", true) => Some("engine_commands"),
        _ => None,
    }
}

impl Subscriber for ApplyTrace {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        kind(metadata).is_some()
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::DEBUG)
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let id = NEXT_SPAN.fetch_add(1, Ordering::Relaxed);
        if let Some(window) = self.0.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            if window.active.len() < MAX_ACTIVE {
                window.active.insert(
                    id,
                    Active {
                        kind: kind(attributes.metadata()).expect("selected static span"),
                        created: Instant::now(),
                        references: 1,
                        polls: 0,
                    },
                );
            } else {
                window.omitted = window.omitted.saturating_add(1);
            }
        }
        Id::from_u64(id)
    }

    // Do not visit, format or retain any field: no values, node identities,
    // commands, operation identities or payloads enter this observation.
    fn record(&self, _span: &Id, _values: &Record<'_>) {}
    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
    fn event(&self, _event: &Event<'_>) {}
    fn exit(&self, _span: &Id) {}

    fn enter(&self, id: &Id) {
        if let Some(active) = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
            .and_then(|window| window.active.get_mut(&id.into_u64()))
        {
            active.polls = active.polls.saturating_add(1);
        }
    }

    fn clone_span(&self, id: &Id) -> Id {
        if let Some(active) = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
            .and_then(|window| window.active.get_mut(&id.into_u64()))
        {
            active.references = active.references.saturating_add(1);
        }
        id.clone()
    }

    fn try_close(&self, id: Id) -> bool {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some(window) = state.as_mut() else {
            return false;
        };
        let Some(active) = window.active.get_mut(&id.into_u64()) else {
            return false;
        };
        active.references -= 1;
        if active.references != 0 {
            return false;
        }
        let active = window.active.remove(&id.into_u64()).expect("observed span");
        let observation = Completed {
            kind: active.kind,
            start_ms: active.created.duration_since(window.started).as_millis(),
            elapsed_ms: active.created.elapsed().as_millis(),
            polls: active.polls,
        };
        if window.completed.len() < MAX_COMPLETED {
            window.completed.push(observation);
        } else {
            // Retain the longest completed spans; an apply stall cannot be
            // displaced by a stream of short heartbeat command loops.
            let (index, shortest) = window
                .completed
                .iter()
                .enumerate()
                .min_by_key(|(_, span)| span.elapsed_ms)
                .expect("full finite observation array");
            if observation.elapsed_ms > shortest.elapsed_ms {
                window.completed[index] = observation;
            }
            window.omitted = window.omitted.saturating_add(1);
        }
        true
    }
}

pub(super) struct Guard(Arc<Mutex<Option<Window>>>);

pub(super) fn begin() -> Guard {
    let shared = WINDOW.get_or_init(|| {
        let shared = Arc::new(Mutex::new(None));
        tracing::subscriber::set_global_default(ApplyTrace(shared.clone()))
            .expect("single diagnostic subscriber in dedicated native test process");
        shared
    });
    let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
    assert!(state.is_none(), "one observed reopen per test process");
    *state = Some(Window {
        started: Instant::now(),
        active: BTreeMap::new(),
        completed: Vec::with_capacity(MAX_COMPLETED),
        omitted: 0,
    });
    Guard(shared.clone())
}

impl Drop for Guard {
    fn drop(&mut self) {
        let Some(mut window) = self.0.lock().unwrap_or_else(|e| e.into_inner()).take() else {
            return;
        };
        window.completed.sort_by_key(|span| span.start_ms);
        eprintln!(
            "CONFIG_CAPACITY_REOPEN_SPANS elapsed_ms={} completed={} active={} omitted={} unwinding={}",
            window.started.elapsed().as_millis(),
            window.completed.len(),
            window.active.len(),
            window.omitted,
            std::thread::panicking()
        );
        for span in window.completed {
            eprintln!(
                "CONFIG_CAPACITY_REOPEN_SPAN kind={} start_ms={} elapsed_ms={} polls={} closed=true",
                span.kind, span.start_ms, span.elapsed_ms, span.polls
            );
        }
        for span in window.active.values() {
            eprintln!(
                "CONFIG_CAPACITY_REOPEN_SPAN kind={} start_ms={} elapsed_ms={} polls={} closed=false",
                span.kind,
                span.created.duration_since(window.started).as_millis(),
                span.created.elapsed().as_millis(),
                span.polls
            );
        }
    }
}
