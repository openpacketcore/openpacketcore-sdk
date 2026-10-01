//! Opt-in test-only native apply phase timings, without operation identities.

use std::cell::Cell;
use std::time::Instant;

type Observation = Option<(Instant, usize)>;

thread_local! {
    static CURRENT: Cell<Observation> = const { Cell::new(None) };
}

pub(super) struct Scope {
    previous: Observation,
}

impl Scope {
    pub(super) fn enter(value: Observation) -> Self {
        let previous = CURRENT.with(|current| current.replace(value));
        observe("worker_entered");
        Self { previous }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        observe("worker_return");
        CURRENT.with(|current| current.set(self.previous));
    }
}

pub(crate) fn observe(phase: &'static str) {
    CURRENT.with(|current| record(current.get(), phase));
}

pub(super) fn record(value: Observation, phase: &'static str) {
    if let Some((origin, entries)) = value {
        println!(
            "CONFIG_CAPACITY_NATIVE_APPLY phase={} entries={} elapsed_ms={}",
            phase,
            entries,
            origin.elapsed().as_millis(),
        );
    }
}
