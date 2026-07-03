//! Per-(peer, service) outbound circuit breakers (RFC 007 §13.4).
//!
//! Breakers count consecutive failures, trip open after a threshold, hold
//! requests off for a cooldown, then admit a bounded number of half-open
//! probes before either closing (probe succeeded) or re-opening (probe
//! failed). State transitions are exported through the
//! `opc_sbi_circuit_state` metric with redaction-safe labels.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::lock_or_recover;
use crate::redact::safe_metric_label;

/// State of a circuit breaker's three-state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation: requests flow and consecutive failures are
    /// counted; reaching the failure threshold trips the breaker open.
    Closed,
    /// Tripped: all requests are rejected without dialing the peer until
    /// the cooldown has elapsed since the stored trip instant, at which
    /// point the breaker moves to `HalfOpen`.
    Open(Instant),
    /// Probation: up to `max_probes` trial requests are admitted. The first
    /// recorded success closes the breaker; any recorded failure re-opens
    /// it immediately.
    HalfOpen,
}

/// Failure-tripped breaker guarding one (peer, service) pair.
///
/// Not internally synchronized — `CircuitBreakers` wraps each instance in a
/// `Mutex`. Callers drive it manually: `allow_request` before sending,
/// then exactly one of `record_success`/`record_failure` per attempt.
pub struct CircuitBreaker {
    state: CircuitState,
    consecutive_failures: u32,
    failure_threshold: u32,
    cooldown: Duration,
    max_probes: u32,
    active_probes: u32,
}

impl CircuitBreaker {
    /// Create a breaker in the `Closed` state.
    ///
    /// It trips open after `failure_threshold` consecutive failures, stays
    /// open for `cooldown`, then admits at most `max_probes` half-open
    /// trial requests.
    pub fn new(failure_threshold: u32, cooldown: Duration, max_probes: u32) -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            failure_threshold,
            cooldown,
            max_probes,
            active_probes: 0,
        }
    }

    /// Current state, for metrics and debug surfaces.
    pub fn state(&self) -> CircuitState {
        self.state
    }

    /// Decide whether a request may proceed at time `now`; may transition
    /// the breaker.
    ///
    /// `Closed` always admits. `Open` rejects (fail-fast, sparing the
    /// struggling peer) until the cooldown has elapsed, then flips to
    /// `HalfOpen` and admits. `HalfOpen` admits until `max_probes` probes
    /// are in flight, rejecting the rest.
    pub fn allow_request(&mut self, now: Instant) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open(opened_at) => {
                if now.duration_since(opened_at) >= self.cooldown {
                    self.state = CircuitState::HalfOpen;
                    self.active_probes = 0;
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                if self.active_probes < self.max_probes {
                    self.active_probes += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Record a successful attempt against the peer.
    ///
    /// In `Closed` this resets the consecutive-failure counter; in
    /// `HalfOpen` a single success is enough to close the breaker (emitting
    /// a `closed` state metric). Successes that race a transition to `Open`
    /// are ignored. `peer`/`service` are only used as metric labels.
    pub fn record_success(&mut self, peer: &str, service: &str) {
        match self.state {
            CircuitState::Closed => {
                self.consecutive_failures = 0;
            }
            CircuitState::Open(_) => {}
            CircuitState::HalfOpen => {
                self.consecutive_failures = 0;
                self.state = CircuitState::Closed;
                self.active_probes = 0;
                self.update_metrics(peer, service, "closed");
            }
        }
    }

    /// Record a failed attempt against the peer at time `now`.
    ///
    /// In `Closed`, increments the consecutive-failure counter and trips to
    /// `Open(now)` when it reaches the threshold. In `HalfOpen`, a single
    /// failed probe re-opens immediately (restarting the cooldown from
    /// `now`). Failures while already `Open` are ignored.
    /// `peer`/`service` are only used as metric labels.
    pub fn record_failure(&mut self, peer: &str, service: &str, now: Instant) {
        match self.state {
            CircuitState::Closed => {
                self.consecutive_failures += 1;
                if self.consecutive_failures >= self.failure_threshold {
                    self.state = CircuitState::Open(now);
                    self.update_metrics(peer, service, "open");
                }
            }
            CircuitState::Open(_) => {}
            CircuitState::HalfOpen => {
                self.state = CircuitState::Open(now);
                self.active_probes = 0;
                self.update_metrics(peer, service, "open");
            }
        }
    }

    fn update_metrics(&self, peer: &str, service: &str, state_str: &str) {
        lock_or_recover(&opc_redaction::metrics::METRICS.sbi_circuit_state)
            .entry((
                safe_metric_label(peer),
                safe_metric_label(service),
                state_str.to_string(),
            ))
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }
}

/// Registry of CircuitBreakers for peers and services.
#[allow(clippy::type_complexity)]
pub struct CircuitBreakers {
    breakers: Mutex<HashMap<(String, String), Arc<Mutex<CircuitBreaker>>>>,
    failure_threshold: u32,
    cooldown: Duration,
    max_probes: u32,
}

impl CircuitBreakers {
    /// Create an empty registry; the three parameters become the defaults
    /// for every breaker it lazily creates (see `CircuitBreaker::new`).
    pub fn new(failure_threshold: u32, cooldown: Duration, max_probes: u32) -> Self {
        Self {
            breakers: Mutex::new(HashMap::new()),
            failure_threshold,
            cooldown,
            max_probes,
        }
    }

    /// Fetch the breaker for a (peer, service) pair, creating a fresh
    /// `Closed` breaker with the registry's defaults on first use. Entries
    /// are never evicted, so callers should key by bounded identifiers
    /// (host names and service names), not per-request data.
    pub fn get(&self, peer: &str, service: &str) -> Arc<Mutex<CircuitBreaker>> {
        let mut lock = lock_or_recover(&self.breakers);
        let key = (peer.to_string(), service.to_string());
        lock.entry(key)
            .or_insert_with(|| {
                Arc::new(Mutex::new(CircuitBreaker::new(
                    self.failure_threshold,
                    self.cooldown,
                    self.max_probes,
                )))
            })
            .clone()
    }
}
