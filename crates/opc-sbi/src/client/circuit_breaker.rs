use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::redact::safe_metric_label;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open(Instant),
    HalfOpen,
}

pub struct CircuitBreaker {
    state: CircuitState,
    consecutive_failures: u32,
    failure_threshold: u32,
    cooldown: Duration,
    max_probes: u32,
    active_probes: u32,
}

impl CircuitBreaker {
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

    pub fn state(&self) -> CircuitState {
        self.state
    }

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
        opc_redaction::metrics::METRICS
            .sbi_circuit_state
            .lock()
            .unwrap()
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
    pub fn new(failure_threshold: u32, cooldown: Duration, max_probes: u32) -> Self {
        Self {
            breakers: Mutex::new(HashMap::new()),
            failure_threshold,
            cooldown,
            max_probes,
        }
    }

    pub fn get(&self, peer: &str, service: &str) -> Arc<Mutex<CircuitBreaker>> {
        let mut lock = self.breakers.lock().unwrap();
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
