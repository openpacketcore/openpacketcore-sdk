//! Fake / stub simulator (fidelity = "stub").
//!
//! Provides the simplest possible peer that can be wired into scenario
//! execution for early integration of the DSL, virtual time, and assertions.
//! All behavior is hardcoded or scripted per test.

use crate::scenario::NfSpec;
use std::collections::HashMap;

/// Fidelity level per RFC 012 §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Fidelity {
    #[default]
    Stub,
    // Others will be added as real simulators are implemented.
}

/// A minimal fake peer simulator used in examples and framework tests.
#[derive(Debug, Default)]
pub struct FakeSimulator {
    pub name: String,
    pub fidelity: Fidelity,
    /// Simple key/value state exposed to the assertion engine.
    state: HashMap<String, String>,
}

impl FakeSimulator {
    pub fn new(name: impl Into<String>, fidelity: Fidelity) -> Self {
        let mut s = Self {
            name: name.into(),
            fidelity,
            state: HashMap::new(),
        };
        // Seed deterministic initial state for examples and simple assertions.
        s.state.insert("state".into(), "INITIAL".into());
        s
    }

    /// Construct a fake simulator from an [`NfSpec`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if the spec requests a simulator other than `"fake"`.
    pub fn from_spec(name: &str, spec: &NfSpec) -> Result<Self, crate::TestbedError> {
        match spec.simulator.as_deref() {
            Some("fake") => Ok(Self::new(name, Fidelity::Stub)),
            Some(other) => Err(crate::TestbedError::Simulator(format!(
                "unsupported simulator '{other}' for '{name}'; only 'fake' is supported"
            ))),
            None => Err(crate::TestbedError::Simulator(format!(
                "no simulator specified for '{name}'; expected 'fake'"
            ))),
        }
    }

    pub fn set_state(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.state.insert(key.into(), value.into());
    }

    pub fn get_state(&self, key: &str) -> Option<&str> {
        self.state.get(key).map(|s| s.as_str())
    }

    /// Advance internal state for a known procedure step.
    ///
    /// # Errors
    ///
    /// Returns `Err` for unknown step kinds so that typos or miswired
    /// scenario plumbing fail fast instead of silently no-oping.
    pub fn handle_step(&mut self, step_kind: &str) -> Result<(), crate::TestbedError> {
        match step_kind {
            "registration" => {
                self.set_state("state", "REGISTERED");
                Ok(())
            }
            "session" => {
                self.set_state("state", "SESSION_ACTIVE");
                Ok(())
            }
            other => Err(crate::TestbedError::Simulator(format!(
                "unknown step kind '{other}' for simulator '{}'",
                self.name
            ))),
        }
    }
}
