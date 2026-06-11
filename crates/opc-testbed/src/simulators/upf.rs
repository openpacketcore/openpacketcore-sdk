//! Procedure-faithful UPF peer simulator (fidelity = "procedure_faithful").

use crate::scenario::Step;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpfState {
    Idle,
    Associated,
    Unreachable,
    PreflightFailed,
}

impl UpfState {
    pub fn as_str(self) -> &'static str {
        match self {
            UpfState::Idle => "IDLE",
            UpfState::Associated => "ASSOCIATED",
            UpfState::Unreachable => "UNREACHABLE",
            UpfState::PreflightFailed => "PREFLIGHT_FAILED",
        }
    }
}

#[derive(Debug)]
pub struct UpfSimulator {
    pub name: String,
    pub state: UpfState,
    pub association_active: bool,
    pub dataplane_ready: bool,
    pub flow_counter: u64,
    pub flow_threshold: u64,
    pub alarm_active: bool,
}

impl UpfSimulator {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            state: UpfState::Idle,
            association_active: false,
            dataplane_ready: true,
            flow_counter: 0,
            flow_threshold: 100,
            alarm_active: false,
        }
    }

    pub fn get_state(&self, key: &str) -> Option<String> {
        match key {
            "state" => Some(self.state.as_str().to_string()),
            "association_active" => Some(self.association_active.to_string()),
            "dataplane_ready" => Some(self.dataplane_ready.to_string()),
            "flow_counter" => Some(self.flow_counter.to_string()),
            "flow_threshold" => Some(self.flow_threshold.to_string()),
            "alarm_active" => Some(self.alarm_active.to_string()),
            _ => None,
        }
    }

    pub fn get_all_state(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("state".to_string(), self.state.as_str().to_string());
        map.insert(
            "association_active".to_string(),
            self.association_active.to_string(),
        );
        map.insert(
            "dataplane_ready".to_string(),
            self.dataplane_ready.to_string(),
        );
        map.insert("flow_counter".to_string(), self.flow_counter.to_string());
        map.insert(
            "flow_threshold".to_string(),
            self.flow_threshold.to_string(),
        );
        map.insert("alarm_active".to_string(), self.alarm_active.to_string());
        map
    }

    pub fn handle_step(&mut self, step: &Step) -> Result<(), crate::TestbedError> {
        match step {
            Step::SendNgap { message, .. } => {
                let msg = message.trim().to_lowercase();
                if !self.dataplane_ready {
                    self.state = UpfState::PreflightFailed;
                    return Err(crate::TestbedError::Simulator(
                        "Dataplane preflight failure".into(),
                    ));
                }
                if msg.contains("associate") || msg.contains("pfcp") {
                    self.association_active = true;
                    self.state = UpfState::Associated;
                } else if msg.contains("packet") || msg.contains("flow") {
                    self.flow_counter += 10;
                    if self.flow_counter > self.flow_threshold {
                        self.alarm_active = true;
                    }
                } else if msg.contains("recover") {
                    self.association_active = true;
                    self.state = UpfState::Associated;
                } else {
                    return Err(crate::TestbedError::Simulator(format!(
                        "unknown message: {message}"
                    )));
                }
            }
            Step::PeerUnavailable { .. } => {
                self.association_active = false;
                self.state = UpfState::Unreachable;
            }
            Step::DependencyTimeout { .. } => {
                self.dataplane_ready = false;
                self.state = UpfState::PreflightFailed;
            }
            Step::ProcessRestart { .. } => {
                self.state = UpfState::Idle;
                self.association_active = false;
                self.dataplane_ready = true;
                self.alarm_active = false;
                self.flow_counter = 0;
            }
            _ => {}
        }
        Ok(())
    }
}
