//! Procedure-faithful AMF peer simulator (fidelity = "procedure_faithful").

use crate::scenario::Step;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmfState {
    BootstrapPending,
    Ready,
    Registering,
    Registered,
    SessionCreating,
    SessionActive,
    AlarmActive,
    Failed,
}

impl AmfState {
    pub fn as_str(self) -> &'static str {
        match self {
            AmfState::BootstrapPending => "BOOTSTRAP_PENDING",
            AmfState::Ready => "READY",
            AmfState::Registering => "REGISTERING",
            AmfState::Registered => "REGISTERED",
            AmfState::SessionCreating => "SESSION_CREATING",
            AmfState::SessionActive => "SESSION_ACTIVE",
            AmfState::AlarmActive => "ALARM_ACTIVE",
            AmfState::Failed => "FAILED",
        }
    }
}

#[derive(Debug)]
pub struct AmfSimulator {
    pub name: String,
    pub state: AmfState,
    pub nrf_connected: bool,
    pub subscriber_context_created: bool,
    pub alarm_emitted: bool,
    pub transient_peer_failures: u32,
    pub config_version: String,
}

impl AmfSimulator {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            state: AmfState::BootstrapPending,
            nrf_connected: true,
            subscriber_context_created: false,
            alarm_emitted: false,
            transient_peer_failures: 0,
            config_version: "1.0.0".to_string(),
        }
    }

    pub fn get_state(&self, key: &str) -> Option<String> {
        match key {
            "state" => Some(self.state.as_str().to_string()),
            "nrf_connected" => Some(self.nrf_connected.to_string()),
            "subscriber_context_created" => Some(self.subscriber_context_created.to_string()),
            "alarm_emitted" => Some(self.alarm_emitted.to_string()),
            "transient_peer_failures" => Some(self.transient_peer_failures.to_string()),
            "config_version" => Some(self.config_version.clone()),
            _ => None,
        }
    }

    pub fn get_all_state(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("state".to_string(), self.state.as_str().to_string());
        map.insert("nrf_connected".to_string(), self.nrf_connected.to_string());
        map.insert(
            "subscriber_context_created".to_string(),
            self.subscriber_context_created.to_string(),
        );
        map.insert("alarm_emitted".to_string(), self.alarm_emitted.to_string());
        map.insert(
            "transient_peer_failures".to_string(),
            self.transient_peer_failures.to_string(),
        );
        map.insert("config_version".to_string(), self.config_version.clone());
        map
    }

    pub fn handle_step(&mut self, step: &Step) -> Result<(), crate::TestbedError> {
        match step {
            Step::SendNgap { message, .. } => {
                let msg = message.trim().to_lowercase();
                if msg.contains("registration") {
                    if self.state == AmfState::Failed {
                        return Err(crate::TestbedError::Simulator(
                            "AMF is in failed state".into(),
                        ));
                    }
                    if !self.nrf_connected {
                        self.state = AmfState::AlarmActive;
                        self.alarm_emitted = true;
                        return Err(crate::TestbedError::Simulator(
                            "NRF dependency failure".into(),
                        ));
                    }
                    self.state = AmfState::Registered;
                    self.subscriber_context_created = true;
                } else if msg.contains("session") || msg.contains("pdu") {
                    if self.state != AmfState::Registered {
                        return Err(crate::TestbedError::Simulator(
                            "Invalid transition: session establishment requires registered state"
                                .into(),
                        ));
                    }
                    self.state = AmfState::SessionActive;
                } else if msg.contains("config") || msg.contains("reconfigure") {
                    if self.state == AmfState::SessionActive {
                        self.config_version = "1.1.0".to_string();
                    } else {
                        return Err(crate::TestbedError::Simulator(
                            "Invalid transition: config apply requires active session".into(),
                        ));
                    }
                } else if msg.contains("recover") {
                    self.nrf_connected = true;
                    self.alarm_emitted = false;
                    self.state = AmfState::Registered;
                } else {
                    return Err(crate::TestbedError::Simulator(format!(
                        "unknown message: {message}"
                    )));
                }
            }
            Step::PeerUnavailable { .. } => {
                self.nrf_connected = false;
                self.state = AmfState::AlarmActive;
                self.alarm_emitted = true;
                self.transient_peer_failures += 1;
            }
            Step::DependencyTimeout { .. } => {
                self.nrf_connected = false;
                self.state = AmfState::Failed;
                self.alarm_emitted = true;
            }
            Step::ProcessRestart { .. } => {
                self.state = AmfState::Ready;
                self.nrf_connected = true;
                self.alarm_emitted = false;
            }
            _ => {}
        }
        Ok(())
    }
}
