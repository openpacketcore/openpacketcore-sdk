//! Procedure-faithful SMF peer simulator (fidelity = "procedure_faithful").

use crate::scenario::Step;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmfState {
    Idle,
    SessionEstablished,
    SessionModified,
    SessionReleased,
    Timeout,
    StaleFenceRejected,
}

impl SmfState {
    pub fn as_str(self) -> &'static str {
        match self {
            SmfState::Idle => "IDLE",
            SmfState::SessionEstablished => "SESSION_ESTABLISHED",
            SmfState::SessionModified => "SESSION_MODIFIED",
            SmfState::SessionReleased => "SESSION_RELEASED",
            SmfState::Timeout => "TIMEOUT",
            SmfState::StaleFenceRejected => "STALE_FENCE_REJECTED",
        }
    }
}

#[derive(Debug)]
pub struct SmfSimulator {
    pub name: String,
    pub state: SmfState,
    pub lease_owner: Option<String>,
    pub current_fence: u64,
    pub timeout_injected: bool,
    pub failure_injected: bool,
}

impl SmfSimulator {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            state: SmfState::Idle,
            lease_owner: None,
            current_fence: 0,
            timeout_injected: false,
            failure_injected: false,
        }
    }

    pub fn get_state(&self, key: &str) -> Option<String> {
        match key {
            "state" => Some(self.state.as_str().to_string()),
            "lease_owner" => self.lease_owner.clone(),
            "current_fence" => Some(self.current_fence.to_string()),
            "timeout_injected" => Some(self.timeout_injected.to_string()),
            "failure_injected" => Some(self.failure_injected.to_string()),
            _ => None,
        }
    }

    pub fn get_all_state(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("state".to_string(), self.state.as_str().to_string());
        if let Some(owner) = &self.lease_owner {
            map.insert("lease_owner".to_string(), owner.clone());
        }
        map.insert("current_fence".to_string(), self.current_fence.to_string());
        map.insert(
            "timeout_injected".to_string(),
            self.timeout_injected.to_string(),
        );
        map.insert(
            "failure_injected".to_string(),
            self.failure_injected.to_string(),
        );
        map
    }

    pub fn handle_step(&mut self, step: &Step) -> Result<(), crate::TestbedError> {
        match step {
            Step::SendNgap { message, .. } => {
                let msg = message.trim().to_lowercase();
                if self.timeout_injected {
                    self.state = SmfState::Timeout;
                    return Err(crate::TestbedError::Simulator("SMF request timeout".into()));
                }
                if msg.contains("establish") {
                    let mut fence = 1;
                    let mut owner = "default".to_string();
                    for part in msg.split(':') {
                        if let Some(stripped) = part.strip_prefix("owner=") {
                            owner = stripped.to_string();
                        } else if let Some(stripped) = part.strip_prefix("fence=") {
                            if let Ok(f) = stripped.parse::<u64>() {
                                fence = f;
                            }
                        }
                    }
                    if fence < self.current_fence {
                        self.state = SmfState::StaleFenceRejected;
                        return Err(crate::TestbedError::Simulator(
                            "Stale fence rejected".into(),
                        ));
                    }
                    self.current_fence = fence;
                    self.lease_owner = Some(owner);
                    self.state = SmfState::SessionEstablished;
                } else if msg.contains("modify") {
                    if self.state != SmfState::SessionEstablished
                        && self.state != SmfState::SessionModified
                    {
                        return Err(crate::TestbedError::Simulator(
                            "Invalid transition: modify requires established session".into(),
                        ));
                    }
                    self.state = SmfState::SessionModified;
                } else if msg.contains("release") {
                    self.lease_owner = None;
                    self.state = SmfState::SessionReleased;
                } else {
                    return Err(crate::TestbedError::Simulator(format!(
                        "unknown message: {message}"
                    )));
                }
            }
            Step::DependencyTimeout { .. } => {
                self.timeout_injected = true;
                self.state = SmfState::Timeout;
            }
            Step::PeerUnavailable { .. } => {
                self.failure_injected = true;
            }
            Step::ProcessRestart { .. } => {
                self.timeout_injected = false;
                self.failure_injected = false;
                self.state = SmfState::Idle;
            }
            _ => {}
        }
        Ok(())
    }
}
