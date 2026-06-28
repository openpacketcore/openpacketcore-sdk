//! Peer simulators (RFC 012 §9).
//!
//! Each simulator declares a fidelity level and exposes deterministic
//! state for assertions. This module contains the fake/stub implementations
//! used for early scenario development and unit testing of the framework.

pub mod amf;
pub mod epc;
pub mod fake;
pub mod smf;
pub mod upf;

pub use amf::{AmfSimulator, AmfState};
pub use epc::{
    DiameterApplication, DiameterMessageView, DiameterPeerEvent, DiameterPeerSimulator,
    DiameterPeerState, PeerMessageDirection, PgwS2bEvent, PgwS2bSimulator, PgwS2bState,
    S2bMessageView, S2bProcedure, SdkDecodeProfile,
};
pub use fake::{FakeSimulator, Fidelity};
pub use smf::{SmfSimulator, SmfState};
pub use upf::{UpfSimulator, UpfState};

use crate::scenario::{NfSpec, Step};
use std::collections::HashMap;

#[derive(Debug)]
pub enum Simulator {
    Fake(FakeSimulator),
    Amf(AmfSimulator),
    Smf(SmfSimulator),
    Upf(UpfSimulator),
    PgwS2b(PgwS2bSimulator),
    DiameterPeer(DiameterPeerSimulator),
}

impl Simulator {
    pub fn from_spec(name: &str, spec: &NfSpec) -> Result<Self, crate::TestbedError> {
        match spec.simulator.as_deref() {
            Some("fake") => Ok(Simulator::Fake(FakeSimulator::new(name, Fidelity::Stub))),
            Some("amf") => Ok(Simulator::Amf(AmfSimulator::new(name))),
            Some("smf") => Ok(Simulator::Smf(SmfSimulator::new(name))),
            Some("upf") => Ok(Simulator::Upf(UpfSimulator::new(name))),
            Some("pgw-s2b") => Ok(Simulator::PgwS2b(PgwS2bSimulator::new(name))),
            Some("diameter-peer") => Ok(Simulator::DiameterPeer(DiameterPeerSimulator::new(name))),
            Some(other) => Err(crate::TestbedError::Simulator(format!(
                "unsupported simulator '{other}' for '{name}'"
            ))),
            None => Err(crate::TestbedError::Simulator(format!(
                "no simulator specified for '{name}'"
            ))),
        }
    }

    pub fn get_state(&self, key: &str) -> Option<String> {
        match self {
            Simulator::Fake(ref sim) => sim.get_state(key).map(|s| s.to_string()),
            Simulator::Amf(ref sim) => sim.get_state(key),
            Simulator::Smf(ref sim) => sim.get_state(key),
            Simulator::Upf(ref sim) => sim.get_state(key),
            Simulator::PgwS2b(ref sim) => sim.get_state(key),
            Simulator::DiameterPeer(ref sim) => sim.get_state(key),
        }
    }

    pub fn get_all_state(&self) -> HashMap<String, String> {
        match self {
            Simulator::Fake(ref sim) => {
                let mut map = HashMap::new();
                if let Some(s) = sim.get_state("state") {
                    map.insert("state".to_string(), s.to_string());
                }
                map
            }
            Simulator::Amf(ref sim) => sim.get_all_state(),
            Simulator::Smf(ref sim) => sim.get_all_state(),
            Simulator::Upf(ref sim) => sim.get_all_state(),
            Simulator::PgwS2b(ref sim) => sim.get_all_state(),
            Simulator::DiameterPeer(ref sim) => sim.get_all_state(),
        }
    }

    pub fn handle_step(&mut self, step: &Step) -> Result<(), crate::TestbedError> {
        match self {
            Simulator::Fake(ref mut sim) => match step {
                Step::SendNgap { message, .. } => {
                    let step_kind = match message.trim().to_lowercase().as_str() {
                        "registration" | "initialuemessage.registration_request" => "registration",
                        "session"
                        | "pdusessionresourcesetup.session_establishment"
                        | "pdusessionresourcesetuprequest.session_establishment" => "session",
                        _ => message,
                    };
                    sim.handle_step(step_kind)
                }
                _ => Ok(()),
            },
            Simulator::Amf(ref mut sim) => sim.handle_step(step),
            Simulator::Smf(ref mut sim) => sim.handle_step(step),
            Simulator::Upf(ref mut sim) => sim.handle_step(step),
            Simulator::PgwS2b(ref mut sim) => match step {
                Step::PeerUnavailable { .. } | Step::DependencyTimeout { .. } => {
                    sim.mark_peer_unavailable();
                    Ok(())
                }
                Step::ProcessRestart { .. } => {
                    sim.restart();
                    Ok(())
                }
                Step::MalformedResponse { .. } => {
                    sim.record_decode_failure("malformed S2b response injected")
                }
                Step::SendNgap { .. } => Err(crate::TestbedError::Simulator(
                    "PGW S2b simulator requires SDK-decoded S2b messages; the NGAP step DSL does not carry S2b bytes".into(),
                )),
                _ => Ok(()),
            },
            Simulator::DiameterPeer(ref mut sim) => match step {
                Step::PeerUnavailable { .. } | Step::DependencyTimeout { .. } => {
                    sim.mark_peer_unavailable();
                    Ok(())
                }
                Step::ProcessRestart { .. } => {
                    sim.restart();
                    Ok(())
                }
                Step::MalformedResponse { .. } => {
                    sim.record_decode_failure("malformed Diameter response injected")
                }
                Step::SendNgap { .. } => Err(crate::TestbedError::Simulator(
                    "Diameter peer simulator requires SDK-decoded Diameter messages; the NGAP step DSL does not carry Diameter bytes".into(),
                )),
                _ => Ok(()),
            },
        }
    }
}
