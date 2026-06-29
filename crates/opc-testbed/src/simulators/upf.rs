//! Procedure-faithful UPF peer simulator (fidelity = "procedure_faithful").

use crate::scenario::Step;
use crate::TestbedError;
use std::collections::HashMap;

/// Stable profile label for SDK-decoded user-plane simulator messages.
pub const UPF_USER_PLANE_DECODE_PROFILE: &str = "opc-protocol+gtpu-esp-user-plane-decoded";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpfState {
    Idle,
    Associated,
    Unreachable,
    PreflightFailed,
    MalformedRejected,
}

impl UpfState {
    pub fn as_str(self) -> &'static str {
        match self {
            UpfState::Idle => "IDLE",
            UpfState::Associated => "ASSOCIATED",
            UpfState::Unreachable => "UNREACHABLE",
            UpfState::PreflightFailed => "PREFLIGHT_FAILED",
            UpfState::MalformedRejected => "MALFORMED_REJECTED",
        }
    }
}

/// Product-neutral user-plane evidence kind accepted by [`UpfSimulator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserPlaneMessageKind {
    /// GTP-U G-PDU packet metadata.
    GtpuGpdu,
    /// ESP continuity evidence keyed by SPI.
    EspContinuity,
    /// XFRM dataplane readiness or probe evidence.
    XfrmDataplaneEvidence,
}

impl UserPlaneMessageKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::GtpuGpdu => "GTPU_GPDU",
            Self::EspContinuity => "ESP_CONTINUITY",
            Self::XfrmDataplaneEvidence => "XFRM_DATAPLANE_EVIDENCE",
        }
    }
}

/// User-plane continuity state observed by decoded-message adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserPlaneContinuityState {
    /// No continuity evidence has been observed yet.
    Unknown,
    /// Packets/evidence prove the user plane is currently continuous.
    Established,
    /// Evidence indicates the user plane is interrupted.
    Interrupted,
    /// Evidence indicates continuity was restored after interruption.
    Restored,
}

impl UserPlaneContinuityState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::Established => "ESTABLISHED",
            Self::Interrupted => "INTERRUPTED",
            Self::Restored => "RESTORED",
        }
    }
}

/// SDK-decoded user-plane message view accepted by [`UpfSimulator`].
///
/// Implement this trait for thin adapters over SDK protocol-crate decoded
/// values. The simulator stores only counters, TEID/SPI metadata, extension
/// presence, and a deterministic hash of `session_identity`, never raw packet
/// bytes or subscriber identifiers.
pub trait UserPlaneMessageView {
    /// Return the decoded user-plane evidence kind.
    fn kind(&self) -> UserPlaneMessageKind;

    /// Return an optional product/session identity. The simulator hashes this
    /// value before exposing it through state.
    fn session_identity(&self) -> Option<&str>;

    /// Return the GTP-U TEID when the decoded evidence carries one.
    fn teid(&self) -> Option<u32>;

    /// Return the ESP/XFRM SPI when the decoded evidence carries one.
    fn spi(&self) -> Option<u32>;

    /// Return whether a decoded GTP-U extension header chain was present.
    fn has_extension_headers(&self) -> bool;

    /// Return continuity state carried by the decoded evidence.
    fn continuity_state(&self) -> UserPlaneContinuityState;

    /// Stable malformed reason code, if the SDK decoder rejected this evidence.
    fn malformed_reason(&self) -> Option<&'static str> {
        None
    }
}

/// Event returned after the UPF simulator records decoded user-plane evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpfUserPlaneEvent {
    /// Decoded evidence kind.
    pub kind: UserPlaneMessageKind,
    /// Redaction-safe deterministic session evidence key.
    pub session_key: Option<String>,
    /// GTP-U TEID observed in the decoded view.
    pub teid: Option<u32>,
    /// ESP/XFRM SPI observed in the decoded view.
    pub spi: Option<u32>,
    /// Whether GTP-U extension headers were present.
    pub extension_headers_present: bool,
    /// Continuity state after processing the event.
    pub continuity_state: UserPlaneContinuityState,
    /// Simulator state after processing the event.
    pub state: UpfState,
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
    pub accepted_packets: u64,
    pub malformed_packets: u64,
    pub extension_header_packets: u64,
    pub continuity_state: UserPlaneContinuityState,
    pub last_message_kind: Option<UserPlaneMessageKind>,
    pub last_session_key: Option<String>,
    pub last_teid: Option<u32>,
    pub last_spi: Option<u32>,
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
            accepted_packets: 0,
            malformed_packets: 0,
            extension_header_packets: 0,
            continuity_state: UserPlaneContinuityState::Unknown,
            last_message_kind: None,
            last_session_key: None,
            last_teid: None,
            last_spi: None,
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
            "accepted_packets" => Some(self.accepted_packets.to_string()),
            "malformed_packets" => Some(self.malformed_packets.to_string()),
            "extension_header_packets" => Some(self.extension_header_packets.to_string()),
            "continuity_state" => Some(self.continuity_state.as_str().to_string()),
            "last_message_kind" => self.last_message_kind.map(|kind| kind.as_str().to_string()),
            "last_session_key" => self.last_session_key.clone(),
            "last_teid" => self.last_teid.map(|teid| teid.to_string()),
            "last_spi" => self.last_spi.map(|spi| spi.to_string()),
            "sdk_protocol_profile" => Some(UPF_USER_PLANE_DECODE_PROFILE.to_string()),
            _ => None,
        }
    }

    pub fn get_all_state(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for key in [
            "state",
            "association_active",
            "dataplane_ready",
            "flow_counter",
            "flow_threshold",
            "alarm_active",
            "accepted_packets",
            "malformed_packets",
            "extension_header_packets",
            "continuity_state",
            "last_message_kind",
            "last_session_key",
            "last_teid",
            "last_spi",
            "sdk_protocol_profile",
        ] {
            if let Some(value) = self.get_state(key) {
                map.insert(key.to_string(), value);
            }
        }
        map
    }

    /// Record SDK-decoded user-plane metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the decoded view reports a malformed packet or the
    /// dataplane has been faulted unavailable.
    pub fn handle_sdk_message(
        &mut self,
        message: &impl UserPlaneMessageView,
    ) -> Result<UpfUserPlaneEvent, TestbedError> {
        if matches!(
            self.state,
            UpfState::Unreachable | UpfState::PreflightFailed
        ) {
            self.record_malformed_packet();
            return Err(TestbedError::Simulator(format!(
                "UPF simulator '{}' dataplane is unavailable",
                self.name
            )));
        }
        if let Some(reason) = message.malformed_reason() {
            self.record_malformed_packet();
            return Err(TestbedError::Simulator(format!(
                "UPF SDK decoded user-plane evidence rejected: {reason}"
            )));
        }

        self.accepted_packets = self.accepted_packets.checked_add(1).ok_or_else(|| {
            TestbedError::Simulator("UPF accepted-packet counter overflow".into())
        })?;
        self.flow_counter = self
            .flow_counter
            .checked_add(1)
            .ok_or_else(|| TestbedError::Simulator("UPF flow counter overflow".into()))?;
        if self.flow_counter > self.flow_threshold {
            self.alarm_active = true;
        }

        let kind = message.kind();
        let continuity_state = normalized_continuity(kind, message.continuity_state());
        let session_key = message.session_identity().map(redaction_safe_session_key);

        if message.has_extension_headers() {
            self.extension_header_packets = self
                .extension_header_packets
                .checked_add(1)
                .ok_or_else(|| {
                    TestbedError::Simulator("UPF extension-header counter overflow".into())
                })?;
        }
        self.last_message_kind = Some(kind);
        self.last_session_key.clone_from(&session_key);
        self.last_teid = message.teid();
        self.last_spi = message.spi();
        self.continuity_state = continuity_state;

        match continuity_state {
            UserPlaneContinuityState::Interrupted => {
                self.dataplane_ready = false;
                self.alarm_active = true;
                self.state = UpfState::PreflightFailed;
            }
            UserPlaneContinuityState::Established | UserPlaneContinuityState::Restored => {
                self.dataplane_ready = true;
                self.association_active = true;
                self.state = UpfState::Associated;
            }
            UserPlaneContinuityState::Unknown => {}
        }

        Ok(UpfUserPlaneEvent {
            kind,
            session_key,
            teid: message.teid(),
            spi: message.spi(),
            extension_headers_present: message.has_extension_headers(),
            continuity_state,
            state: self.state,
        })
    }

    /// Record a malformed user-plane decode outcome.
    ///
    /// # Errors
    ///
    /// Always returns a simulator error after updating rejection counters.
    pub fn record_decode_failure(&mut self, reason: &'static str) -> Result<(), TestbedError> {
        self.record_malformed_packet();
        Err(TestbedError::Simulator(format!(
            "UPF SDK user-plane decode failed: {reason}"
        )))
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
                let name = self.name.clone();
                *self = Self::new(name);
            }
            _ => {}
        }
        Ok(())
    }

    fn record_malformed_packet(&mut self) {
        self.malformed_packets = self.malformed_packets.saturating_add(1);
        self.continuity_state = UserPlaneContinuityState::Interrupted;
        self.dataplane_ready = false;
        self.alarm_active = true;
        self.state = UpfState::MalformedRejected;
    }
}

fn normalized_continuity(
    kind: UserPlaneMessageKind,
    continuity: UserPlaneContinuityState,
) -> UserPlaneContinuityState {
    if continuity != UserPlaneContinuityState::Unknown {
        return continuity;
    }
    match kind {
        UserPlaneMessageKind::GtpuGpdu => UserPlaneContinuityState::Established,
        UserPlaneMessageKind::EspContinuity | UserPlaneMessageKind::XfrmDataplaneEvidence => {
            UserPlaneContinuityState::Unknown
        }
    }
}

fn redaction_safe_session_key(raw: &str) -> String {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for byte in raw.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("session:{hash:016x}")
}
