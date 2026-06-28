//! EPC and untrusted-access peer simulator skeletons.
//!
//! PGW S2b peer simulator skeleton (fidelity = "stateful-mock", experimental).
//! Diameter peer simulator skeleton (fidelity = "stateful-mock", experimental).
//!
//! These simulators are deliberately product-neutral mechanics for testbeds:
//! they record SDK-decoded protocol events and expose deterministic state for
//! assertions. They do not choose APN/realm policy, subscriber authorization,
//! charging behavior, or ePDG attach orchestration.
//!
//! RFC 012 fidelity: the [`PgwS2bSimulator`] decoded-message interface and the
//! [`DiameterPeerSimulator`] decoded-metadata interface are both experimental
//! `stateful-mock` skeletons. They are not procedure-faithful simulators,
//! conformance simulators, or production EPC/ePDG peers.

use crate::TestbedError;
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, ProtocolVersion, UnknownIePolicy, ValidationLevel,
};
use std::collections::HashMap;

/// Shared decode profile used by EPC/ePDG simulator interfaces.
///
/// The profile is built from `opc-protocol` controls so simulator callers can
/// configure protocol crates consistently without adding local parsers to
/// `opc-testbed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdkDecodeProfile {
    /// Decode context to pass to the SDK protocol crate before calling the
    /// simulator's decoded-message interface.
    pub context: DecodeContext,
}

impl SdkDecodeProfile {
    /// Procedure-aware S2b profile for `opc-proto-gtpv2c` typed views.
    pub const fn s2b_procedure_aware() -> Self {
        Self {
            context: DecodeContext {
                protocol_version: ProtocolVersion::new(2),
                max_depth: 8,
                max_ies: 128,
                max_message_len: 8192,
                unknown_ie_policy: UnknownIePolicy::Preserve,
                duplicate_ie_policy: DuplicateIePolicy::Reject,
                validation_level: ValidationLevel::ProcedureAware,
                allocation_budget: opc_protocol::AllocationBudget::FAST_PATH,
            },
        }
    }

    /// Transport-neutral Diameter profile for `opc-proto-diameter` decoded
    /// views and compatible product adapters.
    ///
    /// This profile intentionally names only generic parser limits. The
    /// Diameter peer simulator does not parse bytes by itself.
    pub const fn diameter_transport_neutral() -> Self {
        Self {
            context: DecodeContext {
                protocol_version: ProtocolVersion::new(1),
                max_depth: 8,
                max_ies: 256,
                max_message_len: 65_535,
                unknown_ie_policy: UnknownIePolicy::Preserve,
                duplicate_ie_policy: DuplicateIePolicy::Reject,
                validation_level: ValidationLevel::Strict,
                allocation_budget: opc_protocol::AllocationBudget::FAST_PATH,
            },
        }
    }
}

/// Request/response direction shared by EPC control-plane simulators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerMessageDirection {
    /// Request message.
    Request,
    /// Response or answer message.
    Response,
}

impl PeerMessageDirection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Request => "REQUEST",
            Self::Response => "RESPONSE",
        }
    }
}

/// S2b procedures currently understood by the PGW S2b simulator skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum S2bProcedure {
    /// GTPv2-C Echo request/response.
    Echo,
    /// S2b Create Session request/response.
    CreateSession,
    /// S2b Modify Session, represented by GTPv2-C Modify Bearer.
    ModifyBearer,
    /// S2b Delete Session request/response.
    DeleteSession,
    /// S2b Update Session, represented by GTPv2-C Update Bearer.
    UpdateSession,
    /// Unsupported or future message type preserved by the SDK protocol crate.
    Unsupported(u8),
}

impl S2bProcedure {
    fn as_str(self) -> &'static str {
        match self {
            Self::Echo => "ECHO",
            Self::CreateSession => "CREATE_SESSION",
            Self::ModifyBearer => "MODIFY_BEARER",
            Self::DeleteSession => "DELETE_SESSION",
            Self::UpdateSession => "UPDATE_SESSION",
            Self::Unsupported(_) => "UNSUPPORTED",
        }
    }
}

/// SDK-decoded S2b message view accepted by [`PgwS2bSimulator`].
///
/// Implement this trait for thin adapters over SDK protocol-crate decoded
/// message types, such as `opc-proto-gtpv2c::S2bMessage`. The simulator accepts
/// this decoded view instead of raw bytes so it never grows a local ePDG parser.
pub trait S2bMessageView {
    /// Return the S2b procedure represented by the decoded message.
    fn procedure(&self) -> S2bProcedure;

    /// Return whether the decoded message is a request or response.
    fn direction(&self) -> PeerMessageDirection;

    /// Return the GTPv2-C sequence number.
    fn sequence_number(&self) -> u32;

    /// Return the TEID/GRE key from the GTPv2-C common header, if present.
    fn teid(&self) -> Option<u32>;

    /// Return true if the protocol crate retained raw bytes for byte-exact
    /// forwarding or evidence.
    fn raw_preserving_view(&self) -> bool;
}

/// PGW S2b simulator state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgwS2bState {
    /// No SDK-decoded S2b message has been observed.
    Idle,
    /// Echo liveness message observed.
    EchoSeen,
    /// A create-session request has opened synthetic session state.
    SessionCreated,
    /// A modify/update request has changed synthetic session state.
    SessionModified,
    /// A delete-session request has released synthetic session state.
    SessionDeleted,
    /// A peer failure was injected by the testbed.
    PeerUnavailable,
    /// A decode or semantic rejection was recorded.
    MalformedRejected,
}

impl PgwS2bState {
    /// Return a stable assertion-friendly state label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "IDLE",
            Self::EchoSeen => "ECHO_SEEN",
            Self::SessionCreated => "SESSION_CREATED",
            Self::SessionModified => "SESSION_MODIFIED",
            Self::SessionDeleted => "SESSION_DELETED",
            Self::PeerUnavailable => "PEER_UNAVAILABLE",
            Self::MalformedRejected => "MALFORMED_REJECTED",
        }
    }
}

/// Event returned after the PGW S2b simulator records a decoded message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgwS2bEvent {
    /// Procedure observed by the simulator.
    pub procedure: S2bProcedure,
    /// Direction observed by the simulator.
    pub direction: PeerMessageDirection,
    /// Sequence number copied from the SDK-decoded message.
    pub sequence_number: u32,
    /// Optional TEID/GRE key copied from the SDK-decoded message.
    pub teid: Option<u32>,
    /// Simulator state after processing the event.
    pub state: PgwS2bState,
}

/// Product-neutral PGW S2b simulator skeleton.
///
/// RFC 012 fidelity = "stateful-mock" (experimental). This is not a
/// procedure-faithful S2b conformance simulator and not a production PGW/ePDG
/// control plane.
#[derive(Debug, Clone)]
pub struct PgwS2bSimulator {
    /// Simulator instance name.
    pub name: String,
    /// Current synthetic state.
    pub state: PgwS2bState,
    /// Decode profile callers should use with the SDK protocol crate.
    pub decode_profile: SdkDecodeProfile,
    /// Count of SDK-decoded S2b messages accepted by the simulator.
    pub accepted_messages: u64,
    /// Count of malformed or semantically rejected messages.
    pub rejected_messages: u64,
    /// Count of messages whose SDK-decoded view retained raw bytes.
    pub raw_preserving_messages: u64,
    /// Count of synthetic active sessions.
    pub active_sessions: u64,
    /// Last observed sequence number.
    pub last_sequence_number: Option<u32>,
    /// Last observed TEID/GRE key.
    pub last_teid: Option<u32>,
    /// Last observed procedure.
    pub last_procedure: Option<S2bProcedure>,
    /// Last observed request/response direction.
    pub last_direction: Option<PeerMessageDirection>,
}

impl PgwS2bSimulator {
    /// Construct a PGW S2b simulator with the procedure-aware S2b profile.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            state: PgwS2bState::Idle,
            decode_profile: SdkDecodeProfile::s2b_procedure_aware(),
            accepted_messages: 0,
            rejected_messages: 0,
            raw_preserving_messages: 0,
            active_sessions: 0,
            last_sequence_number: None,
            last_teid: None,
            last_procedure: None,
            last_direction: None,
        }
    }

    /// Record an SDK-decoded S2b message.
    ///
    /// # Errors
    ///
    /// Returns an error when an unsupported procedure is presented, when a
    /// state-changing request arrives while no synthetic session exists, or
    /// when a failure injection has placed the simulator in a peer-unavailable
    /// state.
    pub fn handle_sdk_message(
        &mut self,
        message: &impl S2bMessageView,
    ) -> Result<PgwS2bEvent, TestbedError> {
        if self.state == PgwS2bState::PeerUnavailable {
            self.record_unavailable_rejection();
            return Err(TestbedError::Simulator(format!(
                "PGW S2b simulator '{}' is unavailable",
                self.name
            )));
        }
        if self.state == PgwS2bState::MalformedRejected {
            self.record_rejection();
            return Err(TestbedError::Simulator(format!(
                "PGW S2b simulator '{}' requires restart after previous rejection",
                self.name
            )));
        }

        let procedure = message.procedure();
        let direction = message.direction();
        match procedure {
            S2bProcedure::Echo => {
                self.state = PgwS2bState::EchoSeen;
            }
            S2bProcedure::CreateSession => {
                if direction == PeerMessageDirection::Request {
                    self.active_sessions =
                        self.active_sessions.checked_add(1).ok_or_else(|| {
                            TestbedError::Simulator("PGW S2b session counter overflow".into())
                        })?;
                    self.state = PgwS2bState::SessionCreated;
                }
            }
            S2bProcedure::ModifyBearer | S2bProcedure::UpdateSession => {
                if direction == PeerMessageDirection::Request {
                    self.require_active_session(procedure)?;
                    self.state = PgwS2bState::SessionModified;
                }
            }
            S2bProcedure::DeleteSession => {
                if direction == PeerMessageDirection::Request {
                    self.require_active_session(procedure)?;
                    self.active_sessions = self.active_sessions.saturating_sub(1);
                    self.state = PgwS2bState::SessionDeleted;
                }
            }
            S2bProcedure::Unsupported(message_type) => {
                self.record_rejection();
                return Err(TestbedError::Simulator(format!(
                    "unsupported S2b message type {message_type}"
                )));
            }
        }

        self.accepted_messages = self.accepted_messages.checked_add(1).ok_or_else(|| {
            TestbedError::Simulator("PGW S2b accepted-message counter overflow".into())
        })?;
        if message.raw_preserving_view() {
            self.raw_preserving_messages =
                self.raw_preserving_messages.checked_add(1).ok_or_else(|| {
                    TestbedError::Simulator("PGW S2b raw-preserving counter overflow".into())
                })?;
        }
        self.last_sequence_number = Some(message.sequence_number());
        self.last_teid = message.teid();
        self.last_procedure = Some(procedure);
        self.last_direction = Some(direction);

        Ok(PgwS2bEvent {
            procedure,
            direction,
            sequence_number: message.sequence_number(),
            teid: message.teid(),
            state: self.state,
        })
    }

    /// Record a decode failure reported by the SDK protocol crate.
    ///
    /// # Errors
    ///
    /// Always returns a simulator error after updating rejection counters.
    pub fn record_decode_failure(&mut self, reason: impl Into<String>) -> Result<(), TestbedError> {
        self.record_rejection();
        Err(TestbedError::Simulator(format!(
            "PGW S2b SDK decode failed: {}",
            reason.into()
        )))
    }

    /// Mark the peer unavailable for fault-injection scenarios.
    pub fn mark_peer_unavailable(&mut self) {
        self.state = PgwS2bState::PeerUnavailable;
    }

    /// Reset transient state after a simulated process restart.
    pub fn restart(&mut self) {
        let name = self.name.clone();
        *self = Self::new(name);
    }

    /// Return a single assertion-friendly state value.
    pub fn get_state(&self, key: &str) -> Option<String> {
        match key {
            "state" => Some(self.state.as_str().to_string()),
            "accepted_messages" => Some(self.accepted_messages.to_string()),
            "rejected_messages" => Some(self.rejected_messages.to_string()),
            "raw_preserving_messages" => Some(self.raw_preserving_messages.to_string()),
            "active_sessions" => Some(self.active_sessions.to_string()),
            "last_sequence_number" => self.last_sequence_number.map(|value| value.to_string()),
            "last_teid" => self.last_teid.map(|value| value.to_string()),
            "last_procedure" => self.last_procedure.map(|value| value.as_str().to_string()),
            "last_direction" => self.last_direction.map(|value| value.as_str().to_string()),
            "sdk_protocol_profile" => Some("opc-protocol+s2b-procedure-aware".to_string()),
            _ => None,
        }
    }

    /// Return all assertion-friendly state values.
    pub fn get_all_state(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for key in [
            "state",
            "accepted_messages",
            "rejected_messages",
            "raw_preserving_messages",
            "active_sessions",
            "last_sequence_number",
            "last_teid",
            "last_procedure",
            "last_direction",
            "sdk_protocol_profile",
        ] {
            if let Some(value) = self.get_state(key) {
                map.insert(key.to_string(), value);
            }
        }
        map
    }

    fn require_active_session(&mut self, procedure: S2bProcedure) -> Result<(), TestbedError> {
        if self.active_sessions == 0 {
            self.record_rejection();
            return Err(TestbedError::Simulator(format!(
                "S2b {} request requires an active synthetic session",
                procedure.as_str()
            )));
        }
        Ok(())
    }

    fn record_rejection(&mut self) {
        self.rejected_messages = self.rejected_messages.saturating_add(1);
        self.active_sessions = 0;
        self.state = PgwS2bState::MalformedRejected;
    }

    fn record_unavailable_rejection(&mut self) {
        self.rejected_messages = self.rejected_messages.saturating_add(1);
    }
}

const DIAMETER_APP_BASE: u32 = 0;
const DIAMETER_APP_3GPP_RF_ACCOUNTING: u32 = 3;
const DIAMETER_APP_3GPP_GX: u32 = 16_777_238;
const DIAMETER_APP_3GPP_S6A_S6D: u32 = 16_777_251;
const DIAMETER_CC_CAPABILITIES_EXCHANGE: u32 = 257;
const DIAMETER_CC_DEVICE_WATCHDOG: u32 = 280;
const DIAMETER_CC_DISCONNECT_PEER: u32 = 282;

/// Diameter application families relevant to EPC/ePDG test peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiameterApplication {
    /// Diameter base protocol.
    Base,
    /// 3GPP S6a/S6d application family.
    S6a,
    /// 3GPP Gx application family.
    Gx,
    /// 3GPP Rf accounting application family.
    ///
    /// 3GPP TS 32.299 defines the Rf charging interface on the Diameter
    /// accounting application; RFC 6733/IANA assign that application-id as 3.
    Rf,
    /// Unknown or future Diameter application ID.
    Unknown(u32),
}

impl DiameterApplication {
    /// Map a Diameter application-id to the simulator's product-neutral family.
    pub const fn from_application_id(application_id: u32) -> Self {
        match application_id {
            DIAMETER_APP_BASE => Self::Base,
            DIAMETER_APP_3GPP_RF_ACCOUNTING => Self::Rf,
            DIAMETER_APP_3GPP_S6A_S6D => Self::S6a,
            DIAMETER_APP_3GPP_GX => Self::Gx,
            other => Self::Unknown(other),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Base => "BASE",
            Self::S6a => "S6A",
            Self::Gx => "GX",
            Self::Rf => "RF",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

/// SDK-decoded Diameter message view accepted by [`DiameterPeerSimulator`].
///
/// This trait is intentionally header/metadata-only. The experimental
/// `opc-proto-diameter` crate owns RFC 6733/3GPP AVP parsing when raw bytes are
/// involved; `opc-testbed` must not parse Diameter bytes locally.
pub trait DiameterMessageView {
    /// Return the Diameter command-code.
    fn command_code(&self) -> u32;

    /// Return the Diameter application-id.
    fn application_id(&self) -> u32;

    /// Return whether the decoded command has the request bit set.
    fn direction(&self) -> PeerMessageDirection;

    /// Return true if the decoded message carries a Session-Id AVP.
    fn has_session_id(&self) -> bool;
}

/// Diameter peer simulator state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiameterPeerState {
    /// No decoded Diameter message has been observed.
    Idle,
    /// Capabilities Exchange Request/Answer observed.
    CapabilitiesExchanged,
    /// Device Watchdog Request/Answer observed.
    WatchdogSeen,
    /// Disconnect Peer Request/Answer observed.
    DisconnectSeen,
    /// A non-base application message was observed.
    ApplicationMessageSeen,
    /// A peer failure was injected by the testbed.
    PeerUnavailable,
    /// A decode or semantic rejection was recorded.
    MalformedRejected,
}

impl DiameterPeerState {
    /// Return a stable assertion-friendly state label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "IDLE",
            Self::CapabilitiesExchanged => "CAPABILITIES_EXCHANGED",
            Self::WatchdogSeen => "WATCHDOG_SEEN",
            Self::DisconnectSeen => "DISCONNECT_SEEN",
            Self::ApplicationMessageSeen => "APPLICATION_MESSAGE_SEEN",
            Self::PeerUnavailable => "PEER_UNAVAILABLE",
            Self::MalformedRejected => "MALFORMED_REJECTED",
        }
    }
}

/// Event returned after the Diameter peer records a decoded message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiameterPeerEvent {
    /// Command-code observed by the simulator.
    pub command_code: u32,
    /// Application family observed by the simulator.
    pub application: DiameterApplication,
    /// Direction observed by the simulator.
    pub direction: PeerMessageDirection,
    /// Simulator state after processing the event.
    pub state: DiameterPeerState,
}

/// Product-neutral Diameter peer simulator skeleton.
///
/// RFC 012 fidelity = "stateful-mock" (experimental). This is not a
/// procedure-faithful Diameter conformance simulator and not a production
/// AAA/HSS/CDF peer.
#[derive(Debug, Clone)]
pub struct DiameterPeerSimulator {
    /// Simulator instance name.
    pub name: String,
    /// Current synthetic state.
    pub state: DiameterPeerState,
    /// Decode profile callers should use with the SDK protocol crate.
    pub decode_profile: SdkDecodeProfile,
    /// Count of SDK-decoded Diameter messages accepted by the simulator.
    pub accepted_messages: u64,
    /// Count of malformed or semantically rejected messages.
    pub rejected_messages: u64,
    /// Count of Capabilities Exchange commands observed.
    pub capability_messages: u64,
    /// Count of Device Watchdog commands observed.
    pub watchdog_messages: u64,
    /// Count of application messages with a Session-Id AVP.
    pub session_messages: u64,
    /// Last observed command-code.
    pub last_command_code: Option<u32>,
    /// Last observed Diameter application family.
    pub last_application: Option<DiameterApplication>,
    /// Last observed request/response direction.
    pub last_direction: Option<PeerMessageDirection>,
}

impl DiameterPeerSimulator {
    /// Construct a Diameter peer simulator with the transport-neutral profile.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            state: DiameterPeerState::Idle,
            decode_profile: SdkDecodeProfile::diameter_transport_neutral(),
            accepted_messages: 0,
            rejected_messages: 0,
            capability_messages: 0,
            watchdog_messages: 0,
            session_messages: 0,
            last_command_code: None,
            last_application: None,
            last_direction: None,
        }
    }

    /// Record an SDK-decoded Diameter message.
    ///
    /// # Errors
    ///
    /// Returns an error when a decoded message is presented while the peer is
    /// unavailable or when counters overflow.
    pub fn handle_sdk_message(
        &mut self,
        message: &impl DiameterMessageView,
    ) -> Result<DiameterPeerEvent, TestbedError> {
        if self.state == DiameterPeerState::PeerUnavailable {
            self.record_unavailable_rejection();
            return Err(TestbedError::Simulator(format!(
                "Diameter simulator '{}' is unavailable",
                self.name
            )));
        }
        if self.state == DiameterPeerState::MalformedRejected {
            self.record_rejection();
            return Err(TestbedError::Simulator(format!(
                "Diameter simulator '{}' requires restart after previous rejection",
                self.name
            )));
        }

        let command_code = message.command_code();
        let application = DiameterApplication::from_application_id(message.application_id());
        let direction = message.direction();

        match command_code {
            DIAMETER_CC_CAPABILITIES_EXCHANGE => {
                self.capability_messages =
                    self.capability_messages.checked_add(1).ok_or_else(|| {
                        TestbedError::Simulator(
                            "Diameter capability-message counter overflow".into(),
                        )
                    })?;
                self.state = DiameterPeerState::CapabilitiesExchanged;
            }
            DIAMETER_CC_DEVICE_WATCHDOG => {
                self.watchdog_messages =
                    self.watchdog_messages.checked_add(1).ok_or_else(|| {
                        TestbedError::Simulator("Diameter watchdog counter overflow".into())
                    })?;
                self.state = DiameterPeerState::WatchdogSeen;
            }
            DIAMETER_CC_DISCONNECT_PEER => {
                self.state = DiameterPeerState::DisconnectSeen;
            }
            _ => {
                self.state = DiameterPeerState::ApplicationMessageSeen;
            }
        }

        if message.has_session_id() {
            self.session_messages = self.session_messages.checked_add(1).ok_or_else(|| {
                TestbedError::Simulator("Diameter session-message counter overflow".into())
            })?;
        }
        self.accepted_messages = self.accepted_messages.checked_add(1).ok_or_else(|| {
            TestbedError::Simulator("Diameter accepted-message counter overflow".into())
        })?;
        self.last_command_code = Some(command_code);
        self.last_application = Some(application);
        self.last_direction = Some(direction);

        Ok(DiameterPeerEvent {
            command_code,
            application,
            direction,
            state: self.state,
        })
    }

    /// Record a decode failure reported by the SDK protocol crate.
    ///
    /// # Errors
    ///
    /// Always returns a simulator error after updating rejection counters.
    pub fn record_decode_failure(&mut self, reason: impl Into<String>) -> Result<(), TestbedError> {
        self.record_rejection();
        Err(TestbedError::Simulator(format!(
            "Diameter SDK decode failed: {}",
            reason.into()
        )))
    }

    /// Mark the peer unavailable for fault-injection scenarios.
    pub fn mark_peer_unavailable(&mut self) {
        self.state = DiameterPeerState::PeerUnavailable;
    }

    /// Reset transient state after a simulated process restart.
    pub fn restart(&mut self) {
        let name = self.name.clone();
        *self = Self::new(name);
    }

    /// Return a single assertion-friendly state value.
    pub fn get_state(&self, key: &str) -> Option<String> {
        match key {
            "state" => Some(self.state.as_str().to_string()),
            "accepted_messages" => Some(self.accepted_messages.to_string()),
            "rejected_messages" => Some(self.rejected_messages.to_string()),
            "capability_messages" => Some(self.capability_messages.to_string()),
            "watchdog_messages" => Some(self.watchdog_messages.to_string()),
            "session_messages" => Some(self.session_messages.to_string()),
            "last_command_code" => self.last_command_code.map(|value| value.to_string()),
            "last_application" => self
                .last_application
                .map(|value| value.as_str().to_string()),
            "last_direction" => self.last_direction.map(|value| value.as_str().to_string()),
            "sdk_protocol_profile" => Some("opc-protocol+diameter-transport-neutral".to_string()),
            _ => None,
        }
    }

    /// Return all assertion-friendly state values.
    pub fn get_all_state(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for key in [
            "state",
            "accepted_messages",
            "rejected_messages",
            "capability_messages",
            "watchdog_messages",
            "session_messages",
            "last_command_code",
            "last_application",
            "last_direction",
            "sdk_protocol_profile",
        ] {
            if let Some(value) = self.get_state(key) {
                map.insert(key.to_string(), value);
            }
        }
        map
    }

    fn record_rejection(&mut self) {
        self.rejected_messages = self.rejected_messages.saturating_add(1);
        self.state = DiameterPeerState::MalformedRejected;
    }

    fn record_unavailable_rejection(&mut self) {
        self.rejected_messages = self.rejected_messages.saturating_add(1);
    }
}
