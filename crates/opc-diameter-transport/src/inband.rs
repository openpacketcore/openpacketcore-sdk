use std::fmt;

use opc_proto_diameter::peer::{
    build_capabilities_exchange_request, parse_capabilities_exchange_answer,
    parse_capabilities_exchange_request, CapabilitiesExchangeAnswer, PeerCapabilities,
    PeerMessageDirection, PeerProtectionFailure, PeerProtectionMechanism, PeerProtectionPending,
    PeerProtectionPolicy, PeerProtectionRequirement, PeerProtectionSequence, PeerSession,
    PeerSessionBlocker, PeerSessionGeneration, PeerSessionPolicy,
};
use opc_protocol::{DecodeContext, EncodeContext, ValidationLevel};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::frame::{borrowed, read_frame, write_frame, write_wire_frame};
use crate::tls::{
    begin_generation, bind_inband_socket, fail_inband_socket, finish_connection,
    upgrade_client_socket, upgrade_server_socket, DiameterConnectionRole, DiameterTlsConnection,
    DiameterTlsError, DiameterTlsPolicy, ExpectedPeerIdentity, SocketShutdownGuard,
};

/// Outbound cleartext typestate before the sole permitted CER is emitted.
pub struct DiameterInbandTlsInitiator {
    tcp: TcpStream,
    shutdown: SocketShutdownGuard,
    session: PeerSession,
    generation: PeerSessionGeneration,
    tls_config: opc_tls::AuthenticatedClientConfig,
    expected_peer: ExpectedPeerIdentity,
    policy: DiameterTlsPolicy,
    server_name: ServerName<'static>,
    local_capabilities: PeerCapabilities,
}

/// Outbound cleartext typestate after CER, permitting only the correlated CEA
/// followed immediately by a TLS client handshake on the same TCP stream.
pub struct DiameterInbandTlsInitiatorAwaitingAnswer {
    tcp: TcpStream,
    shutdown: SocketShutdownGuard,
    session: PeerSession,
    generation: PeerSessionGeneration,
    tls_config: opc_tls::AuthenticatedClientConfig,
    expected_peer: ExpectedPeerIdentity,
    policy: DiameterTlsPolicy,
    server_name: ServerName<'static>,
}

/// Inbound cleartext typestate before the sole permitted CER is received.
pub struct DiameterInbandTlsResponder {
    tcp: TcpStream,
    shutdown: SocketShutdownGuard,
    session: PeerSession,
    generation: PeerSessionGeneration,
    tls_config: opc_tls::AuthenticatedServerConfig,
    expected_peer: ExpectedPeerIdentity,
    policy: DiameterTlsPolicy,
    local_capabilities: PeerCapabilities,
}

/// Inbound cleartext typestate after CER, permitting only the canonical CEA
/// followed immediately by a TLS server handshake on the same TCP stream.
pub struct DiameterInbandTlsResponderCerReceived {
    tcp: TcpStream,
    shutdown: SocketShutdownGuard,
    session: PeerSession,
    generation: PeerSessionGeneration,
    tls_config: opc_tls::AuthenticatedServerConfig,
    expected_peer: ExpectedPeerIdentity,
    policy: DiameterTlsPolicy,
    local_capabilities: PeerCapabilities,
}

pub(crate) struct InbandClientParameters {
    pub(crate) tls_config: opc_tls::AuthenticatedClientConfig,
    pub(crate) expected_peer: ExpectedPeerIdentity,
    pub(crate) policy: DiameterTlsPolicy,
    pub(crate) address: std::net::SocketAddr,
    pub(crate) server_name: ServerName<'static>,
    pub(crate) local_capabilities: PeerCapabilities,
    pub(crate) session_policy: PeerSessionPolicy,
    pub(crate) deadline: Instant,
}

pub(crate) async fn connect_inband(
    parameters: InbandClientParameters,
) -> Result<DiameterInbandTlsInitiator, DiameterTlsError> {
    let InbandClientParameters {
        tls_config,
        expected_peer,
        policy,
        address,
        server_name,
        local_capabilities,
        session_policy,
        deadline,
    } = parameters;
    let mut session = PeerSession::with_policy_and_protection(
        local_capabilities.clone(),
        session_policy,
        PeerProtectionPolicy::Require(PeerProtectionRequirement::inband_tls_tcp()),
    );
    let generation = begin_generation(&mut session, PeerProtectionRequirement::inband_tls_tcp())?;
    if session.pending_protection().is_some() {
        let _ = session.fail_on(generation, PeerSessionBlocker::SessionFailed);
        return Err(DiameterTlsError::PeerBinding);
    }
    let tcp = match tokio::time::timeout_at(deadline, TcpStream::connect(address)).await {
        Err(_) => {
            let _ = session.fail_on(generation, PeerSessionBlocker::SessionFailed);
            return Err(DiameterTlsError::DeadlineExceeded);
        }
        Ok(Err(_)) => {
            let _ = session.fail_on(generation, PeerSessionBlocker::SessionFailed);
            return Err(DiameterTlsError::Transport);
        }
        Ok(Ok(tcp)) => tcp,
    };
    let (tcp, shutdown) = match bind_inband_socket(tcp) {
        Ok(bound) => bound,
        Err(error) => {
            let _ = session.fail_on(generation, PeerSessionBlocker::SessionFailed);
            return Err(error);
        }
    };
    Ok(DiameterInbandTlsInitiator {
        tcp,
        shutdown,
        session,
        generation,
        tls_config,
        expected_peer,
        policy,
        server_name,
        local_capabilities,
    })
}

pub(crate) fn accept_inband(
    tls_config: opc_tls::AuthenticatedServerConfig,
    expected_peer: ExpectedPeerIdentity,
    policy: DiameterTlsPolicy,
    tcp: TcpStream,
    local_capabilities: PeerCapabilities,
    session_policy: PeerSessionPolicy,
) -> Result<DiameterInbandTlsResponder, DiameterTlsError> {
    let mut session = PeerSession::with_policy_and_protection(
        local_capabilities.clone(),
        session_policy,
        PeerProtectionPolicy::Require(PeerProtectionRequirement::inband_tls_tcp()),
    );
    let generation = begin_generation(&mut session, PeerProtectionRequirement::inband_tls_tcp())?;
    if session.pending_protection().is_some() {
        let _ = session.fail_on(generation, PeerSessionBlocker::SessionFailed);
        return Err(DiameterTlsError::PeerBinding);
    }
    let (tcp, shutdown) = match bind_inband_socket(tcp) {
        Ok(bound) => bound,
        Err(error) => {
            let _ = session.fail_on(generation, PeerSessionBlocker::SessionFailed);
            return Err(error);
        }
    };
    Ok(DiameterInbandTlsResponder {
        tcp,
        shutdown,
        session,
        generation,
        tls_config,
        expected_peer,
        policy,
        local_capabilities,
    })
}

impl DiameterInbandTlsInitiator {
    /// Exact candidate generation available to caller-owned simultaneous-open
    /// winner election; this transport does not elect a winner.
    pub const fn generation(&self) -> PeerSessionGeneration {
        self.generation
    }

    /// Canonically build and emit the only cleartext request permitted by this
    /// typestate. The same local capabilities construct both the session and
    /// CER, preventing split-brain capability evidence.
    pub async fn send_capabilities_request(
        mut self,
        hop_by_hop_identifier: u32,
        end_to_end_identifier: u32,
        deadline: Instant,
    ) -> Result<DiameterInbandTlsInitiatorAwaitingAnswer, DiameterTlsError> {
        let message = build_capabilities_exchange_request(
            &self.local_capabilities,
            hop_by_hop_identifier,
            end_to_end_identifier,
            encode_context(self.policy),
        )
        .map_err(|_| DiameterTlsError::CapabilitiesExchangeFailed)?;
        if self
            .session
            .admit_message(
                self.generation,
                PeerMessageDirection::Outbound,
                &message.header,
            )
            .is_err()
            || self
                .session
                .capabilities_request_sent_on(self.generation, &message.header)
                .is_err()
        {
            fail_inband_socket(&mut self.session, self.generation, self.shutdown);
            return Err(DiameterTlsError::CapabilitiesExchangeFailed);
        }
        if let Err(error) = write_frame(
            &mut self.tcp,
            &message,
            self.policy.frame_limits(),
            deadline,
        )
        .await
        {
            fail_inband_socket(&mut self.session, self.generation, self.shutdown);
            return Err(error);
        }
        Ok(DiameterInbandTlsInitiatorAwaitingAnswer {
            tcp: self.tcp,
            shutdown: self.shutdown,
            session: self.session,
            generation: self.generation,
            tls_config: self.tls_config,
            expected_peer: self.expected_peer,
            policy: self.policy,
            server_name: self.server_name,
        })
    }
}

impl DiameterInbandTlsInitiatorAwaitingAnswer {
    /// Read the exact correlated CEA without read-ahead and immediately consume
    /// this cleartext typestate into a TLS client handshake on the same stream.
    pub async fn receive_capabilities_answer_and_upgrade(
        mut self,
        deadline: Instant,
    ) -> Result<(DiameterTlsConnection, CapabilitiesExchangeAnswer), DiameterTlsError> {
        let message = match read_frame(&mut self.tcp, self.policy.frame_limits(), deadline).await {
            Ok(message) => message,
            Err(error) => {
                fail_inband_socket(&mut self.session, self.generation, self.shutdown);
                return Err(error);
            }
        };
        if self
            .session
            .admit_message(
                self.generation,
                PeerMessageDirection::Inbound,
                &message.header,
            )
            .is_err()
        {
            fail_inband_socket(&mut self.session, self.generation, self.shutdown);
            return Err(DiameterTlsError::CommandNotAdmitted);
        }
        let answer = match parse_capabilities_exchange_answer(
            &borrowed(&message),
            decode_context(self.policy),
        ) {
            Ok(answer) => answer,
            Err(_) => {
                fail_inband_socket(&mut self.session, self.generation, self.shutdown);
                return Err(DiameterTlsError::CapabilitiesExchangeFailed);
            }
        };
        if !answer
            .capabilities
            .identity
            .semantically_eq(self.expected_peer.diameter_identity())
        {
            fail_inband_socket(&mut self.session, self.generation, self.shutdown);
            return Err(DiameterTlsError::PeerIdentityMismatch);
        }
        if self
            .session
            .observe_capabilities_answer_on(self.generation, &message.header, &answer)
            .is_err()
        {
            fail_inband_socket(&mut self.session, self.generation, self.shutdown);
            return Err(DiameterTlsError::CapabilitiesExchangeFailed);
        }
        let pending = match pending_inband_tls(&self.session) {
            Ok(pending) => pending,
            Err(error) => {
                fail_inband_socket(&mut self.session, self.generation, self.shutdown);
                return Err(error);
            }
        };
        let (value, material) = match upgrade_client_socket(
            &self.tls_config,
            &self.expected_peer,
            self.policy,
            self.tcp,
            self.shutdown,
            self.server_name,
            deadline,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                fail_pending_for_transport(&mut self.session, &pending, error);
                return Err(error);
            }
        };
        let connection = finish_connection(
            value,
            material,
            self.tls_config.subscribe_material_changes(),
            self.session,
            self.generation,
            pending,
            self.expected_peer,
            DiameterConnectionRole::Connector,
            self.policy,
        )?;
        Ok((connection, answer))
    }
}

impl DiameterInbandTlsResponder {
    /// Exact candidate generation available to caller-owned simultaneous-open
    /// winner election; this transport does not elect a winner.
    pub const fn generation(&self) -> PeerSessionGeneration {
        self.generation
    }

    /// Receive exactly one cleartext CER. Any other command, malformed frame,
    /// timeout, or capability parse failure terminally closes this generation.
    pub async fn receive_capabilities_request(
        mut self,
        deadline: Instant,
    ) -> Result<(DiameterInbandTlsResponderCerReceived, PeerCapabilities), DiameterTlsError> {
        let message = match read_frame(&mut self.tcp, self.policy.frame_limits(), deadline).await {
            Ok(message) => message,
            Err(error) => {
                fail_inband_socket(&mut self.session, self.generation, self.shutdown);
                return Err(error);
            }
        };
        if self
            .session
            .admit_message(
                self.generation,
                PeerMessageDirection::Inbound,
                &message.header,
            )
            .is_err()
        {
            fail_inband_socket(&mut self.session, self.generation, self.shutdown);
            return Err(DiameterTlsError::CommandNotAdmitted);
        }
        let remote = match parse_capabilities_exchange_request(
            &borrowed(&message),
            decode_context(self.policy),
        ) {
            Ok(remote) => remote,
            Err(_) => {
                fail_inband_socket(&mut self.session, self.generation, self.shutdown);
                return Err(DiameterTlsError::CapabilitiesExchangeFailed);
            }
        };
        if !remote
            .identity
            .semantically_eq(self.expected_peer.diameter_identity())
        {
            fail_inband_socket(&mut self.session, self.generation, self.shutdown);
            return Err(DiameterTlsError::PeerIdentityMismatch);
        }
        if self
            .session
            .capabilities_request_received_on(self.generation, &message.header, remote.clone())
            .is_err()
        {
            fail_inband_socket(&mut self.session, self.generation, self.shutdown);
            return Err(DiameterTlsError::CapabilitiesExchangeFailed);
        }
        Ok((
            DiameterInbandTlsResponderCerReceived {
                tcp: self.tcp,
                shutdown: self.shutdown,
                session: self.session,
                generation: self.generation,
                tls_config: self.tls_config,
                expected_peer: self.expected_peer,
                policy: self.policy,
                local_capabilities: self.local_capabilities,
            },
            remote,
        ))
    }
}

impl DiameterInbandTlsResponderCerReceived {
    /// Prepare the one canonical generation-bound CEA, emit and flush its exact
    /// immutable bytes, then immediately consume this typestate into a TLS
    /// server handshake on the same stream.
    pub async fn send_capabilities_answer_and_upgrade(
        mut self,
        answer: &CapabilitiesExchangeAnswer,
        deadline: Instant,
    ) -> Result<DiameterTlsConnection, DiameterTlsError> {
        if answer.capabilities != self.local_capabilities {
            fail_inband_socket(&mut self.session, self.generation, self.shutdown);
            return Err(DiameterTlsError::CapabilitiesExchangeFailed);
        }
        let emission = match self.session.prepare_capabilities_answer_on(
            self.generation,
            answer,
            encode_context(self.policy),
        ) {
            Ok(emission) => emission,
            Err(_) => {
                fail_inband_socket(&mut self.session, self.generation, self.shutdown);
                return Err(DiameterTlsError::CapabilitiesExchangeFailed);
            }
        };
        if let Err(error) = write_wire_frame(
            &mut self.tcp,
            emission.as_bytes(),
            self.policy.frame_limits(),
            deadline,
        )
        .await
        {
            if let Some(pending) = self.session.pending_protection() {
                let _ = self
                    .session
                    .fail_pending_protection(&pending, PeerProtectionFailure::HandshakeFailed);
            }
            fail_inband_socket(&mut self.session, self.generation, self.shutdown);
            return Err(error);
        }
        let pending = match pending_inband_tls(&self.session) {
            Ok(pending) => pending,
            Err(error) => {
                fail_inband_socket(&mut self.session, self.generation, self.shutdown);
                return Err(error);
            }
        };
        let (value, material) = match upgrade_server_socket(
            &self.tls_config,
            &self.expected_peer,
            self.policy,
            self.tcp,
            self.shutdown,
            deadline,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                fail_pending_for_transport(&mut self.session, &pending, error);
                return Err(error);
            }
        };
        finish_connection(
            value,
            material,
            self.tls_config.subscribe_material_changes(),
            self.session,
            self.generation,
            pending,
            self.expected_peer,
            DiameterConnectionRole::Acceptor,
            self.policy,
        )
    }
}

fn pending_inband_tls(session: &PeerSession) -> Result<PeerProtectionPending, DiameterTlsError> {
    let pending = session
        .pending_protection()
        .ok_or(DiameterTlsError::CapabilitiesExchangeFailed)?;
    if pending.mechanism() != PeerProtectionMechanism::TlsTcp
        || pending.sequence() != PeerProtectionSequence::InbandAfterCapabilities
    {
        return Err(DiameterTlsError::CapabilitiesExchangeFailed);
    }
    Ok(pending)
}

fn decode_context(policy: DiameterTlsPolicy) -> DecodeContext {
    DecodeContext {
        max_message_len: policy.frame_limits().max_message_len(),
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}

fn encode_context(policy: DiameterTlsPolicy) -> EncodeContext {
    EncodeContext {
        max_message_len: policy.frame_limits().max_message_len(),
        ..EncodeContext::default()
    }
}

fn fail_pending_for_transport(
    session: &mut PeerSession,
    pending: &PeerProtectionPending,
    error: DiameterTlsError,
) {
    let failure = match error {
        DiameterTlsError::Authentication | DiameterTlsError::PeerIdentityMismatch => {
            PeerProtectionFailure::PeerAuthenticationFailed
        }
        DiameterTlsError::ProtocolRejected | DiameterTlsError::CipherRejected => {
            PeerProtectionFailure::DowngradeRejected
        }
        _ => PeerProtectionFailure::HandshakeFailed,
    };
    let _ = session.fail_pending_protection(pending, failure);
}

impl fmt::Debug for DiameterInbandTlsInitiator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterInbandTlsInitiator")
            .field("generation", &self.generation)
            .field("policy", &self.policy)
            .field("peer", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DiameterInbandTlsInitiatorAwaitingAnswer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterInbandTlsInitiatorAwaitingAnswer")
            .field("generation", &self.generation)
            .field("policy", &self.policy)
            .field("peer", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DiameterInbandTlsResponder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterInbandTlsResponder")
            .field("generation", &self.generation)
            .field("policy", &self.policy)
            .field("peer", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DiameterInbandTlsResponderCerReceived {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterInbandTlsResponderCerReceived")
            .field("generation", &self.generation)
            .field("policy", &self.policy)
            .field("peer", &"<redacted>")
            .finish_non_exhaustive()
    }
}
