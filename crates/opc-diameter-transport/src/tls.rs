use std::fmt;
use std::io;
use std::net::Shutdown;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use opc_proto_diameter::peer::{
    build_capabilities_exchange_request, is_valid_diameter_identity,
    parse_capabilities_exchange_answer, parse_capabilities_exchange_error_answer,
    parse_capabilities_exchange_request, CapabilitiesExchangeAnswer,
    CapabilitiesExchangeErrorAnswer, PeerCapabilities, PeerCommandAdmission, PeerCommandClass,
    PeerIdentity, PeerMessageDirection, PeerProtectionEvidence, PeerProtectionFailure,
    PeerProtectionMechanism, PeerProtectionPending, PeerProtectionReadiness,
    PeerProtectionRequirement, PeerProtectionSequence, PeerSession, PeerSessionBlocker,
    PeerSessionGeneration, PeerSessionReadiness, PeerSessionSnapshot,
};
use opc_proto_diameter::OwnedMessage;
use opc_protocol::{DecodeContext, ValidationLevel};
use opc_tls::{
    AuthenticatedClientConfig, AuthenticatedServerConfig, PeerTlsIdentity, TlsAdmittedConnection,
    TlsHandshakeRunError, TlsMaterialAvailability, TlsMaterialEpoch, TlsMaterialReloadReason,
    TlsMaterialStatusReceiver,
};
use opc_types::{SpiffeId, Timestamp};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::rustls::{self, CipherSuite, ProtocolVersion};

use crate::frame::{borrowed, read_frame, write_frame};
use crate::frame_transport::{ProtectedFrameTransportClose, ProtectedFrameTransportParts};
use crate::DiameterFrameLimits;

static NEXT_SESSION_GENERATION: AtomicU64 = AtomicU64::new(1);

pub(crate) trait DiameterIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> DiameterIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// TLS endpoint role retained as bounded connection evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DiameterConnectionRole {
    /// Outbound TCP and TLS client.
    Connector,
    /// Inbound TCP and TLS server.
    Acceptor,
}

/// TLS protocol versions accepted by this transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DiameterTlsVersion {
    /// TLS 1.3. TLS 1.2 compatibility is deliberately not admitted.
    Tls13,
}

/// TLS 1.3 cipher-suite evidence understood by this transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DiameterTlsCipher {
    /// TLS_AES_128_GCM_SHA256.
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384.
    Aes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256.
    Chacha20Poly1305Sha256,
}

impl DiameterTlsCipher {
    const ALL: [Self; 3] = [
        Self::Aes128GcmSha256,
        Self::Aes256GcmSha384,
        Self::Chacha20Poly1305Sha256,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 0,
            Self::Aes256GcmSha384 => 1,
            Self::Chacha20Poly1305Sha256 => 2,
        }
    }

    fn from_rustls(suite: CipherSuite) -> Option<Self> {
        match suite {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Some(Self::Aes128GcmSha256),
            CipherSuite::TLS13_AES_256_GCM_SHA384 => Some(Self::Aes256GcmSha384),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => Some(Self::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    const fn rustls_suite(self) -> CipherSuite {
        match self {
            Self::Aes128GcmSha256 => CipherSuite::TLS13_AES_128_GCM_SHA256,
            Self::Aes256GcmSha384 => CipherSuite::TLS13_AES_256_GCM_SHA384,
            Self::Chacha20Poly1305Sha256 => CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        }
    }
}

/// Typed TLS and Diameter frame policy applied to every connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiameterTlsPolicy {
    version: DiameterTlsVersion,
    allowed_ciphers: [bool; 3],
    frame_limits: DiameterFrameLimits,
    maximum_connection_age: Duration,
}

impl DiameterTlsPolicy {
    /// TLS 1.3 policy with all Rustls ring-provider TLS 1.3 AEAD suites.
    pub const fn tls13(frame_limits: DiameterFrameLimits) -> Self {
        Self {
            version: DiameterTlsVersion::Tls13,
            allowed_ciphers: [true; 3],
            frame_limits,
            maximum_connection_age: Duration::from_secs(60 * 60),
        }
    }

    /// Restrict the cipher suites advertised during the TLS handshake. At
    /// least one suite already supported by `opc-tls`'s provider is required;
    /// the negotiated suite is checked again before admission.
    pub fn with_allowed_ciphers(
        mut self,
        allowed: &[DiameterTlsCipher],
    ) -> Result<Self, DiameterTlsPolicyError> {
        if allowed.is_empty() {
            return Err(DiameterTlsPolicyError::EmptyCipherSet);
        }
        self.allowed_ciphers = [false; 3];
        for cipher in allowed {
            self.allowed_ciphers[cipher.index()] = true;
        }
        Ok(self)
    }

    /// Set the hard authentication-age bound for an otherwise healthy idle
    /// connection. Material epoch changes retire immediately; local or peer
    /// certificate-chain expiry may impose an earlier bound.
    pub fn with_maximum_connection_age(
        mut self,
        maximum_connection_age: Duration,
    ) -> Result<Self, DiameterTlsPolicyError> {
        if maximum_connection_age.is_zero()
            || Instant::now().checked_add(maximum_connection_age).is_none()
        {
            return Err(DiameterTlsPolicyError::InvalidConnectionAge);
        }
        self.maximum_connection_age = maximum_connection_age;
        Ok(self)
    }

    /// Required TLS protocol version.
    pub const fn version(self) -> DiameterTlsVersion {
        self.version
    }

    /// Diameter frame bounds used by the connection.
    pub const fn frame_limits(self) -> DiameterFrameLimits {
        self.frame_limits
    }

    /// Hard maximum age of one authenticated connection.
    pub const fn maximum_connection_age(self) -> Duration {
        self.maximum_connection_age
    }

    /// Return whether a cipher is admitted.
    pub const fn allows_cipher(self, cipher: DiameterTlsCipher) -> bool {
        self.allowed_ciphers[cipher.index()]
    }

    /// Enumerate the finite supported TLS 1.3 cipher evidence values.
    pub fn allowed_ciphers(self) -> impl Iterator<Item = DiameterTlsCipher> {
        DiameterTlsCipher::ALL
            .into_iter()
            .filter(move |cipher| self.allows_cipher(*cipher))
    }
}

impl Default for DiameterTlsPolicy {
    fn default() -> Self {
        Self::tls13(DiameterFrameLimits::default())
    }
}

/// Invalid local TLS policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DiameterTlsPolicyError {
    /// A cipher allowlist cannot deny every negotiated suite.
    #[error("Diameter TLS cipher allowlist is empty")]
    EmptyCipherSet,
    /// The connection-age bound must be finite, nonzero, and representable.
    #[error("Diameter TLS maximum connection age is invalid")]
    InvalidConnectionAge,
}

/// Certificate and Diameter protocol identity expected on one connection.
#[derive(Clone, PartialEq, Eq)]
pub struct ExpectedPeerIdentity {
    spiffe_id: SpiffeId,
    diameter_identity: PeerIdentity,
}

impl ExpectedPeerIdentity {
    /// Require this canonical SPIFFE ID after certificate validation and this
    /// semantic DiameterIdentity pair during CER/CEA. Diameter identity values
    /// must be nonempty ASCII; authorization comparison remains ASCII
    /// case-insensitive rather than imposing a narrower FQDN grammar.
    pub fn new(
        spiffe_id: SpiffeId,
        diameter_identity: PeerIdentity,
    ) -> Result<Self, ExpectedPeerIdentityError> {
        if !is_valid_diameter_identity(&diameter_identity.origin_host) {
            return Err(if diameter_identity.origin_host.is_empty() {
                ExpectedPeerIdentityError::EmptyOriginHost
            } else {
                ExpectedPeerIdentityError::NonAsciiOriginHost
            });
        }
        if !is_valid_diameter_identity(&diameter_identity.origin_realm) {
            return Err(if diameter_identity.origin_realm.is_empty() {
                ExpectedPeerIdentityError::EmptyOriginRealm
            } else {
                ExpectedPeerIdentityError::NonAsciiOriginRealm
            });
        }
        Ok(Self {
            spiffe_id,
            diameter_identity,
        })
    }

    /// Borrow the exact expected SPIFFE ID.
    pub const fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }

    /// Borrow the expected Diameter Origin-Host/Origin-Realm pair.
    pub const fn diameter_identity(&self) -> &PeerIdentity {
        &self.diameter_identity
    }
}

/// Invalid configured Diameter authorization identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExpectedPeerIdentityError {
    /// Origin-Host is empty.
    #[error("expected Diameter Origin-Host is empty")]
    EmptyOriginHost,
    /// Origin-Host contains a non-ASCII code point.
    #[error("expected Diameter Origin-Host is not ASCII")]
    NonAsciiOriginHost,
    /// Origin-Realm is empty.
    #[error("expected Diameter Origin-Realm is empty")]
    EmptyOriginRealm,
    /// Origin-Realm contains a non-ASCII code point.
    #[error("expected Diameter Origin-Realm is not ASCII")]
    NonAsciiOriginRealm,
}

impl fmt::Debug for ExpectedPeerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedPeerIdentity([redacted])")
    }
}

/// Redaction-safe negotiated evidence for an admitted Diameter TLS connection.
#[derive(Clone, PartialEq, Eq)]
pub struct DiameterTlsEvidence {
    role: DiameterConnectionRole,
    version: DiameterTlsVersion,
    cipher: DiameterTlsCipher,
    material: TlsAdmittedConnection,
    peer_identity: PeerTlsIdentity,
    protection: PeerProtectionEvidence,
}

impl DiameterTlsEvidence {
    /// Local endpoint role in the TLS handshake.
    pub const fn role(&self) -> DiameterConnectionRole {
        self.role
    }

    /// Negotiated and policy-admitted TLS version.
    pub const fn version(&self) -> DiameterTlsVersion {
        self.version
    }

    /// Negotiated and policy-admitted TLS cipher suite.
    pub const fn cipher(&self) -> DiameterTlsCipher {
        self.cipher
    }

    /// Exact coherent local credential epoch used by the handshake.
    pub const fn material_epoch(&self) -> TlsMaterialEpoch {
        self.material.epoch()
    }

    /// Authenticated exact peer identity and certificate-expiry evidence.
    pub const fn peer_identity(&self) -> &PeerTlsIdentity {
        &self.peer_identity
    }

    /// Exact Diameter generation-bound protection evidence.
    pub const fn protection(&self) -> PeerProtectionEvidence {
        self.protection
    }
}

impl fmt::Debug for DiameterTlsEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterTlsEvidence")
            .field("role", &self.role)
            .field("version", &self.version)
            .field("cipher", &self.cipher)
            .field("material_epoch", &self.material.epoch())
            .field("peer_identity", &"<redacted>")
            .field("protection", &self.protection)
            .finish()
    }
}

/// Closed, bounded transport errors safe to classify or log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DiameterTlsError {
    /// The peer session is not configured for the requested TLS/TCP sequence.
    #[error("Diameter peer protection policy does not match the transport sequence")]
    ProtectionPolicyMismatch,
    /// The process-wide connection generation counter was exhausted.
    #[error("Diameter connection generation is exhausted")]
    GenerationExhausted,
    /// The peer session rejected generation binding or transport attestation.
    #[error("Diameter peer generation binding failed")]
    PeerBinding,
    /// The caller's absolute operation deadline elapsed.
    #[error("Diameter transport deadline exceeded")]
    DeadlineExceeded,
    /// TCP or stream I/O failed.
    #[error("Diameter transport I/O failed")]
    Transport,
    /// TLS negotiation failed without an authenticated channel.
    #[error("Diameter TLS handshake failed")]
    TlsHandshake,
    /// Certificate or mutual-authentication verification failed.
    #[error("Diameter TLS peer authentication failed")]
    Authentication,
    /// The authenticated certificate or semantic Diameter identity did not
    /// match policy.
    #[error("Diameter TLS peer identity did not match")]
    PeerIdentityMismatch,
    /// Negotiation selected a protocol version outside policy.
    #[error("Diameter TLS protocol downgrade rejected")]
    ProtocolRejected,
    /// Negotiation selected a cipher suite outside policy.
    #[error("Diameter TLS cipher rejected")]
    CipherRejected,
    /// Coherent TLS material was unavailable or changed during admission.
    #[error("Diameter TLS material was not admitted")]
    MaterialNotAdmitted,
    /// The Diameter frame was malformed or exceeded configured limits.
    #[error("invalid Diameter stream frame")]
    InvalidFrame,
    /// CER/CEA was malformed, contradictory, rejected, or did not negotiate
    /// the required in-band TLS/TCP mechanism.
    #[error("Diameter capabilities exchange failed")]
    CapabilitiesExchangeFailed,
    /// The exact peer session did not admit this command on this generation.
    #[error("Diameter command was not admitted")]
    CommandNotAdmitted,
    /// A connector-only or acceptor-only capability operation was requested
    /// on the opposite endpoint role.
    #[error("Diameter capability operation does not match the connection role")]
    ConnectionRoleMismatch,
    /// A cleartext or foreign-PPID SCTP user message reached an association
    /// that admits only protected DTLS records.
    #[error("Diameter transport received cleartext input")]
    CleartextInput,
    /// The admitted credential epoch was superseded or became unavailable.
    #[error("Diameter TLS connection retired")]
    Retired,
}

/// Terminal disposition of one direct TLS/TCP capability exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiameterCapabilitiesExchangeOutcome {
    /// CER/CEA completed and application traffic is ready.
    Negotiated(PeerSessionReadiness),
    /// The canonical non-success CEA was emitted or received and the
    /// connection was then failed closed.
    Rejected(PeerSessionReadiness),
}

/// Strictly parsed answer received by a direct-mode connector.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiameterCapabilitiesExchangeAnswer {
    /// A full CEA carrying peer capabilities.
    Answer(CapabilitiesExchangeAnswer),
    /// A minimal RFC 6733 section 7.2 protocol-error CEA.
    ProtocolError(CapabilitiesExchangeErrorAnswer),
}

impl DiameterCapabilitiesExchangeOutcome {
    /// Return the owned readiness projection produced by the exchange.
    pub const fn readiness(&self) -> &PeerSessionReadiness {
        match self {
            Self::Negotiated(readiness) | Self::Rejected(readiness) => readiness,
        }
    }

    /// Return whether the capability exchange admitted application traffic.
    pub const fn is_negotiated(&self) -> bool {
        matches!(self, Self::Negotiated(_))
    }
}

/// Outbound mutually authenticated Diameter TLS/TCP connector.
#[derive(Clone)]
pub struct DiameterTlsConnector {
    tls_config: AuthenticatedClientConfig,
    expected_peer: ExpectedPeerIdentity,
    policy: DiameterTlsPolicy,
}

impl DiameterTlsConnector {
    /// Create a connector that requires an exact authenticated peer identity.
    pub const fn new(
        tls_config: AuthenticatedClientConfig,
        expected_peer: ExpectedPeerIdentity,
        policy: DiameterTlsPolicy,
    ) -> Self {
        Self {
            tls_config,
            expected_peer,
            policy,
        }
    }

    /// Open a clear TCP connection whose typestate permits only a canonical
    /// CER before consuming the same unbuffered stream into TLS. `server_name`
    /// is ClientHello routing/SNI input only; the SPIFFE verifier and exact
    /// [`ExpectedPeerIdentity`] provide authorization evidence.
    pub async fn connect_inband(
        &self,
        address: std::net::SocketAddr,
        server_name: ServerName<'static>,
        local_capabilities: opc_proto_diameter::peer::PeerCapabilities,
        session_policy: opc_proto_diameter::peer::PeerSessionPolicy,
        deadline: Instant,
    ) -> Result<crate::DiameterInbandTlsInitiator, DiameterTlsError> {
        crate::inband::connect_inband(crate::inband::InbandClientParameters {
            tls_config: self.tls_config.clone(),
            expected_peer: self.expected_peer.clone(),
            policy: self.policy,
            address,
            server_name,
            local_capabilities,
            session_policy,
            deadline,
        })
        .await
    }

    /// Connect TCP and complete mutually authenticated TLS before any Diameter
    /// byte can be emitted. The absolute deadline includes TCP, TLS, and
    /// `opc-tls` material-epoch admission/retry work. `server_name` is
    /// ClientHello routing/SNI input only; authorization comes from the SPIFFE
    /// verifier and exact [`ExpectedPeerIdentity`].
    pub async fn connect_direct(
        &self,
        address: std::net::SocketAddr,
        server_name: ServerName<'static>,
        mut session: PeerSession,
        deadline: Instant,
    ) -> Result<DiameterTlsConnection, DiameterTlsError> {
        let (generation, pending) =
            bind_session(&mut session, PeerProtectionRequirement::direct_tls_tcp())?;
        let expected_peer = self.expected_peer.clone();
        let policy = self.policy;
        let allowed_ciphers = rustls_cipher_suites(policy);
        let operation =
            self.tls_config
                .run_handshake_with_cipher_suites(&allowed_ciphers, |attempt| {
                    let expected_peer = expected_peer.clone();
                    let server_name = server_name.clone();
                    async move {
                        let tcp = TcpStream::connect(address)
                            .await
                            .map_err(classify_tls_io_error)?;
                        let (tcp, shutdown) = tcp_with_shutdown_handle(tcp)?;
                        let connector = tokio_rustls::TlsConnector::from(diameter_client_config(
                            attempt.rustls_config(),
                        ));
                        let stream = connector
                            .connect(server_name, tcp)
                            .await
                            .map_err(classify_tls_io_error)?;
                        let connection = stream.get_ref().1;
                        let (version, cipher) = negotiated_tls(
                            connection.protocol_version(),
                            connection
                                .negotiated_cipher_suite()
                                .map(|suite| suite.suite()),
                            connection.alpn_protocol(),
                            policy,
                        )?;
                        let peer = opc_tls::peer_tls_identity_from_client_connection(connection)
                            .map_err(|_| HandshakeOperationError::Authentication)?;
                        if peer.spiffe_id() != expected_peer.spiffe_id() {
                            return Err(HandshakeOperationError::PeerIdentityMismatch);
                        }
                        Ok(HandshakeValue {
                            io: Box::new(stream),
                            shutdown,
                            peer,
                            version,
                            cipher,
                            established_at: Instant::now(),
                        })
                    }
                });
        let outcome = match tokio::time::timeout_at(deadline, operation).await {
            Err(_) => {
                fail_pending(
                    &mut session,
                    &pending,
                    PeerProtectionFailure::HandshakeFailed,
                );
                return Err(DiameterTlsError::DeadlineExceeded);
            }
            Ok(Err(error)) => {
                let (public, failure) = map_run_error(error);
                fail_pending(&mut session, &pending, failure);
                return Err(public);
            }
            Ok(Ok(outcome)) => outcome,
        };
        let (value, material) = outcome.into_parts();
        finish_connection(
            value,
            material,
            self.tls_config.subscribe_material_changes(),
            session,
            generation,
            pending,
            self.expected_peer.clone(),
            DiameterConnectionRole::Connector,
            self.policy,
        )
    }
}

impl fmt::Debug for DiameterTlsConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterTlsConnector")
            .field("tls_config", &"<redacted>")
            .field("expected_peer", &self.expected_peer)
            .field("policy", &self.policy)
            .finish()
    }
}

/// Inbound mutually authenticated Diameter TLS/TCP acceptor.
#[derive(Clone)]
pub struct DiameterTlsAcceptor {
    tls_config: AuthenticatedServerConfig,
    expected_peer: ExpectedPeerIdentity,
    policy: DiameterTlsPolicy,
}

impl DiameterTlsAcceptor {
    /// Create an acceptor that requires an exact configured inbound identity.
    pub const fn new(
        tls_config: AuthenticatedServerConfig,
        expected_peer: ExpectedPeerIdentity,
        policy: DiameterTlsPolicy,
    ) -> Self {
        Self {
            tls_config,
            expected_peer,
            policy,
        }
    }

    /// Bind an accepted clear TCP connection to an in-band TLS/TCP typestate.
    /// Only one exact CER may be read before the canonical CEA and TLS upgrade.
    pub fn accept_inband(
        &self,
        tcp: TcpStream,
        local_capabilities: opc_proto_diameter::peer::PeerCapabilities,
        session_policy: opc_proto_diameter::peer::PeerSessionPolicy,
    ) -> Result<crate::DiameterInbandTlsResponder, DiameterTlsError> {
        crate::inband::accept_inband(
            self.tls_config.clone(),
            self.expected_peer.clone(),
            self.policy,
            tcp,
            local_capabilities,
            session_policy,
        )
    }

    /// Complete mutually authenticated TLS on an accepted TCP stream before
    /// reading any Diameter byte. A stale credential epoch closes this socket;
    /// a listener may accept a fresh connection with a fresh generation.
    pub async fn accept_direct(
        &self,
        tcp: TcpStream,
        mut session: PeerSession,
        deadline: Instant,
    ) -> Result<DiameterTlsConnection, DiameterTlsError> {
        let (generation, pending) =
            bind_session(&mut session, PeerProtectionRequirement::direct_tls_tcp())?;
        // One accepted TCP socket cannot be replayed after a material-epoch
        // race. `run_handshake` still owns the global handshake permit; if it
        // asks for an epoch retry, the consumed socket fails closed and the
        // listener must accept a fresh connection/generation.
        let mut accepted = Some(tcp);
        let expected_peer = self.expected_peer.clone();
        let policy = self.policy;
        let allowed_ciphers = rustls_cipher_suites(policy);
        let operation =
            self.tls_config
                .run_handshake_with_cipher_suites(&allowed_ciphers, |attempt| {
                    let tcp = accepted.take();
                    let expected_peer = expected_peer.clone();
                    async move {
                        let tcp = tcp.ok_or(HandshakeOperationError::AcceptedSocketSuperseded)?;
                        let (tcp, shutdown) = tcp_with_shutdown_handle(tcp)?;
                        let acceptor = tokio_rustls::TlsAcceptor::from(diameter_server_config(
                            attempt.rustls_config(),
                        ));
                        let stream = acceptor.accept(tcp).await.map_err(classify_tls_io_error)?;
                        let connection = stream.get_ref().1;
                        let (version, cipher) = negotiated_tls(
                            connection.protocol_version(),
                            connection
                                .negotiated_cipher_suite()
                                .map(|suite| suite.suite()),
                            connection.alpn_protocol(),
                            policy,
                        )?;
                        let peer = opc_tls::peer_tls_identity_from_server_connection(connection)
                            .map_err(|_| HandshakeOperationError::Authentication)?;
                        if peer.spiffe_id() != expected_peer.spiffe_id() {
                            return Err(HandshakeOperationError::PeerIdentityMismatch);
                        }
                        Ok(HandshakeValue {
                            io: Box::new(stream),
                            shutdown,
                            peer,
                            version,
                            cipher,
                            established_at: Instant::now(),
                        })
                    }
                });
        let outcome = match tokio::time::timeout_at(deadline, operation).await {
            Err(_) => {
                fail_pending(
                    &mut session,
                    &pending,
                    PeerProtectionFailure::HandshakeFailed,
                );
                return Err(DiameterTlsError::DeadlineExceeded);
            }
            Ok(Err(error)) => {
                let (public, failure) = map_run_error(error);
                fail_pending(&mut session, &pending, failure);
                return Err(public);
            }
            Ok(Ok(outcome)) => outcome,
        };
        let (value, material) = outcome.into_parts();
        finish_connection(
            value,
            material,
            self.tls_config.subscribe_material_changes(),
            session,
            generation,
            pending,
            self.expected_peer.clone(),
            DiameterConnectionRole::Acceptor,
            self.policy,
        )
    }
}

impl fmt::Debug for DiameterTlsAcceptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterTlsAcceptor")
            .field("tls_config", &"<redacted>")
            .field("expected_peer", &self.expected_peer)
            .field("policy", &self.policy)
            .finish()
    }
}

/// An admitted mutually authenticated TLS/TCP stream bound to one peer session.
///
/// Capability setup and narrow integrations may use the sequential `&mut self`
/// operations. Long-lived users consume a negotiated connection with
/// [`DiameterTlsConnection::into_peer_runtime`], which privately owns the split
/// without exposing raw I/O or mutable peer-session state.
pub struct DiameterTlsConnection {
    io: Box<dyn DiameterIo>,
    shutdown: Arc<std::net::TcpStream>,
    session: PeerSession,
    generation: PeerSessionGeneration,
    evidence: DiameterTlsEvidence,
    expected_peer: ExpectedPeerIdentity,
    frame_limits: DiameterFrameLimits,
    material_status: TlsMaterialStatusReceiver,
    hard_deadline: Instant,
    retired: Arc<AtomicBool>,
    _retirement_task: RetirementTask,
    closed: bool,
}

impl DiameterTlsConnection {
    /// Negotiated, authenticated, generation-bound connection evidence.
    pub const fn evidence(&self) -> &DiameterTlsEvidence {
        &self.evidence
    }

    /// Exact transport-owned peer session generation.
    pub const fn generation(&self) -> PeerSessionGeneration {
        self.generation
    }

    /// Return an owned redaction-safe session snapshot after synchronously
    /// reconciling material replacement, certificate expiry, and age limits.
    pub fn peer_session_snapshot(&mut self) -> Result<PeerSessionSnapshot, DiameterTlsError> {
        self.ensure_active()?;
        let snapshot = self.session.snapshot();
        self.ensure_active()?;
        Ok(snapshot)
    }

    /// Return current protection readiness after synchronous retirement
    /// reconciliation.
    pub fn protection_readiness(&mut self) -> Result<PeerProtectionReadiness, DiameterTlsError> {
        self.ensure_active()?;
        let readiness = self.session.protection_readiness();
        self.ensure_active()?;
        Ok(readiness)
    }

    /// Return current peer readiness after synchronous retirement
    /// reconciliation.
    pub fn readiness(&mut self) -> Result<PeerSessionReadiness, DiameterTlsError> {
        self.ensure_active()?;
        let readiness = self.session.readiness();
        self.ensure_active()?;
        Ok(readiness)
    }

    /// Canonically build, bind, and emit the connector's direct-mode CER.
    pub async fn send_capabilities_request(
        &mut self,
        hop_by_hop_identifier: u32,
        end_to_end_identifier: u32,
        deadline: Instant,
    ) -> Result<PeerCommandAdmission, DiameterTlsError> {
        self.ensure_role(DiameterConnectionRole::Connector)?;
        self.ensure_active()?;
        let message = build_capabilities_exchange_request(
            self.session.local_capabilities(),
            hop_by_hop_identifier,
            end_to_end_identifier,
            self.frame_limits.encode_context(),
        )
        .map_err(|_| DiameterTlsError::CapabilitiesExchangeFailed)?;
        let admission = self
            .session
            .admit_message(
                self.generation,
                PeerMessageDirection::Outbound,
                &message.header,
            )
            .map_err(|_| DiameterTlsError::CommandNotAdmitted)?;
        self.session
            .capabilities_request_sent_on(self.generation, &message.header)
            .map_err(|_| DiameterTlsError::CapabilitiesExchangeFailed)?;
        self.ensure_active()?;
        self.write_protected_message(&message, deadline).await?;
        Ok(admission)
    }

    /// Receive, strictly parse, authenticate, and commit the acceptor's
    /// direct-mode CER.
    pub async fn receive_capabilities_request(
        &mut self,
        deadline: Instant,
    ) -> Result<PeerCapabilities, DiameterTlsError> {
        self.ensure_role(DiameterConnectionRole::Acceptor)?;
        self.ensure_active()?;
        let generation = self.generation;
        let frame_limits = self.frame_limits;
        let expected_identity = self.expected_peer.diameter_identity().clone();
        let material_status = self.material_status.clone();
        let admitted_epoch = self.evidence.material_epoch();
        let hard_deadline = self.hard_deadline;
        let retired = Arc::clone(&self.retired);
        let (message, mut operation) = self.read_protected_message(deadline).await?;
        operation
            .session
            .admit_message(generation, PeerMessageDirection::Inbound, &message.header)
            .map_err(|_| DiameterTlsError::CommandNotAdmitted)?;
        let remote = parse_capabilities_exchange_request(
            &borrowed(&message),
            capabilities_decode_context(frame_limits),
        )
        .map_err(|_| DiameterTlsError::CapabilitiesExchangeFailed)?;
        if !remote.identity.semantically_eq(&expected_identity) {
            return Err(DiameterTlsError::PeerIdentityMismatch);
        }
        operation
            .session
            .capabilities_request_received_on(generation, &message.header, remote.clone())
            .map_err(|_| DiameterTlsError::CapabilitiesExchangeFailed)?;
        if retirement_required(&material_status, admitted_epoch, hard_deadline, &retired) {
            retired.store(true, Ordering::Release);
            return Err(DiameterTlsError::Retired);
        }
        operation.disarm();
        Ok(remote)
    }

    /// Prepare and emit the acceptor's sole canonical direct-mode CEA.
    /// A non-success answer is flushed before this connection is failed closed
    /// and reported as [`DiameterCapabilitiesExchangeOutcome::Rejected`].
    pub async fn send_capabilities_answer(
        &mut self,
        answer: &CapabilitiesExchangeAnswer,
        deadline: Instant,
    ) -> Result<DiameterCapabilitiesExchangeOutcome, DiameterTlsError> {
        self.ensure_role(DiameterConnectionRole::Acceptor)?;
        self.ensure_active()?;
        if answer.capabilities != *self.session.local_capabilities() {
            return Err(DiameterTlsError::CapabilitiesExchangeFailed);
        }
        let emission = self
            .session
            .prepare_capabilities_answer_on(
                self.generation,
                answer,
                self.frame_limits.encode_context(),
            )
            .map_err(|_| DiameterTlsError::CapabilitiesExchangeFailed)?;
        let outcome = capabilities_outcome(emission.readiness().clone());
        self.ensure_active()?;
        let mut operation = ConnectionOperationGuard::new(
            &mut self.session,
            self.generation,
            &mut self.closed,
            &self.shutdown,
        );
        if let Err(error) = crate::frame::write_wire_frame(
            &mut *self.io,
            emission.as_bytes(),
            self.frame_limits,
            deadline,
        )
        .await
        {
            return Err(
                if retirement_required(
                    &self.material_status,
                    self.evidence.material_epoch(),
                    self.hard_deadline,
                    &self.retired,
                ) {
                    self.retired.store(true, Ordering::Release);
                    DiameterTlsError::Retired
                } else {
                    error
                },
            );
        }
        if retirement_required(
            &self.material_status,
            self.evidence.material_epoch(),
            self.hard_deadline,
            &self.retired,
        ) {
            self.retired.store(true, Ordering::Release);
            return Err(DiameterTlsError::Retired);
        }
        if outcome.is_negotiated() {
            operation.disarm();
        }
        Ok(outcome)
    }

    /// Receive the connector's strict, correlated direct-mode CEA. A
    /// non-success answer is returned as an explicit rejected outcome after
    /// this connection has been failed closed.
    pub async fn receive_capabilities_answer(
        &mut self,
        deadline: Instant,
    ) -> Result<
        (
            DiameterCapabilitiesExchangeAnswer,
            DiameterCapabilitiesExchangeOutcome,
        ),
        DiameterTlsError,
    > {
        self.ensure_role(DiameterConnectionRole::Connector)?;
        self.ensure_active()?;
        let generation = self.generation;
        let frame_limits = self.frame_limits;
        let expected_identity = self.expected_peer.diameter_identity().clone();
        let material_status = self.material_status.clone();
        let admitted_epoch = self.evidence.material_epoch();
        let hard_deadline = self.hard_deadline;
        let retired = Arc::clone(&self.retired);
        let (message, mut operation) = self.read_protected_message(deadline).await?;
        operation
            .session
            .admit_message(generation, PeerMessageDirection::Inbound, &message.header)
            .map_err(|_| DiameterTlsError::CommandNotAdmitted)?;
        let borrowed = borrowed(&message);
        let (answer, transition) = match parse_capabilities_exchange_answer(
            &borrowed,
            capabilities_decode_context(frame_limits),
        ) {
            Ok(answer) => {
                if !answer
                    .capabilities
                    .identity
                    .semantically_eq(&expected_identity)
                {
                    return Err(DiameterTlsError::PeerIdentityMismatch);
                }
                let transition = operation
                    .session
                    .observe_capabilities_answer_on(generation, &message.header, &answer)
                    .map_err(|_| DiameterTlsError::CapabilitiesExchangeFailed)?;
                (
                    DiameterCapabilitiesExchangeAnswer::Answer(answer),
                    transition,
                )
            }
            Err(_) => {
                let answer = parse_capabilities_exchange_error_answer(
                    &borrowed,
                    capabilities_decode_context(frame_limits),
                )
                .map_err(|_| DiameterTlsError::CapabilitiesExchangeFailed)?;
                if !answer.identity.semantically_eq(&expected_identity) {
                    return Err(DiameterTlsError::PeerIdentityMismatch);
                }
                let transition = operation
                    .session
                    .observe_capabilities_protocol_error_answer_on(
                        generation,
                        &message.header,
                        &answer,
                    )
                    .map_err(|_| DiameterTlsError::CapabilitiesExchangeFailed)?;
                (
                    DiameterCapabilitiesExchangeAnswer::ProtocolError(answer),
                    transition,
                )
            }
        };
        let outcome = capabilities_outcome(transition.readiness);
        if retirement_required(&material_status, admitted_epoch, hard_deadline, &retired) {
            retired.store(true, Ordering::Release);
            return Err(DiameterTlsError::Retired);
        }
        if outcome.is_negotiated() {
            operation.disarm();
        }
        Ok((answer, outcome))
    }

    /// Admit and emit exactly one post-negotiation application message under
    /// an absolute deadline. CER/CEA, watchdog, and disconnect procedures are
    /// owned by typed transport methods or intentionally outside this slice.
    pub async fn send_message(
        &mut self,
        message: &OwnedMessage,
        deadline: Instant,
    ) -> Result<PeerCommandAdmission, DiameterTlsError> {
        self.ensure_active()?;
        if PeerCommandClass::from_header(&message.header) != PeerCommandClass::Application {
            return Err(DiameterTlsError::CommandNotAdmitted);
        }
        let admission = self
            .session
            .admit_message(
                self.generation,
                PeerMessageDirection::Outbound,
                &message.header,
            )
            .map_err(|_| DiameterTlsError::CommandNotAdmitted)?;
        self.ensure_active()?;
        self.write_protected_message(message, deadline).await?;
        Ok(admission)
    }

    /// Read exactly one bounded post-negotiation application message and
    /// release it only after exact-generation admission.
    pub async fn receive_message(
        &mut self,
        deadline: Instant,
    ) -> Result<(OwnedMessage, PeerCommandAdmission), DiameterTlsError> {
        self.ensure_active()?;
        let generation = self.generation;
        let material_status = self.material_status.clone();
        let admitted_epoch = self.evidence.material_epoch();
        let hard_deadline = self.hard_deadline;
        let retired = Arc::clone(&self.retired);
        let (message, mut operation) = self.read_protected_message(deadline).await?;
        if PeerCommandClass::from_header(&message.header) != PeerCommandClass::Application {
            return Err(DiameterTlsError::CommandNotAdmitted);
        }
        let admission = match operation.session.admit_message(
            generation,
            PeerMessageDirection::Inbound,
            &message.header,
        ) {
            Ok(admission) => admission,
            Err(_) => return Err(DiameterTlsError::CommandNotAdmitted),
        };
        if retirement_required(&material_status, admitted_epoch, hard_deadline, &retired) {
            retired.store(true, Ordering::Release);
            return Err(DiameterTlsError::Retired);
        }
        operation.disarm();
        Ok((message, admission))
    }

    /// Close the protected stream and revoke this generation's readiness.
    pub fn close(mut self) -> Result<PeerSession, DiameterTlsError> {
        let already_closed = self.closed || self.retired.load(Ordering::Acquire);
        let shutdown = poison_connection(
            &mut self.session,
            self.generation,
            &mut self.closed,
            &self.shutdown,
        );
        if !already_closed {
            shutdown.map_err(|_| DiameterTlsError::Transport)?;
        }
        Ok(self.session)
    }

    fn ensure_active(&mut self) -> Result<(), DiameterTlsError> {
        if self.closed
            || retirement_required(
                &self.material_status,
                self.evidence.material_epoch(),
                self.hard_deadline,
                &self.retired,
            )
        {
            self.retired.store(true, Ordering::Release);
            let _ = poison_connection(
                &mut self.session,
                self.generation,
                &mut self.closed,
                &self.shutdown,
            );
            return Err(DiameterTlsError::Retired);
        }
        Ok(())
    }

    fn ensure_role(&self, expected: DiameterConnectionRole) -> Result<(), DiameterTlsError> {
        if self.evidence.role() == expected {
            Ok(())
        } else {
            Err(DiameterTlsError::ConnectionRoleMismatch)
        }
    }

    async fn write_protected_message(
        &mut self,
        message: &OwnedMessage,
        deadline: Instant,
    ) -> Result<(), DiameterTlsError> {
        self.ensure_active()?;
        let mut operation = ConnectionOperationGuard::new(
            &mut self.session,
            self.generation,
            &mut self.closed,
            &self.shutdown,
        );
        if let Err(error) = write_frame(&mut *self.io, message, self.frame_limits, deadline).await {
            return Err(
                if retirement_required(
                    &self.material_status,
                    self.evidence.material_epoch(),
                    self.hard_deadline,
                    &self.retired,
                ) {
                    self.retired.store(true, Ordering::Release);
                    DiameterTlsError::Retired
                } else {
                    error
                },
            );
        }
        if retirement_required(
            &self.material_status,
            self.evidence.material_epoch(),
            self.hard_deadline,
            &self.retired,
        ) {
            self.retired.store(true, Ordering::Release);
            return Err(DiameterTlsError::Retired);
        }
        operation.disarm();
        Ok(())
    }

    async fn read_protected_message(
        &mut self,
        deadline: Instant,
    ) -> Result<(OwnedMessage, ConnectionOperationGuard<'_>), DiameterTlsError> {
        self.ensure_active()?;
        let operation = ConnectionOperationGuard::new(
            &mut self.session,
            self.generation,
            &mut self.closed,
            &self.shutdown,
        );
        let message = match read_frame(&mut *self.io, self.frame_limits, deadline).await {
            Ok(message) => message,
            Err(error) => {
                return Err(
                    if retirement_required(
                        &self.material_status,
                        self.evidence.material_epoch(),
                        self.hard_deadline,
                        &self.retired,
                    ) {
                        self.retired.store(true, Ordering::Release);
                        DiameterTlsError::Retired
                    } else {
                        error
                    },
                );
            }
        };
        if retirement_required(
            &self.material_status,
            self.evidence.material_epoch(),
            self.hard_deadline,
            &self.retired,
        ) {
            self.retired.store(true, Ordering::Release);
            return Err(DiameterTlsError::Retired);
        }
        Ok((message, operation))
    }

    pub(crate) fn into_runtime_parts(self) -> DiameterTlsRuntimeParts {
        let Self {
            io,
            shutdown,
            session,
            generation,
            evidence,
            expected_peer,
            frame_limits,
            material_status,
            hard_deadline,
            retired,
            _retirement_task,
            closed: _,
        } = self;
        let transport_close: Arc<dyn ProtectedFrameTransportClose> = shutdown.clone();
        DiameterTlsRuntimeParts {
            frame_transport: ProtectedFrameTransportParts::from_stream(io, transport_close),
            session,
            generation,
            evidence,
            expected_peer,
            frame_limits,
            material_status,
            hard_deadline,
            retired,
            retirement_task: _retirement_task,
        }
    }
}

impl fmt::Debug for DiameterTlsConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterTlsConnection")
            .field("generation", &self.generation)
            .field("evidence", &self.evidence)
            .field("frame_limits", &self.frame_limits)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

pub(crate) struct HandshakeValue {
    io: Box<dyn DiameterIo>,
    shutdown: SocketShutdownGuard,
    peer: PeerTlsIdentity,
    version: DiameterTlsVersion,
    cipher: DiameterTlsCipher,
    established_at: Instant,
}

pub(crate) struct SocketShutdownGuard {
    socket: std::net::TcpStream,
    armed: bool,
}

impl SocketShutdownGuard {
    const fn new(socket: std::net::TcpStream) -> Self {
        Self {
            socket,
            armed: true,
        }
    }

    fn into_shared(mut self) -> io::Result<Arc<std::net::TcpStream>> {
        let shared = Arc::new(self.socket.try_clone()?);
        self.armed = false;
        Ok(shared)
    }
}

impl Drop for SocketShutdownGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.socket.shutdown(Shutdown::Both);
        }
    }
}

struct ConnectionOperationGuard<'a> {
    session: &'a mut PeerSession,
    generation: PeerSessionGeneration,
    closed: &'a mut bool,
    shutdown: &'a std::net::TcpStream,
    armed: bool,
}

impl<'a> ConnectionOperationGuard<'a> {
    const fn new(
        session: &'a mut PeerSession,
        generation: PeerSessionGeneration,
        closed: &'a mut bool,
        shutdown: &'a std::net::TcpStream,
    ) -> Self {
        Self {
            session,
            generation,
            closed,
            shutdown,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ConnectionOperationGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = poison_connection(self.session, self.generation, self.closed, self.shutdown);
        }
    }
}

fn poison_connection(
    session: &mut PeerSession,
    generation: PeerSessionGeneration,
    closed: &mut bool,
    shutdown: &std::net::TcpStream,
) -> io::Result<()> {
    *closed = true;
    let _ = session.fail_on(generation, PeerSessionBlocker::SessionFailed);
    shutdown.shutdown(Shutdown::Both)
}

pub(crate) struct RetirementTask {
    task: tokio::task::JoinHandle<()>,
    shutdown: Arc<std::net::TcpStream>,
}

pub(crate) struct DiameterTlsRuntimeParts {
    pub(crate) frame_transport: ProtectedFrameTransportParts,
    pub(crate) session: PeerSession,
    pub(crate) generation: PeerSessionGeneration,
    pub(crate) evidence: DiameterTlsEvidence,
    pub(crate) expected_peer: ExpectedPeerIdentity,
    pub(crate) frame_limits: DiameterFrameLimits,
    pub(crate) material_status: TlsMaterialStatusReceiver,
    pub(crate) hard_deadline: Instant,
    pub(crate) retired: Arc<AtomicBool>,
    pub(crate) retirement_task: RetirementTask,
}

impl Drop for RetirementTask {
    fn drop(&mut self) {
        // Abort scheduling is not a synchronous lifetime boundary. Close the
        // duplicated socket first so ordinary handle drop cannot leave a live
        // peer connection while the runtime is starved.
        let _ = self.shutdown.shutdown(Shutdown::Both);
        self.task.abort();
    }
}

#[derive(Clone, Copy)]
enum HandshakeOperationError {
    Transport,
    TlsHandshake,
    Authentication,
    PeerIdentityMismatch,
    ProtocolRejected,
    CipherRejected,
    AcceptedSocketSuperseded,
}

pub(crate) fn next_generation() -> Result<PeerSessionGeneration, DiameterTlsError> {
    let value = NEXT_SESSION_GENERATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| DiameterTlsError::GenerationExhausted)?;
    let value = NonZeroU64::new(value).ok_or(DiameterTlsError::GenerationExhausted)?;
    Ok(PeerSessionGeneration::new(value))
}

pub(crate) fn begin_generation(
    session: &mut PeerSession,
    required: PeerProtectionRequirement,
) -> Result<PeerSessionGeneration, DiameterTlsError> {
    if session.protection_policy().requirement() != Some(required) {
        return Err(DiameterTlsError::ProtectionPolicyMismatch);
    }
    let generation = next_generation()?;
    session
        .begin_connection_generation(generation)
        .map_err(|_| DiameterTlsError::PeerBinding)?;
    Ok(generation)
}

fn bind_session(
    session: &mut PeerSession,
    required: PeerProtectionRequirement,
) -> Result<(PeerSessionGeneration, PeerProtectionPending), DiameterTlsError> {
    let generation = begin_generation(session, required)?;
    let pending = session
        .pending_protection()
        .ok_or(DiameterTlsError::PeerBinding)?;
    if pending.mechanism() != PeerProtectionMechanism::TlsTcp
        || pending.sequence() != PeerProtectionSequence::DirectBeforeCapabilities
    {
        fail_pending(
            session,
            &pending,
            PeerProtectionFailure::UnsupportedMechanism,
        );
        return Err(DiameterTlsError::ProtectionPolicyMismatch);
    }
    Ok((generation, pending))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_connection(
    value: HandshakeValue,
    material: TlsAdmittedConnection,
    material_rx: TlsMaterialStatusReceiver,
    mut session: PeerSession,
    generation: PeerSessionGeneration,
    pending: PeerProtectionPending,
    expected_peer: ExpectedPeerIdentity,
    role: DiameterConnectionRole,
    policy: DiameterTlsPolicy,
) -> Result<DiameterTlsConnection, DiameterTlsError> {
    let transition = session
        .attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp)
        .map_err(|_| DiameterTlsError::PeerBinding)?;
    let protection = transition
        .protection()
        .protected_ready()
        .then(|| session.protection_evidence())
        .flatten()
        .ok_or(DiameterTlsError::PeerBinding)?;
    let status = material_rx.status();
    if !material_status_matches(material.epoch(), status) {
        return Err(DiameterTlsError::Retired);
    }
    let hard_deadline = connection_hard_deadline(
        value.established_at,
        policy.maximum_connection_age(),
        material.certificate_chain_expires_at(),
        value.peer.certificate_chain_expires_at(),
    );
    let shutdown = value
        .shutdown
        .into_shared()
        .map_err(|_| DiameterTlsError::Transport)?;
    let (retired, retirement_task) = spawn_retirement_task(
        material_rx.clone(),
        material.epoch(),
        hard_deadline,
        Arc::clone(&shutdown),
    );
    Ok(DiameterTlsConnection {
        io: value.io,
        shutdown,
        session,
        generation,
        evidence: DiameterTlsEvidence {
            role,
            version: value.version,
            cipher: value.cipher,
            material,
            peer_identity: value.peer,
            protection,
        },
        expected_peer,
        frame_limits: policy.frame_limits(),
        material_status: material_rx,
        hard_deadline,
        retired,
        _retirement_task: retirement_task,
        closed: false,
    })
}

fn fail_pending(
    session: &mut PeerSession,
    pending: &PeerProtectionPending,
    failure: PeerProtectionFailure,
) {
    let _ = session.fail_pending_protection(pending, failure);
}

fn capabilities_decode_context(frame_limits: DiameterFrameLimits) -> DecodeContext {
    DecodeContext {
        max_message_len: frame_limits.max_message_len(),
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}

fn capabilities_outcome(readiness: PeerSessionReadiness) -> DiameterCapabilitiesExchangeOutcome {
    if readiness.traffic_ready {
        DiameterCapabilitiesExchangeOutcome::Negotiated(readiness)
    } else {
        DiameterCapabilitiesExchangeOutcome::Rejected(readiness)
    }
}

fn tcp_with_shutdown_handle(
    tcp: TcpStream,
) -> Result<(TcpStream, SocketShutdownGuard), HandshakeOperationError> {
    let shutdown = match duplicate_shutdown_socket(&tcp) {
        Ok(shutdown) => shutdown,
        Err(_) => {
            full_close_tokio_socket(tcp);
            return Err(HandshakeOperationError::Transport);
        }
    };
    let shutdown = SocketShutdownGuard::new(shutdown);
    // The duplicate guard is armed before Tokio deregistration. If `into_std`
    // fails, Tokio's consuming API drops its inaccessible inner descriptor and
    // this guard still issues Shutdown::Both through the duplicate.
    let tcp = tcp
        .into_std()
        .map_err(|_| HandshakeOperationError::Transport)?;
    let tcp = TcpStream::from_std(tcp).map_err(|_| HandshakeOperationError::Transport)?;
    Ok((tcp, shutdown))
}

fn duplicate_shutdown_socket(tcp: &TcpStream) -> io::Result<std::net::TcpStream> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;

        tcp.as_fd().try_clone_to_owned().map(Into::into)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsSocket;

        tcp.as_socket().try_clone_to_owned().map(Into::into)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = tcp;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP shutdown-handle duplication is unsupported on this platform",
        ))
    }
}

fn full_close_tokio_socket(tcp: TcpStream) {
    // `into_std` consumes `tcp` and returns no recoverable socket on
    // deregistration failure; in that case Tokio drops the descriptor. When it
    // succeeds, explicitly full-close rather than relying on descriptor drop.
    if let Ok(tcp) = tcp.into_std() {
        let _ = tcp.shutdown(Shutdown::Both);
    }
}

pub(crate) fn bind_inband_socket(
    tcp: TcpStream,
) -> Result<(TcpStream, SocketShutdownGuard), DiameterTlsError> {
    tcp_with_shutdown_handle(tcp).map_err(|_| DiameterTlsError::Transport)
}

pub(crate) fn fail_inband_socket(
    session: &mut PeerSession,
    generation: PeerSessionGeneration,
    shutdown: SocketShutdownGuard,
) {
    let _ = session.fail_on(generation, PeerSessionBlocker::SessionFailed);
    drop(shutdown);
}

pub(crate) async fn upgrade_client_socket(
    tls_config: &AuthenticatedClientConfig,
    expected_peer: &ExpectedPeerIdentity,
    policy: DiameterTlsPolicy,
    tcp: TcpStream,
    shutdown: SocketShutdownGuard,
    server_name: ServerName<'static>,
    deadline: Instant,
) -> Result<(HandshakeValue, TlsAdmittedConnection), DiameterTlsError> {
    let mut socket = Some((tcp, shutdown));
    let expected_peer = expected_peer.clone();
    let allowed_ciphers = rustls_cipher_suites(policy);
    let operation = tls_config.run_handshake_with_cipher_suites(&allowed_ciphers, |attempt| {
        let tcp = socket.take();
        let expected_peer = expected_peer.clone();
        let server_name = server_name.clone();
        async move {
            let (tcp, shutdown) = tcp.ok_or(HandshakeOperationError::AcceptedSocketSuperseded)?;
            let connector =
                tokio_rustls::TlsConnector::from(diameter_client_config(attempt.rustls_config()));
            let stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(classify_tls_io_error)?;
            let connection = stream.get_ref().1;
            let (version, cipher) = negotiated_tls(
                connection.protocol_version(),
                connection
                    .negotiated_cipher_suite()
                    .map(|suite| suite.suite()),
                connection.alpn_protocol(),
                policy,
            )?;
            let peer = opc_tls::peer_tls_identity_from_client_connection(connection)
                .map_err(|_| HandshakeOperationError::Authentication)?;
            if peer.spiffe_id() != expected_peer.spiffe_id() {
                return Err(HandshakeOperationError::PeerIdentityMismatch);
            }
            Ok(HandshakeValue {
                io: Box::new(stream),
                shutdown,
                peer,
                version,
                cipher,
                established_at: Instant::now(),
            })
        }
    });
    match tokio::time::timeout_at(deadline, operation).await {
        Err(_) => Err(DiameterTlsError::DeadlineExceeded),
        Ok(Err(error)) => Err(map_run_error(error).0),
        Ok(Ok(outcome)) => Ok(outcome.into_parts()),
    }
}

pub(crate) async fn upgrade_server_socket(
    tls_config: &AuthenticatedServerConfig,
    expected_peer: &ExpectedPeerIdentity,
    policy: DiameterTlsPolicy,
    tcp: TcpStream,
    shutdown: SocketShutdownGuard,
    deadline: Instant,
) -> Result<(HandshakeValue, TlsAdmittedConnection), DiameterTlsError> {
    let mut socket = Some((tcp, shutdown));
    let expected_peer = expected_peer.clone();
    let allowed_ciphers = rustls_cipher_suites(policy);
    let operation = tls_config.run_handshake_with_cipher_suites(&allowed_ciphers, |attempt| {
        let tcp = socket.take();
        let expected_peer = expected_peer.clone();
        async move {
            let (tcp, shutdown) = tcp.ok_or(HandshakeOperationError::AcceptedSocketSuperseded)?;
            let acceptor =
                tokio_rustls::TlsAcceptor::from(diameter_server_config(attempt.rustls_config()));
            let stream = acceptor.accept(tcp).await.map_err(classify_tls_io_error)?;
            let connection = stream.get_ref().1;
            let (version, cipher) = negotiated_tls(
                connection.protocol_version(),
                connection
                    .negotiated_cipher_suite()
                    .map(|suite| suite.suite()),
                connection.alpn_protocol(),
                policy,
            )?;
            let peer = opc_tls::peer_tls_identity_from_server_connection(connection)
                .map_err(|_| HandshakeOperationError::Authentication)?;
            if peer.spiffe_id() != expected_peer.spiffe_id() {
                return Err(HandshakeOperationError::PeerIdentityMismatch);
            }
            Ok(HandshakeValue {
                io: Box::new(stream),
                shutdown,
                peer,
                version,
                cipher,
                established_at: Instant::now(),
            })
        }
    });
    match tokio::time::timeout_at(deadline, operation).await {
        Err(_) => Err(DiameterTlsError::DeadlineExceeded),
        Ok(Err(error)) => Err(map_run_error(error).0),
        Ok(Ok(outcome)) => Ok(outcome.into_parts()),
    }
}

fn material_status_matches(epoch: TlsMaterialEpoch, status: opc_tls::TlsMaterialStatus) -> bool {
    if status.epoch() != epoch {
        return false;
    }
    match status.availability() {
        TlsMaterialAvailability::Ready => true,
        TlsMaterialAvailability::RetainingLastGood => !matches!(
            status.reason(),
            Some(
                TlsMaterialReloadReason::AwaitingInitialMaterial
                    | TlsMaterialReloadReason::MaterialUnavailable
                    | TlsMaterialReloadReason::SourceClosed
                    | TlsMaterialReloadReason::LastGoodExpired
            )
        ),
        TlsMaterialAvailability::Initializing | TlsMaterialAvailability::Unavailable => false,
    }
}

pub(crate) fn retirement_required(
    material_status: &TlsMaterialStatusReceiver,
    admitted_epoch: TlsMaterialEpoch,
    hard_deadline: Instant,
    retired: &AtomicBool,
) -> bool {
    retired.load(Ordering::Acquire)
        || Instant::now() >= hard_deadline
        || !material_status_matches(admitted_epoch, material_status.status())
}

fn connection_hard_deadline(
    established_at: Instant,
    maximum_age: Duration,
    local_chain_expiry: Timestamp,
    peer_chain_expiry: Timestamp,
) -> Instant {
    let maximum_age_deadline = established_at
        .checked_add(maximum_age)
        .unwrap_or(established_at);
    maximum_age_deadline
        .min(wall_expiry_deadline(local_chain_expiry, established_at))
        .min(wall_expiry_deadline(peer_chain_expiry, established_at))
}

fn wall_expiry_deadline(expiry: Timestamp, now: Instant) -> Instant {
    let wall_now = Timestamp::now_utc();
    let remaining = expiry
        .as_offset_datetime()
        .unix_timestamp_nanos()
        .saturating_sub(wall_now.as_offset_datetime().unix_timestamp_nanos());
    if remaining <= 0 {
        return now;
    }
    let seconds = remaining / 1_000_000_000;
    let nanos = remaining % 1_000_000_000;
    let (Ok(seconds), Ok(nanos)) = (u64::try_from(seconds), u32::try_from(nanos)) else {
        return now;
    };
    now.checked_add(Duration::new(seconds, nanos))
        .unwrap_or(now)
}

fn spawn_retirement_task(
    mut material_rx: TlsMaterialStatusReceiver,
    admitted_epoch: TlsMaterialEpoch,
    hard_deadline: Instant,
    shutdown: Arc<std::net::TcpStream>,
) -> (Arc<AtomicBool>, RetirementTask) {
    let retired = Arc::new(AtomicBool::new(false));
    let task_retired = Arc::clone(&retired);
    let task_shutdown = Arc::clone(&shutdown);
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(hard_deadline) => break,
                status = material_rx.changed() => {
                    let Ok(status) = status else {
                        break;
                    };
                    if !material_status_matches(admitted_epoch, status) {
                        break;
                    }
                }
            }
        }
        task_retired.store(true, Ordering::Release);
        let _ = task_shutdown.shutdown(Shutdown::Both);
    });
    (retired, RetirementTask { task, shutdown })
}

fn rustls_cipher_suites(policy: DiameterTlsPolicy) -> Vec<CipherSuite> {
    policy
        .allowed_ciphers()
        .map(DiameterTlsCipher::rustls_suite)
        .collect()
}

fn negotiated_tls(
    protocol: Option<ProtocolVersion>,
    cipher: Option<CipherSuite>,
    alpn: Option<&[u8]>,
    policy: DiameterTlsPolicy,
) -> Result<(DiameterTlsVersion, DiameterTlsCipher), HandshakeOperationError> {
    if protocol != Some(ProtocolVersion::TLSv1_3) || alpn.is_some() {
        return Err(HandshakeOperationError::ProtocolRejected);
    }
    let cipher = cipher
        .and_then(DiameterTlsCipher::from_rustls)
        .ok_or(HandshakeOperationError::CipherRejected)?;
    if !policy.allows_cipher(cipher) {
        return Err(HandshakeOperationError::CipherRejected);
    }
    Ok((DiameterTlsVersion::Tls13, cipher))
}

fn diameter_client_config(config: Arc<rustls::ClientConfig>) -> Arc<rustls::ClientConfig> {
    let mut config = config.as_ref().clone();
    // Diameter has no registered ALPN identifier. Clear opc-tls's HTTP ALPN
    // defaults and require no negotiated ALPN on the completed connection.
    config.alpn_protocols.clear();
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Arc::new(config)
}

fn diameter_server_config(config: Arc<rustls::ServerConfig>) -> Arc<rustls::ServerConfig> {
    let mut config = config.as_ref().clone();
    config.alpn_protocols.clear();
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.ticketer = Arc::new(DisabledSessionTickets);
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    Arc::new(config)
}

#[derive(Debug)]
struct DisabledSessionTickets;

impl rustls::server::ProducesTickets for DisabledSessionTickets {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

fn classify_tls_io_error(error: io::Error) -> HandshakeOperationError {
    let Some(rustls_error) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<rustls::Error>())
    else {
        return HandshakeOperationError::Transport;
    };
    if tls_error_is_authentication(rustls_error) {
        HandshakeOperationError::Authentication
    } else {
        HandshakeOperationError::TlsHandshake
    }
}

fn tls_error_is_authentication(error: &rustls::Error) -> bool {
    use rustls::{AlertDescription, Error};

    match error {
        Error::InvalidCertificate(_)
        | Error::InvalidCertRevocationList(_)
        | Error::NoCertificatesPresented
        | Error::UnsupportedNameType => true,
        Error::AlertReceived(alert) => matches!(
            alert,
            AlertDescription::NoCertificate
                | AlertDescription::BadCertificate
                | AlertDescription::UnsupportedCertificate
                | AlertDescription::CertificateRevoked
                | AlertDescription::CertificateExpired
                | AlertDescription::CertificateUnknown
                | AlertDescription::UnknownCA
                | AlertDescription::AccessDenied
                | AlertDescription::CertificateUnobtainable
                | AlertDescription::BadCertificateStatusResponse
                | AlertDescription::BadCertificateHashValue
                | AlertDescription::CertificateRequired
        ),
        _ => false,
    }
}

fn map_run_error(
    error: TlsHandshakeRunError<HandshakeOperationError>,
) -> (DiameterTlsError, PeerProtectionFailure) {
    match error {
        TlsHandshakeRunError::Material(_) => (
            DiameterTlsError::MaterialNotAdmitted,
            PeerProtectionFailure::HandshakeFailed,
        ),
        TlsHandshakeRunError::Operation(error) => map_operation_error(error),
    }
}

fn map_operation_error(
    error: HandshakeOperationError,
) -> (DiameterTlsError, PeerProtectionFailure) {
    match error {
        HandshakeOperationError::Transport => (
            DiameterTlsError::Transport,
            PeerProtectionFailure::HandshakeFailed,
        ),
        HandshakeOperationError::TlsHandshake => (
            DiameterTlsError::TlsHandshake,
            PeerProtectionFailure::HandshakeFailed,
        ),
        HandshakeOperationError::Authentication => (
            DiameterTlsError::Authentication,
            PeerProtectionFailure::PeerAuthenticationFailed,
        ),
        HandshakeOperationError::PeerIdentityMismatch => (
            DiameterTlsError::PeerIdentityMismatch,
            PeerProtectionFailure::PeerAuthenticationFailed,
        ),
        HandshakeOperationError::ProtocolRejected => (
            DiameterTlsError::ProtocolRejected,
            PeerProtectionFailure::DowngradeRejected,
        ),
        HandshakeOperationError::CipherRejected => (
            DiameterTlsError::CipherRejected,
            PeerProtectionFailure::DowngradeRejected,
        ),
        HandshakeOperationError::AcceptedSocketSuperseded => (
            DiameterTlsError::MaterialNotAdmitted,
            PeerProtectionFailure::HandshakeFailed,
        ),
    }
}
