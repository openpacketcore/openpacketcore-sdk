//! Direct RFC 6083 transport without Diameter procedure state.
//!
//! Explicit policies carry application records on reliable ordered SCTP
//! stream zero or a bounded stream range. DTLS control always uses stream zero.
//! The protected PPIDs are 47 and 66; PPID 60 is never admitted. Full NGAP stream
//! assignment remains caller-owned. A selected PPID is only configuration:
//! [`Connection`] is issued after mutual DTLS authentication and SCTP-AUTH barriers.
//!
//! The implementation shares the existing Diameter transport's DTLS engine,
//! exact SPIFFE certificate verification, coherent credential epochs, sender
//! drains, retirement and close machinery. It requires no Diameter identity,
//! peer session, CER/CEA or NGAP procedure state. The certificate profile is
//! SPIFFE with exact identity, trust-domain anchors, chain time/signatures and
//! role EKU checks. [`Connector::new_with_required_crls`] and
//! [`Acceptor::new_with_required_crls`] additionally require an epoch-bound
//! complete direct CRL publication; the original constructors do not check
//! revocation. The complete 3GPP PKI and OCSP profiles remain unsupported.
//! Material or required-CRL withdrawal/replacement retires the association.
//! [`Policy::with_rekey`] enables coordinated, connection-bound in-place rekey
//! within the original credential, identity, cipher and absolute lifetime.
//!
//! ```no_run
//! use opc_diameter_transport::rfc6083::{
//!     Connection, Connector, Error, ExpectedPeer, PayloadProtocol, Policy, Transport,
//! };
//! use opc_sctp::SctpAssociation;
//! use opc_tls::TlsMaterialController;
//! use opc_types::SpiffeId;
//! use tokio::time::Instant;
//!
//! async fn protect(
//!     association: SctpAssociation,
//!     material: TlsMaterialController,
//!     expected_peer: SpiffeId,
//!     deadline: Instant,
//! ) -> Result<Connection, Error> {
//!     let policy = Policy::ordered_stream_zero(PayloadProtocol::Ngap, 4096)?;
//!     let connector = Connector::new(material, ExpectedPeer::spiffe(expected_peer), policy)?;
//!     let carrier = Transport::from_sctp(association, PayloadProtocol::Ngap, 64)?;
//!     connector.connect(carrier, deadline).await
//! }
//! ```

use super::*;
use opc_types::SpiffeId;

pub(in crate::dtls) mod revocation;
pub(in crate::dtls) mod streams;
pub use revocation::{
    CrlError, CrlEvidence, CrlGeneration, CrlPublisher, CrlSource, MAX_CRLS, MAX_CRL_BYTES,
    MAX_CRL_SET_BYTES,
};

pub use super::{DtlsSctpCipher as Cipher, DtlsSctpVersion as Version};

/// Registered application protocols carried inside DTLS/SCTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadProtocol {
    /// Diameter in DTLS/SCTP, PPID 47 (RFC 6733 section 11.5).
    Diameter,
    /// NGAP over DTLS/SCTP, PPID 66 (IANA SCTP PPID registry).
    Ngap,
}

impl PayloadProtocol {
    /// Registered SCTP payload protocol identifier, in host byte order.
    pub const fn ppid(self) -> u32 {
        match self {
            Self::Diameter => DIAMETER_DTLS_SCTP_PPID,
            Self::Ngap => 66,
        }
    }
}

/// Exact expected SPIFFE identity. Formatting never reveals the identity.
#[derive(Clone, PartialEq, Eq)]
pub struct ExpectedPeer(SpiffeId);

impl ExpectedPeer {
    /// Pin one exact certificate URI identity; wildcard matching is unsupported.
    pub const fn spiffe(identity: SpiffeId) -> Self {
        Self(identity)
    }

    /// Explicitly inspect the caller-selected identity.
    pub const fn spiffe_id(&self) -> &SpiffeId {
        &self.0
    }
}

impl fmt::Debug for ExpectedPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedPeer([redacted])")
    }
}

/// Caller-selected stream and resource limits for reliable ordered DTLS 1.2.
///
/// The plaintext limit is 1 through [`MAX_DTLS_SCTP_MESSAGE_BYTES`], inclusive;
/// an authenticated empty application record is nevertheless valid. The
/// default maximum age is one hour. These are SDK resource/policy choices,
/// distinct from RFC 6083's record and SCTP-AUTH requirements.
#[derive(Clone, Copy)]
pub struct Policy {
    protocol: PayloadProtocol,
    maximum_plaintext_bytes: usize,
    application_stream_count: u16,
    pending_record_capacity: usize,
    allow_rekey: bool,
    shared: DtlsSctpPolicy,
}

impl Policy {
    /// Select reliable ordered stream zero and a finite plaintext budget.
    ///
    /// This deliberately does not advertise the stream pairs required for
    /// complete NGAP operation. Nonzero sends and nonzero or unordered receive
    /// metadata fail the association under this policy.
    pub fn ordered_stream_zero(
        protocol: PayloadProtocol,
        maximum_plaintext_bytes: usize,
    ) -> Result<Self, Error> {
        if !(1..=MAX_DTLS_SCTP_MESSAGE_BYTES).contains(&maximum_plaintext_bytes) {
            return Err(Error::PolicyRejected);
        }
        Ok(Self {
            protocol,
            maximum_plaintext_bytes,
            application_stream_count: 1,
            pending_record_capacity: 0,
            allow_rekey: false,
            shared: DtlsSctpPolicy::default(),
        })
    }

    /// Admit reliable ordered application records on streams `0..stream_count`.
    ///
    /// Control records remain on ordered stream zero. `stream_count` must be
    /// at least two and is a local policy limit, not negotiated stream-count
    /// evidence. SCTP independently enforces its negotiated send range. The
    /// caller owns UE/non-UE stream assignment and must configure its SCTP
    /// association accordingly; this constructor does not assign NGAP streams.
    /// Protected records require the DTLS 1.2 wire version; DTLS 1.0 initial
    /// handshake compatibility does not extend to protected records.
    ///
    /// `pending_record_capacity` bounds both retained record/stream mappings
    /// and queued plaintexts, from one through
    /// [`MAX_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES`]. A record discarded by the
    /// engine can retain one mapping until close; exhaustion fails closed.
    /// This is an SDK resource bound, not a DTLS replay window.
    pub fn ordered_streams(
        protocol: PayloadProtocol,
        maximum_plaintext_bytes: usize,
        stream_count: u16,
        pending_record_capacity: usize,
    ) -> Result<Self, Error> {
        if stream_count < 2
            || !(1..=MAX_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES).contains(&pending_record_capacity)
        {
            return Err(Error::PolicyRejected);
        }
        let mut policy = Self::ordered_stream_zero(protocol, maximum_plaintext_bytes)?;
        policy.application_stream_count = stream_count;
        policy.pending_record_capacity = pending_record_capacity;
        Ok(policy)
    }

    /// Exclusive upper bound of the locally admitted application stream range.
    pub const fn application_stream_count(self) -> u16 {
        self.application_stream_count
    }

    /// Record correlation/queued-plaintext limit; zero denotes the legacy profile.
    pub const fn pending_record_capacity(self) -> usize {
        self.pending_record_capacity
    }

    /// Enable explicitly coordinated in-place DTLS 1.2 renegotiation.
    ///
    /// Both endpoints must select this policy before the initial handshake
    /// and call [`Connection::rekey`] for each transition. RFC 5746 binds each
    /// handshake to the preceding Finished messages. This retains the same
    /// credential/trust epoch, identity, cipher and absolute lifetime; it does
    /// not admit replacement credentials or extend authentication validity.
    pub const fn with_rekey(mut self) -> Self {
        self.allow_rekey = true;
        self
    }

    /// Restrict the existing ECDHE-ECDSA AEAD cipher allowlist.
    pub fn with_allowed_ciphers(mut self, allowed: &[Cipher]) -> Result<Self, Error> {
        self.shared = self
            .shared
            .with_allowed_ciphers(allowed)
            .map_err(|_| Error::PolicyRejected)?;
        Ok(self)
    }

    /// Bound authenticated connection age; material/certificate expiry can win.
    pub fn with_maximum_connection_age(mut self, age: Duration) -> Result<Self, Error> {
        self.shared = self
            .shared
            .with_maximum_connection_age(age)
            .map_err(|_| Error::PolicyRejected)?;
        Ok(self)
    }

    /// Selected protected payload protocol.
    pub const fn payload_protocol(self) -> PayloadProtocol {
        self.protocol
    }

    /// Maximum application plaintext bytes per record.
    pub const fn maximum_plaintext_bytes(self) -> usize {
        self.maximum_plaintext_bytes
    }

    /// Caller-selected authentication age bound.
    pub const fn maximum_connection_age(self) -> Duration {
        self.shared.maximum_connection_age()
    }
}

impl fmt::Debug for Policy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Policy([redacted])")
    }
}

/// Closed error categories containing no input, identity, packet or key values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Unsupported profile, cipher, resource bound or carrier configuration.
    #[error("rfc6083_policy_rejected")]
    PolicyRejected,
    /// The single absolute operation deadline elapsed.
    #[error("rfc6083_deadline_exceeded")]
    DeadlineExceeded,
    /// Sealed transport I/O or record/stream metadata was invalid.
    #[error("rfc6083_transport_failed")]
    Transport,
    /// The mutually authenticated handshake could not complete.
    #[error("rfc6083_handshake_failed")]
    Handshake,
    /// Certificate chain, time, signature, trust or role verification failed.
    #[error("rfc6083_authentication_failed")]
    Authentication,
    /// The presented certificate identity differs from the exact expected peer.
    #[error("rfc6083_peer_identity_mismatch")]
    PeerIdentityMismatch,
    /// Credential material was unavailable or changed during admission.
    #[error("rfc6083_material_not_admitted")]
    MaterialNotAdmitted,
    /// Plaintext or a foreign PPID reached the protected carrier.
    #[error("rfc6083_cleartext_rejected")]
    CleartextRejected,
    /// One application record exceeded the caller's finite plaintext limit.
    #[error("rfc6083_message_limit")]
    MessageLimit,
    /// The authenticated peer completed reciprocal close notification.
    #[error("rfc6083_peer_closed")]
    PeerClosed,
    /// An operation, cancellation or observed carrier termination closed it.
    #[error("rfc6083_connection_closed")]
    ConnectionClosed,
    /// Material replacement, withdrawal, certificate expiry or age retired it.
    #[error("rfc6083_retired")]
    Retired,
}

impl From<DiameterTlsError> for Error {
    fn from(error: DiameterTlsError) -> Self {
        match error {
            DiameterTlsError::ProtectionPolicyMismatch
            | DiameterTlsError::SctpReceiveQueueCapacityInvalid
            | DiameterTlsError::ProtocolRejected
            | DiameterTlsError::CipherRejected => Self::PolicyRejected,
            DiameterTlsError::DeadlineExceeded => Self::DeadlineExceeded,
            DiameterTlsError::TlsHandshake => Self::Handshake,
            DiameterTlsError::Authentication => Self::Authentication,
            DiameterTlsError::PeerIdentityMismatch => Self::PeerIdentityMismatch,
            DiameterTlsError::MaterialNotAdmitted => Self::MaterialNotAdmitted,
            DiameterTlsError::CleartextInput => Self::CleartextRejected,
            DiameterTlsError::PeerClosed => Self::PeerClosed,
            DiameterTlsError::Retired => Self::Retired,
            _ => Self::Transport,
        }
    }
}

/// Exclusive, unestablished carrier with no public DATA send/receive authority.
///
/// Selecting a protected PPID cannot create a [`Connection`]. Dropping this
/// carrier, including an unpolled establishment future, aborts its association.
pub struct Transport {
    io: Box<dyn SctpMessageIo>,
    lifetime: SctpTransportLifetimeGuard,
}

impl Transport {
    /// Consume a pristine SCTP-AUTH DATA association and choose its immutable PPID.
    ///
    /// Requires the existing minimum record receive budget and bounded queue;
    /// see [`KernelSctpMessageIo::new`]. This is the only production constructor.
    pub fn from_sctp(
        association: SctpAssociation,
        protocol: PayloadProtocol,
        receive_queue_capacity: usize,
    ) -> Result<Self, Error> {
        let io = KernelSctpMessageIo::with_protected_ppid(
            association,
            receive_queue_capacity,
            protocol.ppid(),
        )?;
        Ok(Self::from_sealed(Box::new(io)))
    }

    fn from_sealed(io: Box<dyn SctpMessageIo>) -> Self {
        let lifetime = SctpTransportLifetimeGuard::new(io.close_handle());
        Self { io, lifetime }
    }

    #[cfg(test)]
    pub(crate) fn in_memory(mut io: InMemorySctpEndpoint, protocol: PayloadProtocol) -> Self {
        io.protected_ppid = protocol.ppid();
        Self::from_sealed(Box::new(io))
    }
}

impl fmt::Debug for Transport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Transport([redacted])")
    }
}

/// Endpoint role authenticated by the completed handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Active DTLS client, verifying the server certificate and mutual exchange.
    Connector,
    /// DTLS server, requiring and verifying the client certificate.
    Acceptor,
}

#[derive(Clone)]
struct Endpoint {
    controller: TlsMaterialController,
    expected_peer: ExpectedPeer,
    policy: Policy,
    engine_config: Arc<dimpl::Config>,
    crls: Option<CrlSource>,
}

impl Endpoint {
    fn new(
        controller: TlsMaterialController,
        expected_peer: ExpectedPeer,
        policy: Policy,
    ) -> Result<Self, Error> {
        let mut engine_config = policy.shared.engine_config()?;
        if policy.allow_rekey {
            engine_config = Arc::new(
                engine_config
                    .as_ref()
                    .clone()
                    .with_rfc6083_rekey()
                    .map_err(|_| Error::PolicyRejected)?,
            );
        }
        Ok(Self {
            controller,
            expected_peer,
            policy,
            engine_config,
            crls: None,
        })
    }

    async fn establish(
        &self,
        transport: Transport,
        role: Role,
        deadline: Instant,
    ) -> Result<Connection, Error> {
        let Transport {
            mut io,
            mut lifetime,
        } = transport;
        check_deadline(deadline)?;
        if io.protected_ppid() != self.policy.protocol.ppid() {
            return Err(Error::PolicyRejected);
        }
        io.begin_direct_dtls()?;
        let establish = async {
            let PreparedMaterial {
                handshake,
                certificate,
                trust_bundles,
            } = prepare_material(&self.controller).await?;
            let mut crls = self
                .crls
                .as_ref()
                .map(|source| source.bind(handshake.epoch()))
                .transpose()?;
            let handshake_deadline = crls.as_ref().map_or(deadline, |v| {
                deadline.min(wall_expiry_deadline(
                    v.evidence().expires_at(),
                    Instant::now(),
                ))
            });
            let mut engine = new_policy_engine(Arc::clone(&self.engine_config), certificate)?;
            engine.set_active(role == Role::Connector);
            let validation = HandshakeValidation {
                expected_peer: self.expected_peer.0.clone(),
                trust_bundles,
                usage: match role {
                    Role::Connector => PeerUsage::Server,
                    Role::Acceptor => PeerUsage::Client,
                },
                revocation: crls.as_ref().map(|v| Arc::clone(&v.snapshot)),
            };
            let handshake_result = run_transport_handshake_with_streams(
                &mut engine,
                &mut io,
                &validation,
                handshake_deadline,
                streams::RecordStreams::new(
                    self.policy.application_stream_count,
                    self.policy.pending_record_capacity,
                ),
            );
            let completed = if let Some(binding) = crls.as_mut() {
                tokio::select! {
                    biased;
                    () = binding.retired() => return Err(Error::Retired),
                    result = handshake_result => result?,
                }
            } else {
                handshake_result.await?
            };
            if completed.state.peer_closed {
                return Err(Error::PeerClosed);
            }
            if !self.policy.shared.allows_cipher(completed.cipher) {
                return Err(Error::PolicyRejected);
            }
            if completed
                .state
                .inbound
                .iter()
                .any(|message| message.payload.len() > self.policy.maximum_plaintext_bytes)
            {
                return Err(Error::MessageLimit);
            }
            let admission = handshake.admit().map_err(|_| Error::MaterialNotAdmitted)?;
            let material_status = self.controller.subscribe_material_changes();
            if !material_epoch_retained(admission.epoch(), material_status.status()) {
                return Err(Error::Retired);
            }
            check_deadline(deadline)?;
            let hard_deadline = association_hard_deadline(
                Instant::now(),
                self.policy.maximum_connection_age(),
                admission.certificate_chain_expires_at(),
                completed.peer_expires_at,
            );
            let hard_deadline = crls.as_ref().map_or(hard_deadline, |v| {
                hard_deadline.min(wall_expiry_deadline(
                    v.evidence().expires_at(),
                    Instant::now(),
                ))
            });
            let close = io.close_handle();
            let retired = Arc::new(AtomicBool::new(false));
            let retirement_task = spawn_retirement_task(
                material_status.clone(),
                admission.epoch(),
                hard_deadline,
                Arc::clone(&retired),
                Arc::clone(&close),
            );
            let crl_retirement_task = crls
                .as_ref()
                .map(|v| v.spawn_retirement(Arc::clone(&retired), Arc::clone(&close)));
            let connection = Connection {
                engine,
                io,
                close,
                evidence: Evidence {
                    role,
                    protocol: self.policy.protocol,
                    application_stream_count: self.policy.application_stream_count,
                    pending_record_capacity: self.policy.pending_record_capacity,
                    allow_rekey: self.policy.allow_rekey,
                    record_epoch: 1,
                    version: completed.version,
                    cipher: completed.cipher,
                    material_epoch: admission.epoch(),
                    local_certificate_expires_at: admission.certificate_chain_expires_at(),
                    peer_certificate_expires_at: completed.peer_expires_at,
                    expected_peer: self.expected_peer.clone(),
                    crls: crls.as_ref().map(|v| v.evidence()),
                },
                maximum_plaintext_bytes: self.policy.maximum_plaintext_bytes,
                validation,
                material_status,
                hard_deadline,
                retired,
                _retirement_task: retirement_task,
                crls,
                _crl_retirement_task: crl_retirement_task,
                pump: completed.state,
                buffer: completed.buffer,
                closed: Arc::new(AtomicBool::new(false)),
            };
            connection.ensure_active()?;
            Ok(connection)
        };
        let connection = tokio::time::timeout_at(deadline, establish)
            .await
            .map_err(|_| Error::DeadlineExceeded)??;
        lifetime.disarm();
        Ok(connection)
    }
}

/// Outbound mutual-authentication endpoint using read-only material authority.
#[derive(Clone)]
pub struct Connector(Endpoint);

impl Connector {
    /// Validate immutable engine policy before accepting any peer traffic.
    pub fn new(
        material: TlsMaterialController,
        expected_peer: ExpectedPeer,
        policy: Policy,
    ) -> Result<Self, Error> {
        Endpoint::new(material, expected_peer, policy).map(Self)
    }

    /// Require complete direct CRL coverage using the source's own material
    /// controller. No handshake falls back if this exact source/epoch is unavailable.
    pub fn new_with_required_crls(
        source: CrlSource,
        expected_peer: ExpectedPeer,
        policy: Policy,
    ) -> Result<Self, Error> {
        let mut endpoint = Endpoint::new(source.controller(), expected_peer, policy)?;
        endpoint.crls = Some(source);
        Ok(Self(endpoint))
    }

    /// Consume the carrier and complete protection under one absolute deadline.
    pub async fn connect(
        &self,
        transport: Transport,
        deadline: Instant,
    ) -> Result<Connection, Error> {
        self.0.establish(transport, Role::Connector, deadline).await
    }
}

impl fmt::Debug for Connector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Connector([redacted])")
    }
}

/// Inbound mutual-authentication endpoint, requiring a verified client certificate.
#[derive(Clone)]
pub struct Acceptor(Endpoint);

impl Acceptor {
    /// Validate immutable engine policy before accepting any peer traffic.
    pub fn new(
        material: TlsMaterialController,
        expected_peer: ExpectedPeer,
        policy: Policy,
    ) -> Result<Self, Error> {
        Endpoint::new(material, expected_peer, policy).map(Self)
    }

    /// Require complete direct CRL coverage using the source's own material
    /// controller. No handshake falls back if this exact source/epoch is unavailable.
    pub fn new_with_required_crls(
        source: CrlSource,
        expected_peer: ExpectedPeer,
        policy: Policy,
    ) -> Result<Self, Error> {
        let mut endpoint = Endpoint::new(source.controller(), expected_peer, policy)?;
        endpoint.crls = Some(source);
        Ok(Self(endpoint))
    }

    /// Consume the carrier and complete protection under one absolute deadline.
    pub async fn accept(
        &self,
        transport: Transport,
        deadline: Instant,
    ) -> Result<Connection, Error> {
        self.0.establish(transport, Role::Acceptor, deadline).await
    }
}

impl fmt::Debug for Acceptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Acceptor([redacted])")
    }
}

/// Exact negotiated readback; a borrowed observation, not reusable authority.
///
/// Only a successfully established connection owns this value. Reconciliation
/// runs before [`Connection::readback`]; later retirement can invalidate the
/// connection. No protected operation can be authorized from this value alone.
pub struct Evidence {
    role: Role,
    protocol: PayloadProtocol,
    application_stream_count: u16,
    pending_record_capacity: usize,
    allow_rekey: bool,
    record_epoch: u16,
    version: Version,
    cipher: Cipher,
    material_epoch: TlsMaterialEpoch,
    local_certificate_expires_at: Timestamp,
    peer_certificate_expires_at: Timestamp,
    expected_peer: ExpectedPeer,
    crls: Option<CrlEvidence>,
}

impl Evidence {
    /// Local handshake role.
    pub const fn role(&self) -> Role {
        self.role
    }
    /// Immutable protected PPID profile.
    pub const fn payload_protocol(&self) -> PayloadProtocol {
        self.protocol
    }
    /// Locally configured application stream range, not SCTP negotiation evidence.
    pub const fn application_stream_count(&self) -> u16 {
        self.application_stream_count
    }
    /// Configured bounded correlation/queue capacity, or zero for stream zero.
    pub const fn pending_record_capacity(&self) -> usize {
        self.pending_record_capacity
    }
    /// Whether the caller enabled coordinated in-place renegotiation.
    pub const fn allows_rekey(&self) -> bool {
        self.allow_rekey
    }
    /// DTLS record epoch of the last fully authenticated handshake.
    ///
    /// This is published only after the peer Finished and SCTP-AUTH transition
    /// complete. It is distinct from the credential publication epoch and is
    /// not a kernel SCTP-AUTH key-ID readback.
    pub const fn record_epoch(&self) -> u16 {
        self.record_epoch
    }
    /// Authenticated negotiated protocol version.
    pub const fn version(&self) -> Version {
        self.version
    }
    /// Authenticated negotiated cipher.
    pub const fn cipher(&self) -> Cipher {
        self.cipher
    }
    /// Exact coherent local credential/trust epoch admitted for this handshake.
    pub const fn material_epoch(&self) -> TlsMaterialEpoch {
        self.material_epoch
    }
    /// Minimum expiry across the admitted local certificate chain.
    pub const fn local_certificate_expires_at(&self) -> Timestamp {
        self.local_certificate_expires_at
    }
    /// Minimum expiry across the verified peer certificate chain.
    pub const fn peer_certificate_expires_at(&self) -> Timestamp {
        self.peer_certificate_expires_at
    }
    /// Exact caller-selected identity that matched the verified peer certificate.
    pub const fn expected_peer(&self) -> &ExpectedPeer {
        &self.expected_peer
    }
    /// Verified direct-CRL publication, or `None` for the explicit legacy profile.
    pub const fn crls(&self) -> Option<CrlEvidence> {
        self.crls
    }
}

impl fmt::Debug for Evidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Evidence([redacted])")
    }
}

/// One authenticated application record, with value-free diagnostic formatting.
pub struct ApplicationMessage {
    payload: Bytes,
    stream_id: u16,
}

impl ApplicationMessage {
    /// Explicitly borrow the application payload.
    pub fn as_bytes(&self) -> &[u8] {
        &self.payload
    }
    /// SCTP-authenticated stream of this exact decrypted application record.
    /// This is scoped to the delivering connection, not a UE ownership proof.
    pub const fn stream_id(&self) -> u16 {
        self.stream_id
    }
    /// Consume the wrapper and take the application payload.
    pub fn into_bytes(self) -> Bytes {
        self.payload
    }
}

impl fmt::Debug for ApplicationMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApplicationMessage([redacted])")
    }
}

/// Exclusive mutually authenticated RFC 6083 connection.
///
/// No raw association or PPID can construct this capability. Operations are
/// sequential, bounded by one caller deadline and the earlier retirement
/// deadline. Once polled, cancelling or failing an operation closes the whole
/// association. Dropping the connection closes synchronously.
///
/// ```compile_fail
/// use opc_diameter_transport::rfc6083::Connection;
/// fn forge(association: opc_sctp::SctpAssociation) -> Connection {
///     association.into()
/// }
/// ```
pub struct Connection {
    engine: dimpl::Dtls,
    io: Box<dyn SctpMessageIo>,
    close: Arc<dyn SctpTransportClose>,
    evidence: Evidence,
    maximum_plaintext_bytes: usize,
    validation: HandshakeValidation,
    material_status: TlsMaterialStatusReceiver,
    hard_deadline: Instant,
    retired: Arc<AtomicBool>,
    _retirement_task: RetirementTask,
    crls: Option<revocation::Binding>,
    _crl_retirement_task: Option<RetirementTask>,
    pump: PumpState,
    buffer: Vec<u8>,
    closed: Arc<AtomicBool>,
}

impl Connection {
    /// Reconcile retirement and observed carrier termination, then borrow readback.
    ///
    /// The kernel receive task observes terminal notifications independently
    /// of application I/O. This is an observation, not a promise that a remote
    /// network change which has not reached this process has been detected.
    pub fn readback(&self) -> Result<&Evidence, Error> {
        self.ensure_active()?;
        Ok(&self.evidence)
    }

    /// Complete a fresh, connection-bound handshake on this SCTP association.
    ///
    /// Both endpoints explicitly call this operation; the connector sends the
    /// ClientHello and the acceptor waits for it. The application coordinates
    /// that decision as required by RFC 6083 section 4.6. Application writes
    /// are suspended until the new peer Finished is verified. Already admitted
    /// application records retain their stream and order. Every exporter-key,
    /// sender-drain, activation and previous-key retirement barrier runs again.
    ///
    /// The original policy must enable [`Policy::with_rekey`]. The original
    /// credential/trust epoch and expected peer are revalidated, and the
    /// absolute lifetime can only shorten. Failure or cancellation after
    /// polling closes the association, including an unsupported request.
    pub async fn rekey(&mut self, deadline: Instant) -> Result<(), Error> {
        self.ensure_active()?;
        let mut operation = OperationGuard::new(self);
        let deadline = deadline.min(self.hard_deadline);
        check_deadline(deadline)?;
        if !self.evidence.allow_rekey || !self.pump.outbound.is_empty() {
            return Err(Error::PolicyRejected);
        }
        let next_epoch = self
            .evidence
            .record_epoch
            .checked_add(1)
            .ok_or(Error::PolicyRejected)?;
        self.engine
            .begin_rfc6083_rekey()
            .map_err(|_| Error::Handshake)?;
        self.pump.connected = false;
        self.pump.peer_certificate_expires_at = None;
        let result = tokio::time::timeout_at(
            deadline,
            run_transport_handshake_with_state(
                &mut self.engine,
                &mut self.io,
                &self.validation,
                deadline,
                std::mem::take(&mut self.pump),
                std::mem::take(&mut self.buffer),
            ),
        )
        .await;
        self.ensure_authentication_current()?;
        let completed = result.map_err(|_| Error::DeadlineExceeded)??;
        self.ensure_active()?;
        check_deadline(deadline)?;
        if completed.state.peer_closed
            || completed.version != self.evidence.version
            || completed.cipher != self.evidence.cipher
            || self.engine.rfc6083_epoch() != Some(next_epoch)
        {
            return Err(Error::Handshake);
        }
        if completed
            .state
            .inbound
            .iter()
            .any(|v| v.payload.len() > self.maximum_plaintext_bytes)
        {
            return Err(Error::MessageLimit);
        }
        self.hard_deadline = self.hard_deadline.min(wall_expiry_deadline(
            completed.peer_expires_at,
            Instant::now(),
        ));
        self._retirement_task
            .replace_watcher(spawn_retirement_watcher(
                self.material_status.clone(),
                self.evidence.material_epoch,
                self.hard_deadline,
                Arc::clone(&self.retired),
                Arc::clone(&self.close),
            ));
        self.evidence.record_epoch = next_epoch;
        self.evidence.peer_certificate_expires_at = completed.peer_expires_at;
        self.pump = completed.state;
        self.buffer = completed.buffer;
        self.ensure_active()?;
        operation.disarm();
        Ok(())
    }

    /// Emit one opaque application record reliably on ordered stream zero.
    pub async fn send(&mut self, plaintext: &[u8], deadline: Instant) -> Result<(), Error> {
        self.send_on_stream(0, plaintext, deadline).await
    }

    /// Emit one application record on a locally admitted reliable ordered stream.
    ///
    /// Only application records use this stream; DTLS control remains on zero.
    /// SCTP validates the negotiated send range. As with `send`, an error or
    /// cancellation after polling closes the connection.
    pub async fn send_on_stream(
        &mut self,
        stream_id: u16,
        plaintext: &[u8],
        deadline: Instant,
    ) -> Result<(), Error> {
        self.ensure_active()?;
        let mut operation = OperationGuard::new(self);
        let deadline = deadline.min(self.hard_deadline);
        check_deadline(deadline)?;
        if plaintext.len() > self.maximum_plaintext_bytes {
            return Err(Error::MessageLimit);
        }
        let result = write_application_on_stream_via(
            &mut self.engine,
            &mut self.io,
            &mut self.pump,
            &mut self.buffer,
            plaintext,
            stream_id,
            deadline,
        )
        .await;
        self.ensure_authentication_current()?;
        result?;
        self.ensure_active()?;
        check_deadline(deadline)?;
        operation.disarm();
        Ok(())
    }

    /// Receive one authenticated opaque record with its exact ordered stream.
    pub async fn receive(&mut self, deadline: Instant) -> Result<ApplicationMessage, Error> {
        self.ensure_active()?;
        let mut operation = OperationGuard::new(self);
        let deadline = deadline.min(self.hard_deadline);
        check_deadline(deadline)?;
        let result = tokio::time::timeout_at(
            deadline,
            pump_until_inbound(
                &mut self.engine,
                &mut self.io,
                &mut self.pump,
                &mut self.buffer,
                deadline,
            ),
        )
        .await;
        self.ensure_authentication_current()?;
        result.map_err(|_| Error::DeadlineExceeded)??;
        self.ensure_active()?;
        check_deadline(deadline)?;
        let message = self.pump.inbound.pop_front().ok_or(Error::Transport)?;
        if message.payload.len() > self.maximum_plaintext_bytes {
            return Err(Error::MessageLimit);
        }
        operation.disarm();
        Ok(ApplicationMessage {
            payload: message.payload,
            stream_id: message.stream_id,
        })
    }

    /// Consume the connection and perform sender-drained reciprocal close.
    ///
    /// Pending application records cannot be silently discarded as a successful
    /// close. A timeout, failure or cancelled close still aborts the association.
    pub async fn close(mut self, deadline: Instant) -> Result<(), Error> {
        self.ensure_active()?;
        let deadline = deadline.min(self.hard_deadline);
        check_deadline(deadline)?;
        let result = tokio::time::timeout_at(
            deadline,
            close_transport_via(
                &mut self.engine,
                &mut self.io,
                &mut self.pump,
                &mut self.buffer,
                deadline,
            ),
        )
        .await;
        // An authenticated reciprocal close can terminate the carrier before
        // this future resumes. Reconcile credentials without requiring it to
        // remain open after the completed close protocol.
        self.ensure_authentication_current()?;
        result.map_err(|_| Error::DeadlineExceeded)??;
        check_deadline(deadline)?;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), Error> {
        self.ensure_authentication_current()?;
        if self.close.is_closed() {
            self.closed.store(true, Ordering::Release);
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::ConnectionClosed);
        }
        Ok(())
    }

    fn ensure_authentication_current(&self) -> Result<(), Error> {
        if self.crls.as_ref().is_some_and(|v| !v.retained())
            || retirement_required(
                &self.material_status,
                self.evidence.material_epoch,
                self.hard_deadline,
                &self.retired,
            )
        {
            self.retired.store(true, Ordering::Release);
            self.close.close();
            return Err(Error::Retired);
        }
        Ok(())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.close.close();
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Connection([redacted])")
    }
}

struct OperationGuard {
    closed: Arc<AtomicBool>,
    lifetime: SctpTransportLifetimeGuard,
}

impl OperationGuard {
    fn new(connection: &Connection) -> Self {
        Self {
            closed: Arc::clone(&connection.closed),
            lifetime: SctpTransportLifetimeGuard::new(Arc::clone(&connection.close)),
        }
    }

    fn disarm(&mut self) {
        self.lifetime.disarm();
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        if self.lifetime.armed {
            self.closed.store(true, Ordering::Release);
        }
    }
}

fn check_deadline(deadline: Instant) -> Result<(), Error> {
    if Instant::now() >= deadline {
        Err(Error::DeadlineExceeded)
    } else {
        Ok(())
    }
}
