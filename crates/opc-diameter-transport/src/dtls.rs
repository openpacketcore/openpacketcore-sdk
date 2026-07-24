//! Mutually authenticated Diameter-over-DTLS/SCTP transport.
//!
//! This module implements the RFC 6733 section 13 direct-protection sequence
//! for SCTP: a mutually authenticated DTLS session is established before any
//! Diameter byte is carried, and only then may CER/CEA and admitted
//! application commands cross the association. DTLS records are transported
//! as ordered SCTP user messages on stream 0 with PPID
//! [`DIAMETER_DTLS_SCTP_PPID`] (47, registered by RFC 6733 section 11.5 for
//! "Diameter in a DTLS/SCTP DATA chunk"; RFC 6083 section 4.3 deliberately
//! registers no DTLS-specific PPID of its own). Exactly one DTLS record is
//! carried per SCTP user message as RFC 6083 section 4.1 requires, and all
//! records use ordered stream-0 delivery per section 4.4 (Handshake, CCS,
//! and Alert records MUST; ApplicationData MAY, and this transport sends it
//! the same way because the engine's non-disableable replay window makes
//! unordered delivery lossy). PPID 47 is emitted only through an actual,
//! attested DTLS/SCTP association; this module never upgrades a cleartext or
//! PPID-only association into a protection claim.
//!
//! The DTLS engine is `dimpl` (Sans-IO, DTLS 1.2/1.3, ECDHE-ECDSA AEAD suites
//! only, no RSA/DHE/renegotiation) with its pure-Rust `rust-crypto` provider,
//! chosen so the workspace does not gain a second native crypto build. Peer
//! certificates are not PKI-validated by the engine; this module validates the
//! peer leaf certificate itself (trust-anchor chain scoped to the peer's
//! SPIFFE trust domain, validity window, exact configured SPIFFE identity)
//! with the same rustls-webpki verification family used by the TLS/TCP side,
//! and it closes the association without processing any application command
//! when validation fails.
//!
//! Key custody note: the engine's `DtlsCertificate` owns the local private
//! key as a plain, cloneable `Vec<u8>`. Handing the coherent `opc-identity`
//! key to the engine is unavoidable today; the intermediate copy made here
//! is zeroized, and zeroizing engine-side custody is tracked as follow-up
//! (see the admitted-key-custody direction in #508).
//!
//! Documented boundaries of this slice:
//!
//! - The message seam [`SctpMessageIo`] is transport-agnostic. This crate ships
//!   the deterministic in-memory adapter; binding the seam to the kernel SCTP
//!   associations in `opc-sctp` is follow-up work.
//! - RFC 6083 section 4.8 derives a 64-byte SCTP-AUTH shared secret from the
//!   DTLS exporter (RFC 5705, label `EXPORTER_DTLS_OVER_SCTP`, no context) on
//!   every handshake. `dimpl` exposes only the DTLS-SRTP export, so this
//!   slice cannot derive that secret; the SCTP-AUTH key switch prepared in
//!   `opc-sctp` remains unclaimed rather than being fed substitute material.
//! - RFC 6083 section 4.5 additionally requires SCTP DATA chunks to be sent
//!   authenticated per RFC 4895. That kernel SCTP-AUTH configuration is a
//!   separate, also unmet, association-level requirement owned by the
//!   `opc-sctp` integration, not by this record layer.
//! - The in-band CER/CEA-before-DTLS sequence of RFC 6733 section 13.1 over
//!   SCTP is not claimed here; the direct sequence is.
//! - Peer leaf certificates only: the engine presents a single certificate
//!   and this module passes an empty intermediate list to the path builder,
//!   so peers that must chain through intermediate CAs fail closed.
//! - Exact negotiated-cipher evidence is limited by the engine's public API
//!   (it reports the negotiated protocol version only). The configured cipher
//!   allow-list is still enforced at engine configuration; evidence reports
//!   the exact negotiated DTLS version.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use opc_identity::{IdentityState, TrustBundleSet, TrustDomain};
use opc_proto_diameter::peer::{
    build_capabilities_exchange_request, parse_capabilities_exchange_answer,
    parse_capabilities_exchange_error_answer, parse_capabilities_exchange_request,
    CapabilitiesExchangeAnswer, PeerCapabilities, PeerCommandAdmission, PeerCommandClass,
    PeerMessageDirection, PeerProtectionEvidence, PeerProtectionFailure, PeerProtectionMechanism,
    PeerProtectionPending, PeerProtectionReadiness, PeerProtectionRequirement,
    PeerProtectionSequence, PeerSession, PeerSessionBlocker, PeerSessionGeneration,
    PeerSessionReadiness, PeerSessionSnapshot,
};
use opc_proto_diameter::OwnedMessage;
use opc_protocol::{DecodeContext, ValidationLevel};
use opc_tls::{
    TlsMaterialAvailability, TlsMaterialEpoch, TlsMaterialReloadReason, TlsMaterialStatusReceiver,
};
use opc_types::Timestamp;
use rustls_pki_types::CertificateDer;
use tokio::sync::{mpsc, watch, Notify};
use tokio::time::Instant;
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroizing;

use crate::frame::{borrowed, decode_wire_frame, encoded_bytes, validate_wire_frame};
use crate::frame_transport::FrameTransportFuture;
use crate::tls::{begin_generation, retirement_required};
use crate::{
    DiameterCapabilitiesExchangeAnswer, DiameterCapabilitiesExchangeOutcome,
    DiameterConnectionRole, DiameterFrameLimits, DiameterTlsError, DiameterTlsPolicyError,
    ExpectedPeerIdentity,
};

/// PPID for "Diameter in a DTLS/SCTP DATA chunk" (RFC 6733 section 11.5).
pub const DIAMETER_DTLS_SCTP_PPID: u32 = 47;

/// SCTP stream carrying every record of one DTLS connection. RFC 6083
/// section 4.4 requires ordered stream-0 delivery for Handshake, CCS, and
/// Alert records; this transport uses ordered stream-0 delivery for
/// ApplicationData too.
pub const DIAMETER_DTLS_SCTP_STREAM: u16 = 0;

const ENGINE_POLL_BUFFER: usize = 16 * 1024;

/// Classic DTLS record header length (content type, version, epoch, sequence
/// number, length) used to split engine datagrams into single records.
const DTLS_RECORD_HEADER_BYTES: usize = 13;

/// One received SCTP user message surfaced through the message seam.
#[derive(Clone, PartialEq, Eq)]
pub struct SctpUserMessage {
    payload: Bytes,
    ppid: u32,
}

impl SctpUserMessage {
    /// Build one inbound user message.
    pub const fn new(payload: Bytes, ppid: u32) -> Self {
        Self { payload, ppid }
    }

    /// Borrow the user payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Payload protocol identifier carried by the SCTP DATA chunk.
    pub const fn ppid(&self) -> u32 {
        self.ppid
    }
}

impl fmt::Debug for SctpUserMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SctpUserMessage")
            .field("ppid", &self.ppid)
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// Synchronous full-close authority for one SCTP message transport.
///
/// `close` must be idempotent, must interrupt in-flight receive operations,
/// and must return promptly without waiting for asynchronous cleanup.
pub trait SctpTransportClose: Send + Sync {
    /// Close the transport and interrupt in-flight operations.
    fn close(&self);
}

/// Message-oriented SCTP seam between the DTLS association and a transport.
///
/// The send side deliberately accepts only complete DTLS records: the
/// implementation emits each record as its own ordered SCTP user message on
/// stream 0 with PPID 47 (RFC 6083 sections 4.1 and 4.4). This keeps
/// "PPID 47 only through an actual DTLS/SCTP association" and the
/// one-record-per-message rule structural properties rather than caller
/// discipline. Delivery must be ordered: the DTLS replay window discards
/// reordered records, and Handshake/CCS/Alert records are only valid on
/// ordered stream-0 delivery. The receive side surfaces every user message
/// with its PPID so the association can fail closed on any cleartext input.
pub trait SctpMessageIo: Send {
    /// Emit one complete DTLS record as one ordered PPID-47 stream-0 message.
    fn send_dtls_record<'a>(&'a mut self, record: &'a [u8]) -> FrameTransportFuture<'a, ()>;

    /// Receive the next SCTP user message, or `None` once the transport is
    /// cleanly closed and drained.
    fn receive_message(&mut self) -> FrameTransportFuture<'_, Option<SctpUserMessage>>;

    /// Synchronous close authority shared with lifetime guards.
    fn close_handle(&self) -> Arc<dyn SctpTransportClose>;
}

/// One recorded wire emission for deterministic wire-evidence assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SctpWireRecord {
    /// True when endpoint A emitted the record towards endpoint B.
    pub a_to_b: bool,
    /// Payload protocol identifier of the emitted SCTP user message.
    pub ppid: u32,
    /// Emitted payload length in bytes.
    pub payload_bytes: usize,
    /// The first bytes of the emission, enough to parse either DTLS record
    /// header format via [`parse_dtls_record_bounds`]; `None` for cleartext
    /// or truncated payloads so wire assertions can reject them.
    pub record_header: Option<[u8; DTLS_RECORD_HEADER_BYTES]>,
}

/// Shared, bounded wire log for one in-memory link.
#[derive(Clone)]
pub struct SctpWireLog {
    records: Arc<Mutex<Vec<SctpWireRecord>>>,
}

impl SctpWireLog {
    /// Snapshot the recorded wire emissions in order.
    pub fn records(&self) -> Vec<SctpWireRecord> {
        match self.records.lock() {
            Ok(records) => records.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl fmt::Debug for SctpWireLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SctpWireLog")
            .field(
                "records",
                &self
                    .records
                    .lock()
                    .map(|records| records.len())
                    .unwrap_or(0),
            )
            .finish()
    }
}

struct InMemoryShared {
    closed: AtomicBool,
    notify: Notify,
    log: Arc<Mutex<Vec<SctpWireRecord>>>,
}

struct InMemoryClose {
    shared: Arc<InMemoryShared>,
}

impl SctpTransportClose for InMemoryClose {
    fn close(&self) {
        self.shared.closed.store(true, Ordering::Release);
        self.shared.notify.notify_waiters();
    }
}

/// Deterministic in-memory SCTP message endpoint for tests and simulations.
///
/// The endpoint pair preserves one-message-in/one-message-out semantics and
/// records every emission's direction, PPID, and length into a shared
/// [`SctpWireLog`]. It is not a kernel SCTP association and carries no
/// multihoming or path semantics.
pub struct InMemorySctpEndpoint {
    tx: mpsc::Sender<SctpUserMessage>,
    rx: mpsc::Receiver<SctpUserMessage>,
    a_side: bool,
    shared: Arc<InMemoryShared>,
}

impl InMemorySctpEndpoint {
    /// Emit one raw user message with an arbitrary PPID. This bypasses the
    /// protected-record contract of [`SctpMessageIo::send_dtls_record`] and
    /// exists so tests can inject cleartext or foreign-PPID input.
    pub async fn send_raw_message(
        &mut self,
        ppid: u32,
        payload: Bytes,
    ) -> Result<(), DiameterTlsError> {
        self.emit(SctpUserMessage::new(payload, ppid)).await
    }

    /// Clone a retained raw-injection handle. Tests use it to place
    /// cleartext or foreign-PPID messages mid-session after this endpoint
    /// has been consumed by an association.
    pub fn injector(&self) -> InMemorySctpInjector {
        InMemorySctpInjector {
            tx: self.tx.clone(),
            a_side: self.a_side,
            shared: Arc::clone(&self.shared),
        }
    }

    async fn emit(&mut self, message: SctpUserMessage) -> Result<(), DiameterTlsError> {
        emit_logged(&self.tx, &self.shared, self.a_side, message).await
    }
}

/// Retained raw-injection handle for one in-memory endpoint; see
/// [`InMemorySctpEndpoint::injector`].
pub struct InMemorySctpInjector {
    tx: mpsc::Sender<SctpUserMessage>,
    a_side: bool,
    shared: Arc<InMemoryShared>,
}

impl InMemorySctpInjector {
    /// Emit one raw user message with an arbitrary PPID towards the peer.
    pub async fn send_raw_message(
        &self,
        ppid: u32,
        payload: Bytes,
    ) -> Result<(), DiameterTlsError> {
        emit_logged(
            &self.tx,
            &self.shared,
            self.a_side,
            SctpUserMessage::new(payload, ppid),
        )
        .await
    }
}

async fn emit_logged(
    tx: &mpsc::Sender<SctpUserMessage>,
    shared: &InMemoryShared,
    a_side: bool,
    message: SctpUserMessage,
) -> Result<(), DiameterTlsError> {
    if shared.closed.load(Ordering::Acquire) {
        return Err(DiameterTlsError::Transport);
    }
    if let Ok(mut log) = shared.log.lock() {
        log.push(SctpWireRecord {
            a_to_b: a_side,
            ppid: message.ppid(),
            payload_bytes: message.payload().len(),
            record_header: (message.ppid() == DIAMETER_DTLS_SCTP_PPID
                && message.payload().len() >= DTLS_RECORD_HEADER_BYTES)
                .then(|| {
                    let mut header = [0_u8; DTLS_RECORD_HEADER_BYTES];
                    header.copy_from_slice(&message.payload()[..DTLS_RECORD_HEADER_BYTES]);
                    header
                }),
        });
    }
    tx.send(message)
        .await
        .map_err(|_| DiameterTlsError::Transport)
}

impl SctpMessageIo for InMemorySctpEndpoint {
    fn send_dtls_record<'a>(&'a mut self, record: &'a [u8]) -> FrameTransportFuture<'a, ()> {
        Box::pin(async move {
            self.emit(SctpUserMessage::new(
                Bytes::copy_from_slice(record),
                DIAMETER_DTLS_SCTP_PPID,
            ))
            .await
        })
    }

    fn receive_message(&mut self) -> FrameTransportFuture<'_, Option<SctpUserMessage>> {
        Box::pin(async move {
            loop {
                if self.shared.closed.load(Ordering::Acquire) && self.rx.is_empty() {
                    return Ok(None);
                }
                tokio::select! {
                    _ = self.shared.notify.notified() => {
                        if self.shared.closed.load(Ordering::Acquire) && self.rx.is_empty() {
                            return Ok(None);
                        }
                    }
                    message = self.rx.recv() => return Ok(message),
                }
            }
        })
    }

    fn close_handle(&self) -> Arc<dyn SctpTransportClose> {
        Arc::new(InMemoryClose {
            shared: Arc::clone(&self.shared),
        })
    }
}

/// Create one in-memory endpoint pair plus its shared wire log.
pub fn in_memory_sctp_link(
    capacity: usize,
) -> (InMemorySctpEndpoint, InMemorySctpEndpoint, SctpWireLog) {
    let (a_tx, b_rx) = mpsc::channel(capacity.max(1));
    let (b_tx, a_rx) = mpsc::channel(capacity.max(1));
    let shared = Arc::new(InMemoryShared {
        closed: AtomicBool::new(false),
        notify: Notify::new(),
        log: Arc::new(Mutex::new(Vec::new())),
    });
    let log = SctpWireLog {
        records: Arc::clone(&shared.log),
    };
    (
        InMemorySctpEndpoint {
            tx: a_tx,
            rx: a_rx,
            a_side: true,
            shared: Arc::clone(&shared),
        },
        InMemorySctpEndpoint {
            tx: b_tx,
            rx: b_rx,
            a_side: false,
            shared,
        },
        log,
    )
}

/// DTLS protocol versions admitted by this transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DtlsSctpVersion {
    /// DTLS 1.2 (RFC 6347) with ECDHE-ECDSA AEAD suites.
    Dtls12,
    /// DTLS 1.3 (RFC 9147).
    Dtls13,
}

/// Cipher-suite evidence names admitted by this transport.
///
/// The same AEAD names cover both protocol versions; DTLS 1.2 negotiates
/// them as ECDHE-ECDSA suites and DTLS 1.3 as TLS 1.3 suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DtlsSctpCipher {
    /// TLS_AES_128_GCM_SHA256 / ECDHE-ECDSA-AES128-GCM-SHA256.
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384 / ECDHE-ECDSA-AES256-GCM-SHA384.
    Aes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256 / ECDHE-ECDSA-CHACHA20-POLY1305.
    Chacha20Poly1305Sha256,
}

impl DtlsSctpCipher {
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

    const fn dtls12_suite(self) -> dimpl::crypto::Dtls12CipherSuite {
        match self {
            Self::Aes128GcmSha256 => {
                dimpl::crypto::Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256
            }
            Self::Aes256GcmSha384 => {
                dimpl::crypto::Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384
            }
            Self::Chacha20Poly1305Sha256 => {
                dimpl::crypto::Dtls12CipherSuite::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256
            }
        }
    }

    const fn dtls13_suite(self) -> dimpl::crypto::Dtls13CipherSuite {
        match self {
            Self::Aes128GcmSha256 => dimpl::crypto::Dtls13CipherSuite::AES_128_GCM_SHA256,
            Self::Aes256GcmSha384 => dimpl::crypto::Dtls13CipherSuite::AES_256_GCM_SHA384,
            Self::Chacha20Poly1305Sha256 => {
                dimpl::crypto::Dtls13CipherSuite::CHACHA20_POLY1305_SHA256
            }
        }
    }
}

/// Maximum Diameter message wire length the DTLS/SCTP path may carry.
///
/// Each Diameter message is carried as the plaintext of exactly one DTLS
/// record (RFC 6083 section 4.1 admits exactly one record per SCTP user
/// message). RFC 9147 and RFC 6347 bound one record's plaintext to 2^14
/// bytes; with AEAD and header overhead the ciphertext then stays within the
/// 2^14 + 2048 record bound and the 2^14 + 2048 + 13 SCTP user-message budget
/// of RFC 6083. The engine does not fragment application data across
/// records, so a larger configured frame limit must be rejected at policy
/// construction rather than letting the u16 record length wrap.
pub const MAX_DTLS_SCTP_MESSAGE_BYTES: usize = 16_384;

/// Typed DTLS/SCTP protocol, cipher, frame, and age policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtlsSctpPolicy {
    allow_dtls12: bool,
    allowed_ciphers: [bool; 3],
    frame_limits: DiameterFrameLimits,
    maximum_connection_age: Duration,
}

impl DtlsSctpPolicy {
    /// DTLS 1.3-only policy with all supported AEAD suites. DTLS 1.2
    /// compatibility is deliberately not admitted by default. The frame
    /// limit must not exceed [`MAX_DTLS_SCTP_MESSAGE_BYTES`].
    pub fn dtls13(frame_limits: DiameterFrameLimits) -> Result<Self, DiameterTlsPolicyError> {
        if frame_limits.max_message_len() > MAX_DTLS_SCTP_MESSAGE_BYTES {
            return Err(DiameterTlsPolicyError::FrameLimitExceedsDtlsRecordBudget);
        }
        Ok(Self {
            allow_dtls12: false,
            allowed_ciphers: [true; 3],
            frame_limits,
            maximum_connection_age: Duration::from_secs(60 * 60),
        })
    }

    /// Additionally admit DTLS 1.2 with ECDHE-ECDSA AEAD suites for
    /// interoperability with peers that have no DTLS 1.3 stack.
    #[must_use]
    pub const fn with_dtls12_compatibility(mut self) -> Self {
        self.allow_dtls12 = true;
        self
    }

    /// Restrict the cipher suites advertised during the DTLS handshake.
    pub fn with_allowed_ciphers(
        mut self,
        allowed: &[DtlsSctpCipher],
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
    /// association. Material epoch changes retire immediately; local or peer
    /// certificate expiry may impose an earlier bound.
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

    /// Diameter frame bounds used by the association.
    pub const fn frame_limits(self) -> DiameterFrameLimits {
        self.frame_limits
    }

    /// Hard maximum age of one authenticated association.
    pub const fn maximum_connection_age(self) -> Duration {
        self.maximum_connection_age
    }

    /// Return whether a cipher is admitted.
    pub const fn allows_cipher(self, cipher: DtlsSctpCipher) -> bool {
        self.allowed_ciphers[cipher.index()]
    }

    /// Enumerate the finite supported cipher evidence values.
    pub fn allowed_ciphers(self) -> impl Iterator<Item = DtlsSctpCipher> {
        DtlsSctpCipher::ALL
            .into_iter()
            .filter(move |cipher| self.allows_cipher(*cipher))
    }

    fn engine_config(&self) -> Result<Arc<dimpl::Config>, DiameterTlsError> {
        let dtls13: Vec<_> = self
            .allowed_ciphers()
            .map(DtlsSctpCipher::dtls13_suite)
            .collect();
        let dtls12: Vec<_> = self
            .allowed_ciphers()
            .map(DtlsSctpCipher::dtls12_suite)
            .collect();
        let config = dimpl::Config::builder()
            .require_client_certificate(true)
            .dtls13_cipher_suites(&dtls13)
            .dtls12_cipher_suites(&dtls12)
            .build()
            .map_err(|_| DiameterTlsError::MaterialNotAdmitted)?;
        Ok(Arc::new(config))
    }
}

impl Default for DtlsSctpPolicy {
    fn default() -> Self {
        let limits = DiameterFrameLimits::new(MAX_DTLS_SCTP_MESSAGE_BYTES)
            .unwrap_or_else(|_| DiameterFrameLimits::default());
        Self::dtls13(limits).unwrap_or_else(|_| Self {
            allow_dtls12: false,
            allowed_ciphers: [true; 3],
            frame_limits: limits,
            maximum_connection_age: Duration::from_secs(60 * 60),
        })
    }
}

/// Redaction-safe negotiated evidence for an admitted DTLS/SCTP association.
///
/// Carries the local endpoint role, the exact negotiated DTLS protocol
/// version, the coherent local credential epoch admitted for the handshake,
/// local and peer certificate expiry evidence, and the exact Diameter
/// generation-bound protection evidence. Peer identity and certificate
/// material are never exposed. The exact negotiated cipher suite is not
/// reported by the engine's public API; the configured allow-list in
/// [`DtlsSctpPolicy`] bounds what can be negotiated.
#[derive(Clone, PartialEq, Eq)]
pub struct DiameterDtlsSctpEvidence {
    role: DiameterConnectionRole,
    version: DtlsSctpVersion,
    material_epoch: TlsMaterialEpoch,
    local_certificate_expires_at: Timestamp,
    peer_certificate_expires_at: Timestamp,
    protection: PeerProtectionEvidence,
}

impl DiameterDtlsSctpEvidence {
    /// Local endpoint role in the DTLS handshake.
    pub const fn role(&self) -> DiameterConnectionRole {
        self.role
    }

    /// Negotiated and policy-admitted DTLS version.
    pub const fn version(&self) -> DtlsSctpVersion {
        self.version
    }

    /// Exact coherent local credential epoch admitted for the handshake.
    pub const fn material_epoch(&self) -> TlsMaterialEpoch {
        self.material_epoch
    }

    /// Local credential expiry evidence.
    pub const fn local_certificate_expires_at(&self) -> Timestamp {
        self.local_certificate_expires_at
    }

    /// Verified peer certificate expiry evidence.
    pub const fn peer_certificate_expires_at(&self) -> Timestamp {
        self.peer_certificate_expires_at
    }

    /// Exact Diameter generation-bound protection evidence.
    pub const fn protection(&self) -> PeerProtectionEvidence {
        self.protection
    }
}

impl fmt::Debug for DiameterDtlsSctpEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterDtlsSctpEvidence")
            .field("role", &self.role)
            .field("version", &self.version)
            .field("material_epoch", &self.material_epoch)
            .field(
                "local_certificate_expires_at",
                &self.local_certificate_expires_at,
            )
            .field(
                "peer_certificate_expires_at",
                &self.peer_certificate_expires_at,
            )
            .field("protection", &self.protection)
            .finish()
    }
}

/// Coherent local credential snapshot admitted for one handshake.
struct AdmittedMaterial {
    certificate: dimpl::DtlsCertificate,
    trust_bundles: TrustBundleSet,
    epoch: TlsMaterialEpoch,
    local_expires_at: Timestamp,
}

fn admit_material(
    source: &mut watch::Receiver<Option<IdentityState>>,
    status: &TlsMaterialStatusReceiver,
) -> Result<AdmittedMaterial, DiameterTlsError> {
    let snapshot = source.borrow_and_update().clone();
    let state = snapshot.ok_or(DiameterTlsError::MaterialNotAdmitted)?;
    if state.is_expired() {
        return Err(DiameterTlsError::MaterialNotAdmitted);
    }
    let leaf = state
        .svid
        .cert_chain
        .first()
        .ok_or(DiameterTlsError::MaterialNotAdmitted)?;
    // `SvidDocument::expires_at` tracks not_after only; a not-yet-valid local
    // certificate must not be admitted either (the peer-side check alone
    // would leave the asymmetry).
    let (not_before, not_after) = local_leaf_validity_window(leaf.as_ref())?;
    let now = Timestamp::now_utc();
    if now < not_before || now >= not_after {
        return Err(DiameterTlsError::MaterialNotAdmitted);
    }
    let status_value = status.status();
    if !matches!(
        status_value.availability(),
        TlsMaterialAvailability::Ready | TlsMaterialAvailability::RetainingLastGood
    ) {
        return Err(DiameterTlsError::MaterialNotAdmitted);
    }
    // dimpl's `DtlsCertificate` owns plain `Vec<u8>` key material with no
    // zeroization and a `Clone` derive; that custody loss is engine-forced.
    // The intermediate copy here is zeroized so this crate does not add a
    // second long-lived plaintext copy (see also the module docs and the
    // admitted-key-custody direction in #508).
    let private_key = Zeroizing::new(state.svid.private_key.secret_der().to_vec());
    let certificate = dimpl::DtlsCertificate {
        certificate: leaf.as_ref().to_vec(),
        private_key: private_key.to_vec(),
    };
    Ok(AdmittedMaterial {
        certificate,
        trust_bundles: state.trust_bundles,
        epoch: status_value.epoch(),
        local_expires_at: state.svid.expires_at,
    })
}

fn local_leaf_validity_window(der: &[u8]) -> Result<(Timestamp, Timestamp), DiameterTlsError> {
    let (_, certificate) =
        X509Certificate::from_der(der).map_err(|_| DiameterTlsError::MaterialNotAdmitted)?;
    let to_timestamp = |asn1: x509_parser::time::ASN1Time| {
        time::OffsetDateTime::from_unix_timestamp(asn1.timestamp())
            .map(Timestamp::from_offset_datetime)
            .map_err(|_| DiameterTlsError::MaterialNotAdmitted)
    };
    let validity = certificate.validity();
    Ok((
        to_timestamp(validity.not_before)?,
        to_timestamp(validity.not_after)?,
    ))
}

/// Peer certificate usage verified against the leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerUsage {
    Server,
    Client,
}

struct HandshakeValidation {
    expected_peer: ExpectedPeerIdentity,
    trust_bundles: TrustBundleSet,
    usage: PeerUsage,
    allow_dtls12: bool,
}

const SIGNATURE_ALGORITHMS: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P256_SHA384,
    webpki::ring::ECDSA_P384_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
    webpki::ring::ED25519,
];

fn peer_leaf_expiry(der: &[u8]) -> Result<Timestamp, DiameterTlsError> {
    let (_, certificate) =
        X509Certificate::from_der(der).map_err(|_| DiameterTlsError::Authentication)?;
    let not_after = certificate.validity().not_after.timestamp();
    let expiry = time::OffsetDateTime::from_unix_timestamp(not_after)
        .map_err(|_| DiameterTlsError::Authentication)?;
    Ok(Timestamp::from_offset_datetime(expiry))
}

fn validate_peer_certificate(
    der: &[u8],
    validation: &HandshakeValidation,
) -> Result<Timestamp, DiameterTlsError> {
    let expiry = peer_leaf_expiry(der)?;
    let peer_spiffe = opc_identity::extract_spiffe_id_from_cert_der(der)
        .map_err(|_| DiameterTlsError::Authentication)?;
    if peer_spiffe != *validation.expected_peer.spiffe_id() {
        return Err(DiameterTlsError::PeerIdentityMismatch);
    }
    // Anchors are scoped to the peer leaf's SPIFFE trust domain, mirroring
    // the TLS/TCP verifier in opc-tls: a certificate chaining to an anchor
    // that is trusted for a *different* domain must fail closed even when
    // that anchor is present in the local trust store.
    let trust_domain = TrustDomain::new(peer_spiffe.trust_domain())
        .map_err(|_| DiameterTlsError::Authentication)?;
    let bundle = validation
        .trust_bundles
        .get(&trust_domain)
        .ok_or(DiameterTlsError::Authentication)?;
    let anchors: Vec<_> = bundle
        .certificates
        .iter()
        .filter_map(|anchor| webpki::anchor_from_trusted_cert(anchor).ok())
        .collect();
    if anchors.is_empty() {
        return Err(DiameterTlsError::MaterialNotAdmitted);
    }
    let cert_der = CertificateDer::from(der.to_vec());
    let end_entity =
        webpki::EndEntityCert::try_from(&cert_der).map_err(|_| DiameterTlsError::Authentication)?;
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| DiameterTlsError::Authentication)?;
    let usage = match validation.usage {
        PeerUsage::Server => webpki::KeyUsage::server_auth(),
        PeerUsage::Client => webpki::KeyUsage::client_auth(),
    };
    // Leaf-only path building: the engine presents a single peer
    // certificate and no intermediates are carried, so peers that must
    // chain through an intermediate CA fail closed here.
    end_entity
        .verify_for_usage(
            SIGNATURE_ALGORITHMS,
            &anchors,
            &[],
            rustls_pki_types::UnixTime::since_unix_epoch(since_epoch),
            usage,
            None,
            None,
        )
        .map_err(|_| DiameterTlsError::Authentication)?;
    Ok(expiry)
}

#[derive(Default)]
struct PumpState {
    connected: bool,
    peer_certificate_expires_at: Option<Timestamp>,
    inbound: VecDeque<Bytes>,
    peer_closed: bool,
    outbound: Vec<Bytes>,
}

fn poll_engine(
    engine: &mut dimpl::Dtls,
    validation: Option<&HandshakeValidation>,
    state: &mut PumpState,
    buffer: &mut Vec<u8>,
) -> Result<Option<std::time::Instant>, DiameterTlsError> {
    loop {
        match engine.poll_output(buffer) {
            dimpl::Output::Packet(packet) => state.outbound.push(Bytes::copy_from_slice(packet)),
            dimpl::Output::BufferTooSmall { needed } => buffer.resize(needed, 0),
            dimpl::Output::Timeout(next) => return Ok(Some(next)),
            dimpl::Output::Connected => state.connected = true,
            dimpl::Output::PeerCert(der) => {
                let Some(validation) = validation else {
                    return Err(DiameterTlsError::TlsHandshake);
                };
                state.peer_certificate_expires_at =
                    Some(validate_peer_certificate(der, validation)?);
            }
            dimpl::Output::ApplicationData(plaintext) => {
                if !state.connected {
                    return Err(DiameterTlsError::CleartextInput);
                }
                state.inbound.push_back(Bytes::copy_from_slice(plaintext));
            }
            dimpl::Output::CloseNotify => state.peer_closed = true,
            // DTLS-SRTP keying material is not used by this transport; future
            // engine variants carry no Diameter semantics either.
            _ => {}
        }
    }
}

/// Parsed framing of one DTLS record on the wire, covering both the classic
/// 13-byte header (epoch-0 plaintext and all DTLS 1.2 records) and the
/// RFC 9147 unified ciphertext header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtlsRecordBounds {
    /// Record header length in bytes.
    pub header_bytes: usize,
    /// Total record length (header plus fragment) in bytes.
    pub record_bytes: usize,
    /// Plaintext content type for classic headers; ciphertext records carry
    /// the real content type inside the protected tail, so it is `None`.
    pub content_type: Option<u8>,
    /// Classic-header epoch, or the two low epoch bits of a unified header.
    pub epoch: u16,
    /// Whether this record used the RFC 9147 unified header.
    pub unified: bool,
}

/// Parse the framing of the first record in `frame`.
///
/// Returns `None` for truncated or unsupported shapes. Unified headers with
/// a connection ID are rejected: the engine never negotiates connection IDs
/// and the CID length is otherwise unknowable from the wire alone.
pub fn parse_dtls_record_bounds(frame: &[u8]) -> Option<DtlsRecordBounds> {
    let first = *frame.first()?;
    if first & 0b1110_0000 == 0b0010_0000 {
        // RFC 9147 unified header: C(0x10) S(0x08) L(0x04) epoch(0x03).
        if first & 0b0001_0000 != 0 {
            return None;
        }
        let sequence_bytes = if first & 0b0000_1000 != 0 { 2 } else { 1 };
        let has_length = first & 0b0000_0100 != 0;
        let header_bytes = 1 + sequence_bytes + if has_length { 2 } else { 0 };
        if frame.len() < header_bytes {
            return None;
        }
        let record_bytes = if has_length {
            let declared = usize::from(u16::from_be_bytes([
                frame[1 + sequence_bytes],
                frame[2 + sequence_bytes],
            ]));
            header_bytes.checked_add(declared)?
        } else {
            // No explicit length: the record fills the remainder of the
            // datagram, which is the whole user message here.
            frame.len()
        };
        Some(DtlsRecordBounds {
            header_bytes,
            record_bytes,
            content_type: None,
            epoch: u16::from(first & 0b0000_0011),
            unified: true,
        })
    } else {
        if frame.len() < DTLS_RECORD_HEADER_BYTES {
            return None;
        }
        let declared = usize::from(u16::from_be_bytes([frame[11], frame[12]]));
        let record_bytes = DTLS_RECORD_HEADER_BYTES.checked_add(declared)?;
        Some(DtlsRecordBounds {
            header_bytes: DTLS_RECORD_HEADER_BYTES,
            record_bytes,
            content_type: Some(first),
            epoch: u16::from_be_bytes([frame[3], frame[4]]),
            unified: false,
        })
    }
}

/// Split one engine datagram into the individual DTLS records it carries.
///
/// RFC 6083 section 4.1 requires exactly one DTLS record per SCTP user
/// message, while the engine may coalesce several records into one datagram.
/// The record framing is parsed defensively; a malformed boundary fails the
/// association closed.
fn split_dtls_records(datagram: &[u8]) -> Result<Vec<&[u8]>, DiameterTlsError> {
    let mut records = Vec::new();
    let mut remaining = datagram;
    while !remaining.is_empty() {
        let bounds = parse_dtls_record_bounds(remaining).ok_or(DiameterTlsError::Transport)?;
        if bounds.record_bytes == 0 || bounds.record_bytes > remaining.len() {
            return Err(DiameterTlsError::Transport);
        }
        records.push(&remaining[..bounds.record_bytes]);
        remaining = &remaining[bounds.record_bytes..];
    }
    Ok(records)
}

async fn flush_outbound(
    io: &mut Box<dyn SctpMessageIo>,
    state: &mut PumpState,
) -> Result<(), DiameterTlsError> {
    let datagrams: Vec<Bytes> = state.outbound.drain(..).collect();
    for datagram in datagrams {
        for record in split_dtls_records(&datagram)? {
            io.send_dtls_record(record).await?;
        }
    }
    Ok(())
}

fn negotiated_version(
    engine: &dimpl::Dtls,
    allow_dtls12: bool,
) -> Result<DtlsSctpVersion, DiameterTlsError> {
    match engine.protocol_version() {
        Some(dimpl::ProtocolVersion::DTLS1_3) => Ok(DtlsSctpVersion::Dtls13),
        Some(dimpl::ProtocolVersion::DTLS1_2) if allow_dtls12 => Ok(DtlsSctpVersion::Dtls12),
        Some(_) => Err(DiameterTlsError::ProtocolRejected),
        None => Err(DiameterTlsError::TlsHandshake),
    }
}

enum PumpEvent {
    Message(Option<SctpUserMessage>),
    Timer,
    Deadline,
}

async fn pump_wait(
    io: &mut Box<dyn SctpMessageIo>,
    next_timer: Option<std::time::Instant>,
    deadline: Instant,
) -> Result<PumpEvent, DiameterTlsError> {
    let Some(timer) = next_timer else {
        // No engine timer pending; wait for input or the caller deadline only.
        return Ok(tokio::select! {
            () = tokio::time::sleep_until(deadline) => PumpEvent::Deadline,
            message = io.receive_message() => PumpEvent::Message(message?),
        });
    };
    Ok(tokio::select! {
        () = tokio::time::sleep_until(deadline) => PumpEvent::Deadline,
        () = tokio::time::sleep_until(Instant::from_std(timer)) => PumpEvent::Timer,
        message = io.receive_message() => PumpEvent::Message(message?),
    })
}

async fn run_handshake(
    engine: &mut dimpl::Dtls,
    io: &mut Box<dyn SctpMessageIo>,
    validation: &HandshakeValidation,
    deadline: Instant,
) -> Result<(DtlsSctpVersion, Timestamp), DiameterTlsError> {
    // dimpl starts the client flight and seeds server state from
    // handle_timeout; the explicit initial kick keeps the handshake
    // deterministic instead of depending on the engine's first timer.
    engine
        .handle_timeout(std::time::Instant::now())
        .map_err(|_| DiameterTlsError::TlsHandshake)?;
    let mut state = PumpState::default();
    let mut buffer = vec![0_u8; ENGINE_POLL_BUFFER];
    loop {
        // Engine progress is evaluated before waiting so a completed
        // handshake never blocks on an event that already arrived.
        let next_timer = poll_engine(engine, Some(validation), &mut state, &mut buffer)?;
        flush_outbound(io, &mut state).await?;
        if state.connected {
            let version = negotiated_version(engine, validation.allow_dtls12)?;
            let expires_at = state
                .peer_certificate_expires_at
                .ok_or(DiameterTlsError::Authentication)?;
            return Ok((version, expires_at));
        }
        if state.peer_closed {
            return Err(DiameterTlsError::TlsHandshake);
        }
        match pump_wait(io, next_timer, deadline).await? {
            PumpEvent::Deadline => return Err(DiameterTlsError::DeadlineExceeded),
            PumpEvent::Timer => engine
                .handle_timeout(std::time::Instant::now())
                .map_err(|_| DiameterTlsError::TlsHandshake)?,
            PumpEvent::Message(None) => return Err(DiameterTlsError::Transport),
            PumpEvent::Message(Some(message)) => {
                if message.ppid() != DIAMETER_DTLS_SCTP_PPID {
                    return Err(DiameterTlsError::CleartextInput);
                }
                engine
                    .handle_packet(message.payload())
                    .map_err(|_| DiameterTlsError::TlsHandshake)?;
            }
        }
    }
}

async fn pump_until_inbound(
    engine: &mut dimpl::Dtls,
    io: &mut Box<dyn SctpMessageIo>,
    state: &mut PumpState,
    buffer: &mut Vec<u8>,
    deadline: Instant,
) -> Result<(), DiameterTlsError> {
    loop {
        // Engine progress is evaluated before waiting so plaintext delivered
        // by the most recent input is surfaced without another event.
        let next_timer = poll_engine(engine, None, state, buffer)?;
        flush_outbound(io, state).await?;
        if !state.inbound.is_empty() {
            return Ok(());
        }
        if state.peer_closed {
            return Err(DiameterTlsError::Transport);
        }
        match pump_wait(io, next_timer, deadline).await? {
            PumpEvent::Deadline => return Err(DiameterTlsError::DeadlineExceeded),
            PumpEvent::Timer => engine
                .handle_timeout(std::time::Instant::now())
                .map_err(|_| DiameterTlsError::Transport)?,
            PumpEvent::Message(None) => return Err(DiameterTlsError::Transport),
            PumpEvent::Message(Some(message)) => {
                if message.ppid() != DIAMETER_DTLS_SCTP_PPID {
                    return Err(DiameterTlsError::CleartextInput);
                }
                engine
                    .handle_packet(message.payload())
                    .map_err(|_| DiameterTlsError::Transport)?;
            }
        }
    }
}

fn fail_pending(
    session: &mut PeerSession,
    pending: &PeerProtectionPending,
    failure: PeerProtectionFailure,
) {
    let _ = session.fail_pending_protection(pending, failure);
}

fn bind_dtls_session(
    session: &mut PeerSession,
) -> Result<(PeerSessionGeneration, PeerProtectionPending), DiameterTlsError> {
    let generation = begin_generation(session, PeerProtectionRequirement::direct_dtls_sctp())?;
    let pending = session
        .pending_protection()
        .ok_or(DiameterTlsError::PeerBinding)?;
    if pending.mechanism() != PeerProtectionMechanism::DtlsSctp
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

fn association_hard_deadline(
    established_at: Instant,
    maximum_age: Duration,
    local_expiry: Timestamp,
    peer_expiry: Timestamp,
) -> Instant {
    let maximum_age_deadline = established_at
        .checked_add(maximum_age)
        .unwrap_or(established_at);
    maximum_age_deadline
        .min(wall_expiry_deadline(local_expiry, established_at))
        .min(wall_expiry_deadline(peer_expiry, established_at))
}

struct RetirementTask {
    task: tokio::task::JoinHandle<()>,
    close: Arc<dyn SctpTransportClose>,
}

impl Drop for RetirementTask {
    fn drop(&mut self) {
        // Abort scheduling is not a synchronous lifetime boundary. Close the
        // transport first so ordinary handle drop cannot leave a live peer
        // association while the runtime is starved.
        self.close.close();
        self.task.abort();
    }
}

fn spawn_retirement_task(
    mut material_status: TlsMaterialStatusReceiver,
    admitted_epoch: TlsMaterialEpoch,
    hard_deadline: Instant,
    retired: Arc<AtomicBool>,
    close: Arc<dyn SctpTransportClose>,
) -> RetirementTask {
    let task_close = Arc::clone(&close);
    let task = tokio::spawn(async move {
        let hard_deadline_sleep = tokio::time::sleep_until(hard_deadline);
        tokio::pin!(hard_deadline_sleep);
        loop {
            tokio::select! {
                () = &mut hard_deadline_sleep => break,
                changed = material_status.changed() => {
                    let Ok(status) = changed else { break };
                    if !material_epoch_retained(admitted_epoch, status) {
                        break;
                    }
                }
            }
        }
        retired.store(true, Ordering::Release);
        task_close.close();
    });
    RetirementTask {
        task,
        close: Arc::clone(&close),
    }
}

fn material_epoch_retained(epoch: TlsMaterialEpoch, status: opc_tls::TlsMaterialStatus) -> bool {
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

/// Outbound mutually authenticated Diameter DTLS/SCTP connector.
pub struct DiameterDtlsSctpConnector {
    material_source: watch::Receiver<Option<IdentityState>>,
    material_status: TlsMaterialStatusReceiver,
    expected_peer: ExpectedPeerIdentity,
    policy: DtlsSctpPolicy,
}

impl DiameterDtlsSctpConnector {
    /// Create a connector that requires an exact authenticated peer identity.
    pub const fn new(
        material_source: watch::Receiver<Option<IdentityState>>,
        material_status: TlsMaterialStatusReceiver,
        expected_peer: ExpectedPeerIdentity,
        policy: DtlsSctpPolicy,
    ) -> Self {
        Self {
            material_source,
            material_status,
            expected_peer,
            policy,
        }
    }

    /// Complete mutually authenticated DTLS before any Diameter byte can be
    /// emitted. The SCTP message transport must be freshly established; any
    /// cleartext user message fails the association closed.
    pub async fn connect_direct(
        &self,
        io: Box<dyn SctpMessageIo>,
        mut session: PeerSession,
        deadline: Instant,
    ) -> Result<DiameterDtlsSctpConnection, DiameterTlsError> {
        let (generation, pending) = bind_dtls_session(&mut session)?;
        let mut source = self.material_source.clone();
        let material = match admit_material(&mut source, &self.material_status) {
            Ok(material) => material,
            Err(error) => {
                fail_pending(
                    &mut session,
                    &pending,
                    PeerProtectionFailure::HandshakeFailed,
                );
                return Err(error);
            }
        };
        let mut engine = self.new_engine(material_certificate(&material)?)?;
        engine.set_active(true);
        let validation = HandshakeValidation {
            expected_peer: self.expected_peer.clone(),
            trust_bundles: material.trust_bundles.clone(),
            usage: PeerUsage::Server,
            allow_dtls12: self.policy.allow_dtls12,
        };
        let mut io = io;
        let established = match run_handshake(&mut engine, &mut io, &validation, deadline).await {
            Ok(established) => established,
            Err(error) => {
                fail_pending(
                    &mut session,
                    &pending,
                    PeerProtectionFailure::HandshakeFailed,
                );
                return Err(error);
            }
        };
        finish_association(
            engine,
            io,
            material,
            self.material_status.clone(),
            session,
            generation,
            pending,
            self.expected_peer.clone(),
            DiameterConnectionRole::Connector,
            self.policy,
            established,
        )
    }
}

impl DiameterDtlsSctpConnector {
    fn new_engine(
        &self,
        certificate: dimpl::DtlsCertificate,
    ) -> Result<dimpl::Dtls, DiameterTlsError> {
        new_policy_engine(&self.policy, certificate)
    }
}

impl fmt::Debug for DiameterDtlsSctpConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterDtlsSctpConnector")
            .field("expected_peer", &self.expected_peer)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// Inbound mutually authenticated Diameter DTLS/SCTP acceptor.
pub struct DiameterDtlsSctpAcceptor {
    material_source: watch::Receiver<Option<IdentityState>>,
    material_status: TlsMaterialStatusReceiver,
    expected_peer: ExpectedPeerIdentity,
    policy: DtlsSctpPolicy,
}

impl DiameterDtlsSctpAcceptor {
    /// Create an acceptor that requires an exact configured inbound identity.
    /// Any other authenticated or unauthenticated peer is failed closed.
    pub const fn new(
        material_source: watch::Receiver<Option<IdentityState>>,
        material_status: TlsMaterialStatusReceiver,
        expected_peer: ExpectedPeerIdentity,
        policy: DtlsSctpPolicy,
    ) -> Self {
        Self {
            material_source,
            material_status,
            expected_peer,
            policy,
        }
    }

    /// Complete mutually authenticated DTLS on an accepted SCTP association
    /// before reading any Diameter byte. A stale credential epoch closes this
    /// association; the listener may accept a fresh one with a fresh
    /// generation.
    pub async fn accept_direct(
        &self,
        io: Box<dyn SctpMessageIo>,
        mut session: PeerSession,
        deadline: Instant,
    ) -> Result<DiameterDtlsSctpConnection, DiameterTlsError> {
        let (generation, pending) = bind_dtls_session(&mut session)?;
        let mut source = self.material_source.clone();
        let material = match admit_material(&mut source, &self.material_status) {
            Ok(material) => material,
            Err(error) => {
                fail_pending(
                    &mut session,
                    &pending,
                    PeerProtectionFailure::HandshakeFailed,
                );
                return Err(error);
            }
        };
        let mut engine = self.new_engine(material_certificate(&material)?)?;
        let validation = HandshakeValidation {
            expected_peer: self.expected_peer.clone(),
            trust_bundles: material.trust_bundles.clone(),
            usage: PeerUsage::Client,
            allow_dtls12: self.policy.allow_dtls12,
        };
        let mut io = io;
        let established = match run_handshake(&mut engine, &mut io, &validation, deadline).await {
            Ok(established) => established,
            Err(error) => {
                fail_pending(
                    &mut session,
                    &pending,
                    PeerProtectionFailure::HandshakeFailed,
                );
                return Err(error);
            }
        };
        finish_association(
            engine,
            io,
            material,
            self.material_status.clone(),
            session,
            generation,
            pending,
            self.expected_peer.clone(),
            DiameterConnectionRole::Acceptor,
            self.policy,
            established,
        )
    }
}

impl DiameterDtlsSctpAcceptor {
    fn new_engine(
        &self,
        certificate: dimpl::DtlsCertificate,
    ) -> Result<dimpl::Dtls, DiameterTlsError> {
        new_policy_engine(&self.policy, certificate)
    }
}

impl fmt::Debug for DiameterDtlsSctpAcceptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterDtlsSctpAcceptor")
            .field("expected_peer", &self.expected_peer)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// Construct the engine for the policy version floor. A DTLS 1.3-only policy
/// must not auto-sense down to DTLS 1.2; only the explicit compatibility
/// policy uses the version-sensing constructor.
fn new_policy_engine(
    policy: &DtlsSctpPolicy,
    certificate: dimpl::DtlsCertificate,
) -> Result<dimpl::Dtls, DiameterTlsError> {
    let config = policy.engine_config()?;
    Ok(if policy.allow_dtls12 {
        dimpl::Dtls::new_auto(config, certificate, std::time::Instant::now())
    } else {
        dimpl::Dtls::new_13(config, certificate, std::time::Instant::now())
    })
}

fn material_certificate(
    material: &AdmittedMaterial,
) -> Result<dimpl::DtlsCertificate, DiameterTlsError> {
    Ok(dimpl::DtlsCertificate {
        certificate: material.certificate.certificate.clone(),
        private_key: material.certificate.private_key.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn finish_association(
    engine: dimpl::Dtls,
    io: Box<dyn SctpMessageIo>,
    material: AdmittedMaterial,
    material_status: TlsMaterialStatusReceiver,
    mut session: PeerSession,
    generation: PeerSessionGeneration,
    pending: PeerProtectionPending,
    expected_peer: ExpectedPeerIdentity,
    role: DiameterConnectionRole,
    policy: DtlsSctpPolicy,
    established: (DtlsSctpVersion, Timestamp),
) -> Result<DiameterDtlsSctpConnection, DiameterTlsError> {
    let (version, peer_expires_at) = established;
    let transition = session
        .attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::DtlsSctp)
        .map_err(|_| DiameterTlsError::PeerBinding)?;
    let protection = transition
        .protection()
        .protected_ready()
        .then(|| session.protection_evidence())
        .flatten()
        .ok_or(DiameterTlsError::PeerBinding)?;
    if !material_epoch_retained(material.epoch, material_status.status()) {
        return Err(DiameterTlsError::Retired);
    }
    let established_at = Instant::now();
    let hard_deadline = association_hard_deadline(
        established_at,
        policy.maximum_connection_age(),
        material.local_expires_at,
        peer_expires_at,
    );
    let close = io.close_handle();
    let retired = Arc::new(AtomicBool::new(false));
    let retirement_task = spawn_retirement_task(
        material_status.clone(),
        material.epoch,
        hard_deadline,
        Arc::clone(&retired),
        Arc::clone(&close),
    );
    Ok(DiameterDtlsSctpConnection {
        engine,
        io,
        close,
        session,
        generation,
        evidence: DiameterDtlsSctpEvidence {
            role,
            version,
            material_epoch: material.epoch,
            local_certificate_expires_at: material.local_expires_at,
            peer_certificate_expires_at: peer_expires_at,
            protection,
        },
        expected_peer,
        frame_limits: policy.frame_limits(),
        material_status,
        hard_deadline,
        retired,
        _retirement_task: retirement_task,
        // The association is established; the steady-state pump must accept
        // engine plaintext immediately. The pre-handshake cleartext guard ran
        // with the handshake's own state.
        pump_state: PumpState {
            connected: true,
            ..PumpState::default()
        },
        poll_buffer: vec![0_u8; ENGINE_POLL_BUFFER],
        closed: false,
    })
}

struct AssociationOperationGuard<'a> {
    session: &'a mut PeerSession,
    generation: PeerSessionGeneration,
    closed: &'a mut bool,
    close: &'a dyn SctpTransportClose,
    armed: bool,
}

impl<'a> AssociationOperationGuard<'a> {
    const fn new(
        session: &'a mut PeerSession,
        generation: PeerSessionGeneration,
        closed: &'a mut bool,
        close: &'a dyn SctpTransportClose,
    ) -> Self {
        Self {
            session,
            generation,
            closed,
            close,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for AssociationOperationGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            poison_association(self.session, self.generation, self.closed, self.close);
        }
    }
}

fn poison_association(
    session: &mut PeerSession,
    generation: PeerSessionGeneration,
    closed: &mut bool,
    close: &dyn SctpTransportClose,
) {
    *closed = true;
    let _ = session.fail_on(generation, PeerSessionBlocker::SessionFailed);
    close.close();
}

/// An admitted mutually authenticated DTLS/SCTP association bound to one peer
/// session.
///
/// The association is exposed only after the DTLS handshake completed, the
/// peer certificate chain, validity, and exact SPIFFE identity matched
/// policy, and the exact `opc-proto-diameter` peer-protection attempt has
/// been attested. Application commands are admitted only after the direct
/// sequence's CER/CEA succeeds.
pub struct DiameterDtlsSctpConnection {
    engine: dimpl::Dtls,
    io: Box<dyn SctpMessageIo>,
    close: Arc<dyn SctpTransportClose>,
    session: PeerSession,
    generation: PeerSessionGeneration,
    evidence: DiameterDtlsSctpEvidence,
    expected_peer: ExpectedPeerIdentity,
    frame_limits: DiameterFrameLimits,
    material_status: TlsMaterialStatusReceiver,
    hard_deadline: Instant,
    retired: Arc<AtomicBool>,
    _retirement_task: RetirementTask,
    pump_state: PumpState,
    poll_buffer: Vec<u8>,
    closed: bool,
}

impl DiameterDtlsSctpConnection {
    /// Negotiated, authenticated, generation-bound association evidence.
    pub const fn evidence(&self) -> &DiameterDtlsSctpEvidence {
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

    /// Canonically build, bind, and emit the connector's direct-sequence CER.
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
    /// direct-sequence CER.
    pub async fn receive_capabilities_request(
        &mut self,
        deadline: Instant,
    ) -> Result<PeerCapabilities, DiameterTlsError> {
        self.ensure_role(DiameterConnectionRole::Acceptor)?;
        self.ensure_active()?;
        let generation = self.generation;
        let frame_limits = self.frame_limits;
        let expected_identity = self.expected_peer.diameter_identity().clone();
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
        operation.disarm();
        Ok(remote)
    }

    /// Prepare and emit the acceptor's sole canonical direct-sequence CEA.
    /// A non-success answer is flushed before this association is failed
    /// closed and reported as [`DiameterCapabilitiesExchangeOutcome::Rejected`].
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
        let Self {
            engine,
            io,
            session,
            generation,
            frame_limits,
            closed,
            close,
            pump_state,
            poll_buffer,
            ..
        } = self;
        let mut operation = AssociationOperationGuard::new(session, *generation, closed, &**close);
        if let Err(error) = write_wire_frame_via(
            engine,
            io,
            pump_state,
            poll_buffer,
            *frame_limits,
            emission.as_bytes(),
            deadline,
        )
        .await
        {
            let _ = operation;
            return Err(error);
        }
        if outcome.is_negotiated() {
            operation.disarm();
        }
        Ok(outcome)
    }

    /// Receive the connector's strict, correlated direct-sequence CEA. A
    /// non-success answer is returned as an explicit rejected outcome after
    /// this association has been failed closed.
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
        let (message, mut operation) = self.read_protected_message(deadline).await?;
        operation
            .session
            .admit_message(generation, PeerMessageDirection::Inbound, &message.header)
            .map_err(|_| DiameterTlsError::CommandNotAdmitted)?;
        let borrowed_message = borrowed(&message);
        let (answer, transition) = match parse_capabilities_exchange_answer(
            &borrowed_message,
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
                    &borrowed_message,
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
        if outcome.is_negotiated() {
            operation.disarm();
        }
        Ok((answer, outcome))
    }

    /// Admit and emit exactly one post-negotiation application message under
    /// an absolute deadline. Watchdog and disconnect procedures remain owned
    /// by the full-duplex runtime, which this slice does not yet integrate.
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
        operation.disarm();
        Ok((message, admission))
    }

    /// Send close_notify, close the association, and revoke this generation's
    /// readiness. The close-notify flush is bounded by `deadline`; a peer that
    /// never acknowledges still observes the closed transport.
    pub async fn close(mut self, deadline: Instant) -> Result<PeerSession, DiameterTlsError> {
        let already_closed = self.closed || self.retired.load(Ordering::Acquire);
        if !already_closed {
            let _ = self.engine.close();
            let Self {
                engine,
                io,
                pump_state,
                poll_buffer,
                ..
            } = &mut self;
            let flush = async {
                let _ = poll_engine(engine, None, pump_state, poll_buffer);
                flush_outbound(io, pump_state).await
            };
            let _ = tokio::time::timeout_at(deadline, flush).await;
        }
        poison_association(
            &mut self.session,
            self.generation,
            &mut self.closed,
            &*self.close,
        );
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
            poison_association(
                &mut self.session,
                self.generation,
                &mut self.closed,
                &*self.close,
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
        let Self {
            engine,
            io,
            session,
            generation,
            evidence,
            frame_limits,
            material_status,
            hard_deadline,
            retired,
            closed,
            close,
            pump_state,
            poll_buffer,
            ..
        } = self;
        let wire = encoded_bytes(message, *frame_limits)?;
        let mut operation = AssociationOperationGuard::new(session, *generation, closed, &**close);
        if let Err(error) = write_wire_frame_via(
            engine,
            io,
            pump_state,
            poll_buffer,
            *frame_limits,
            &wire,
            deadline,
        )
        .await
        {
            return Err(
                if retirement_required(
                    material_status,
                    evidence.material_epoch(),
                    *hard_deadline,
                    retired,
                ) {
                    retired.store(true, Ordering::Release);
                    DiameterTlsError::Retired
                } else {
                    error
                },
            );
        }
        operation.disarm();
        Ok(())
    }

    async fn read_protected_message(
        &mut self,
        deadline: Instant,
    ) -> Result<(OwnedMessage, AssociationOperationGuard<'_>), DiameterTlsError> {
        self.ensure_active()?;
        let Self {
            engine,
            io,
            session,
            generation,
            evidence,
            frame_limits,
            material_status,
            hard_deadline,
            retired,
            closed,
            close,
            pump_state,
            poll_buffer,
            ..
        } = self;
        let operation = AssociationOperationGuard::new(session, *generation, closed, &**close);
        let message =
            match read_wire_frame_via(engine, io, pump_state, poll_buffer, *frame_limits, deadline)
                .await
            {
                Ok(message) => message,
                Err(error) => {
                    return Err(
                        if retirement_required(
                            material_status,
                            evidence.material_epoch(),
                            *hard_deadline,
                            retired,
                        ) {
                            retired.store(true, Ordering::Release);
                            DiameterTlsError::Retired
                        } else {
                            error
                        },
                    );
                }
            };
        if retirement_required(
            material_status,
            evidence.material_epoch(),
            *hard_deadline,
            retired,
        ) {
            retired.store(true, Ordering::Release);
            return Err(DiameterTlsError::Retired);
        }
        Ok((message, operation))
    }
}

async fn write_wire_frame_via(
    engine: &mut dimpl::Dtls,
    io: &mut Box<dyn SctpMessageIo>,
    pump_state: &mut PumpState,
    poll_buffer: &mut Vec<u8>,
    frame_limits: DiameterFrameLimits,
    wire: &[u8],
    deadline: Instant,
) -> Result<(), DiameterTlsError> {
    validate_wire_frame(wire, frame_limits)?;
    if Instant::now() >= deadline {
        return Err(DiameterTlsError::DeadlineExceeded);
    }
    engine
        .send_application_data(wire)
        .map_err(|_| DiameterTlsError::Transport)?;
    let flush = async {
        let _ = poll_engine(engine, None, pump_state, poll_buffer)?;
        flush_outbound(io, pump_state).await
    };
    tokio::time::timeout_at(deadline, flush)
        .await
        .map_err(|_| DiameterTlsError::DeadlineExceeded)??;
    Ok(())
}

async fn read_wire_frame_via(
    engine: &mut dimpl::Dtls,
    io: &mut Box<dyn SctpMessageIo>,
    pump_state: &mut PumpState,
    poll_buffer: &mut Vec<u8>,
    frame_limits: DiameterFrameLimits,
    deadline: Instant,
) -> Result<OwnedMessage, DiameterTlsError> {
    pump_until_inbound(engine, io, pump_state, poll_buffer, deadline).await?;
    let wire = pump_state
        .inbound
        .pop_front()
        .ok_or(DiameterTlsError::Transport)?;
    decode_wire_frame(wire, frame_limits)
}

impl fmt::Debug for DiameterDtlsSctpConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterDtlsSctpConnection")
            .field("generation", &self.generation)
            .field("evidence", &self.evidence)
            .field("frame_limits", &self.frame_limits)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rejects_empty_cipher_set() {
        let policy = DtlsSctpPolicy::default();
        assert_eq!(
            policy.with_allowed_ciphers(&[]),
            Err(DiameterTlsPolicyError::EmptyCipherSet)
        );
    }

    #[test]
    fn policy_admits_only_configured_ciphers() {
        let policy = DtlsSctpPolicy::default()
            .with_allowed_ciphers(&[DtlsSctpCipher::Aes256GcmSha384])
            .expect("cipher policy");
        assert!(policy.allows_cipher(DtlsSctpCipher::Aes256GcmSha384));
        assert!(!policy.allows_cipher(DtlsSctpCipher::Aes128GcmSha256));
    }

    #[test]
    fn policy_defaults_to_dtls13_only() {
        let policy = DtlsSctpPolicy::default();
        assert!(!policy.allow_dtls12);
        assert!(policy.with_dtls12_compatibility().allow_dtls12);
    }

    #[test]
    fn policy_rejects_zero_connection_age() {
        assert_eq!(
            DtlsSctpPolicy::default().with_maximum_connection_age(Duration::ZERO),
            Err(DiameterTlsPolicyError::InvalidConnectionAge)
        );
    }

    #[tokio::test]
    async fn in_memory_link_enforces_close_and_records_ppid() {
        let (mut a, mut b, log) = in_memory_sctp_link(4);
        a.send_dtls_record(b"dtls-bytes").await.expect("send");
        let received = b.receive_message().await.expect("receive").expect("open");
        assert_eq!(received.ppid(), DIAMETER_DTLS_SCTP_PPID);
        assert_eq!(received.payload(), b"dtls-bytes");
        assert_eq!(
            log.records(),
            vec![SctpWireRecord {
                a_to_b: true,
                ppid: DIAMETER_DTLS_SCTP_PPID,
                payload_bytes: 10,
                record_header: None,
            }]
        );
        a.close_handle().close();
        assert_eq!(b.receive_message().await.expect("closed"), None);
        assert_eq!(
            a.send_dtls_record(b"late").await,
            Err(DiameterTlsError::Transport)
        );
    }

    #[tokio::test]
    async fn in_memory_link_injects_raw_cleartext() {
        let (mut a, mut b, log) = in_memory_sctp_link(4);
        a.send_raw_message(0, Bytes::from_static(b"clear"))
            .await
            .expect("inject");
        let received = b.receive_message().await.expect("receive").expect("open");
        assert_eq!(received.ppid(), 0);
        assert_eq!(log.records()[0].ppid, 0);
    }
}
