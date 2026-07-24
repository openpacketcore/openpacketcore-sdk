//! Mutually authenticated Diameter-over-DTLS/SCTP transport.
//!
//! This module implements both RFC 6733 protection sequences for SCTP. Direct
//! mode completes mutually authenticated DTLS before any Diameter byte.
//! In-band mode permits exactly one canonical cleartext CER/CEA exchange,
//! seals that prelude, and completes DTLS on the same association before any
//! application command. Consuming typestates and exact `PeerSession` generation
//! evidence prevent a caller from skipping or replaying either transition.
//!
//! The RFC 6083 profile is DTLS 1.2 only. It uses the audited, workspace-vendored
//! `dimpl` fork with its explicitly selected pure-Rust `rust-crypto` provider
//! and admits only typed ECDHE-ECDSA AEAD suites. An unrelated process-global
//! `dimpl` provider cannot replace that authority. The profile disables DTLS
//! record replay filtering and flight retransmission because reliable, ordered
//! SCTP owns those properties. Every DTLS record is carried as one ordered SCTP
//! user message on stream 0 with [`DIAMETER_DTLS_SCTP_PPID`] (47); cleartext or
//! foreign-PPID input after the in-band prelude fails the association closed.
//! The maximum Diameter plaintext is 16,347 bytes, the conservative
//! single-record budget across all admitted suites.
//!
//! The engine surfaces the complete presented certificate chain. This module
//! bounds its count, per-certificate size, and aggregate size, verifies
//! leaf-to-root ordering, validates the chain and every certificate's time
//! window with rustls-webpki against anchors scoped to the expected SPIFFE
//! trust domain, and requires the exact configured SPIFFE identity. Servers
//! require a non-empty client certificate, while clients require proof that
//! the server requested and authenticated that certificate; one-way
//! authentication can never produce mutual-authentication evidence. Local
//! material is one coherent, concurrency-bounded `opc-tls` epoch snapshot.
//! Temporary and engine-owned private-key DER buffers are zeroized on drop.
//!
//! [`KernelSctpMessageIo`] binds the record seam to a real one-to-one
//! `opc-sctp` association. It requires DATA-chunk SCTP-AUTH configuration,
//! keeps notification draining independent of its bounded DATA queue, derives
//! exactly 64 bytes with the RFC 5705 label `EXPORTER_DTLS_OVER_SCTP` and no
//! context, and installs/activates the RFC 6083 SCTP-AUTH key before the
//! protected Finished boundary. The protocol-defined initial empty key is only
//! a transition baseline; protected readiness is not reported until mutual
//! DTLS authentication and the exporter-key transition both complete.
//!
//! Negotiated evidence includes the exact DTLS version, cipher suite, local
//! material epoch, full-chain expiry bounds, and Diameter protection
//! generation. A negotiated connection can remain sequential or be consumed
//! into the same bounded full-duplex watchdog/disconnect runtime used by
//! TLS/TCP. External IPsec configuration and attestation remain product-owned;
//! an explicitly unprotected peer policy never satisfies protected readiness.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use opc_identity::{TrustBundleSet, TrustDomain};
use opc_proto_diameter::peer::{
    build_capabilities_exchange_request, parse_capabilities_exchange_answer,
    parse_capabilities_exchange_error_answer, parse_capabilities_exchange_request,
    CapabilitiesExchangeAnswer, PeerCapabilities, PeerCommandAdmission, PeerCommandClass,
    PeerMessageDirection, PeerProtectionEvidence, PeerProtectionFailure, PeerProtectionMechanism,
    PeerProtectionPending, PeerProtectionReadiness, PeerProtectionRequirement,
    PeerProtectionSequence, PeerSession, PeerSessionBlocker, PeerSessionGeneration,
    PeerSessionPolicy, PeerSessionReadiness, PeerSessionSnapshot,
};
use opc_proto_diameter::OwnedMessage;
use opc_protocol::{DecodeContext, EncodeContext, ValidationLevel};
use opc_sctp::{
    DeliveryOrder, OutboundMessage, PayloadProtocolIdentifier, SctpAssociation,
    SctpAssociationAbortHandle, SctpAssociationSendHalf, SctpAuthKey, SctpAuthKeyId,
    DIAMETER_SCTP_PPID,
};
use opc_tls::{
    TlsAdmittedConnection, TlsExternalHandshakeMaterial, TlsMaterialAvailability,
    TlsMaterialController, TlsMaterialEpoch, TlsMaterialReloadReason, TlsMaterialStatusReceiver,
};
use opc_types::Timestamp;
use rustls_pki_types::CertificateDer;
#[cfg(test)]
use tokio::sync::Notify;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::frame::{borrowed, decode_wire_frame, encoded_bytes, validate_wire_frame};
use crate::frame_transport::{
    FrameTransportFuture, ProtectedFrameReceiver, ProtectedFrameSender,
    ProtectedFrameTransportClose, ProtectedFrameTransportParts,
};
use crate::runtime::DiameterProtectedRuntimeParts;
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

/// Maximum encoded DTLS record carried by one SCTP user message.
///
/// RFC 6083 section 4.1 requires receive capacity for the generic DTLS
/// plaintext limit, maximum cipher expansion, and classic record header:
/// `2^14 + 2048 + 13` bytes. This receive bound is deliberately independent
/// of the smaller outbound plaintext budget imposed by section 3.2.
pub const MAX_DTLS_SCTP_RECORD_BYTES: usize = 16_384 + 2_048 + 13;
/// Maximum complete SCTP user messages buffered by the kernel adapter.
pub const MAX_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES: usize = 4_096;
/// Minimum complete SCTP user messages buffered by the kernel adapter.
///
/// The audited RFC 6083 engine profile admits certificate flights requiring
/// more than one record and normalizes its own receive queue to 32 records.
/// Matching that bound prevents a valid burst from filling the adapter queue
/// before the handshake task can be scheduled.
pub const MIN_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES: usize = 32;

/// Maximum peer certificates accepted from one DTLS Certificate message.
pub const MAX_DTLS_PEER_CERTIFICATES: usize = 8;
/// Maximum DER bytes accepted for one peer certificate.
pub const MAX_DTLS_PEER_CERTIFICATE_BYTES: usize = 64 * 1024;
/// Maximum aggregate DER bytes accepted for one peer certificate chain.
pub const MAX_DTLS_PEER_CERTIFICATE_CHAIN_BYTES: usize = 256 * 1024;

/// Classic DTLS record header length (content type, version, epoch, sequence
/// number, length) used to split engine datagrams into single records.
const DTLS_RECORD_HEADER_BYTES: usize = 13;

/// SCTP DATA delivery order reported for a received user message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpDeliveryOrder {
    /// SCTP ordered delivery.
    Ordered,
    /// SCTP unordered delivery.
    Unordered,
}

/// One received SCTP user message surfaced through the message seam.
#[derive(Clone, PartialEq, Eq)]
pub struct SctpUserMessage {
    payload: Bytes,
    ppid: u32,
    stream_id: u16,
    order: SctpDeliveryOrder,
    truncated: bool,
    control_truncated: bool,
    notification: bool,
}

impl SctpUserMessage {
    /// Build one received user message from complete SCTP receive metadata.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        payload: Bytes,
        ppid: u32,
        stream_id: u16,
        order: SctpDeliveryOrder,
        truncated: bool,
        control_truncated: bool,
        notification: bool,
    ) -> Self {
        Self {
            payload,
            ppid,
            stream_id,
            order,
            truncated,
            control_truncated,
            notification,
        }
    }

    #[cfg(test)]
    fn ordered_record(payload: Bytes, ppid: u32) -> Self {
        Self::new(
            payload,
            ppid,
            DIAMETER_DTLS_SCTP_STREAM,
            SctpDeliveryOrder::Ordered,
            false,
            false,
            false,
        )
    }

    /// Borrow the user payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Payload protocol identifier carried by the SCTP DATA chunk.
    pub const fn ppid(&self) -> u32 {
        self.ppid
    }

    /// SCTP stream identifier reported by the receive boundary.
    pub const fn stream_id(&self) -> u16 {
        self.stream_id
    }

    /// SCTP ordered/unordered delivery flag.
    pub const fn order(&self) -> SctpDeliveryOrder {
        self.order
    }

    /// Whether the user payload was truncated by the receive boundary.
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Whether SCTP control metadata was truncated by the receive boundary.
    pub const fn control_truncated(&self) -> bool {
        self.control_truncated
    }

    /// Whether this item is an SCTP notification rather than DATA.
    pub const fn notification(&self) -> bool {
        self.notification
    }
}

impl fmt::Debug for SctpUserMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SctpUserMessage")
            .field("ppid", &self.ppid)
            .field("stream_id", &self.stream_id)
            .field("order", &self.order)
            .field("truncated", &self.truncated)
            .field("control_truncated", &self.control_truncated)
            .field("notification", &self.notification)
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// Synchronous full-close authority for one SCTP message transport.
///
/// `close` must be idempotent, must interrupt in-flight receive operations,
/// and must return promptly without waiting for asynchronous cleanup.
pub(crate) trait SctpTransportClose: Send + Sync {
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
/// discipline. The RFC 6083 engine profile disables its datagram replay
/// window and relies on SCTP's reliable, ordered transport; this seam requires
/// ordered stream-0 delivery for every record. The receive side surfaces every
/// user message with its PPID so the association can fail closed on any
/// cleartext input.
mod sctp_io_sealed {
    pub trait Sealed {}
}

pub(crate) trait SctpMessageIo: sctp_io_sealed::Sealed + Send {
    /// Irreversibly bind a pristine association to the direct-DTLS sequence.
    ///
    /// Implementations must reject this transition after any cleartext DATA or
    /// SCTP-AUTH epoch transition has occurred.
    fn begin_direct_dtls(&mut self) -> Result<(), DiameterTlsError>;

    /// Bind a pristine association to the one-CER/one-CEA in-band prelude.
    ///
    /// The prelude remains cleartext and uses RFC 6083's protocol-defined
    /// initial empty SCTP-AUTH key. That key is not peer-derived cryptographic
    /// authentication; the prelude cannot carry application traffic or
    /// satisfy protected readiness.
    fn begin_inband_cleartext(&mut self) -> Result<(), DiameterTlsError>;

    /// Emit one complete cleartext Diameter CER or CEA on ordered stream 0
    /// with PPID 46 while the in-band prelude is active.
    fn send_inband_cleartext<'a>(&'a mut self, frame: &'a [u8]) -> FrameTransportFuture<'a, ()>;

    /// Receive the one peer cleartext Diameter CER or CEA while the in-band
    /// prelude is active.
    fn receive_inband_cleartext(&mut self) -> FrameTransportFuture<'_, Option<SctpUserMessage>>;

    /// Consume the completed cleartext prelude and permanently fence the
    /// association into DTLS-only operation.
    ///
    /// Implementations must require exactly one local and one peer cleartext
    /// frame, no SCTP-AUTH epoch transition, and exclusive ownership of the
    /// same association.
    fn seal_inband_cleartext(&mut self) -> Result<(), DiameterTlsError>;

    /// Emit one complete DTLS record as one ordered PPID-47 stream-0 message.
    fn send_dtls_record<'a>(&'a mut self, record: &'a [u8]) -> FrameTransportFuture<'a, ()>;

    /// Receive the next SCTP user message, or `None` once the transport is
    /// cleanly closed and drained.
    fn receive_message(&mut self) -> FrameTransportFuture<'_, Option<SctpUserMessage>>;

    /// Install the next RFC 6083 exporter secret as an inactive SCTP-AUTH key.
    fn install_epoch_key<'a>(
        &'a mut self,
        material: &'a [u8],
        deadline: Instant,
    ) -> FrameTransportFuture<'a, ()>;

    /// Prove all preceding SCTP messages sender-dry before emitting
    /// ChangeCipherSpec under the current SCTP-AUTH key.
    fn prepare_change_cipher_spec(&mut self, deadline: Instant) -> FrameTransportFuture<'_, ()>;

    /// Prove ChangeCipherSpec sender-dry and activate the installed key before
    /// emitting Finished.
    fn prepare_epoch(&mut self, deadline: Instant) -> FrameTransportFuture<'_, ()>;

    /// Retire the preceding SCTP-AUTH key after the peer's corresponding
    /// Finished message has been authenticated.
    fn confirm_peer_finished(&mut self, deadline: Instant) -> FrameTransportFuture<'_, ()>;

    /// Prove all outstanding user messages sender-dry before DTLS emits
    /// close_notify.
    fn prepare_close_notify(&mut self, deadline: Instant) -> FrameTransportFuture<'_, ()>;

    /// Synchronous close authority shared with lifetime guards.
    fn close_handle(&self) -> Arc<dyn SctpTransportClose>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SctpIoPhase {
    Fresh,
    InbandCleartext { sent: bool, received: bool },
    Dtls,
}

impl SctpIoPhase {
    fn begin_direct(&mut self) -> Result<(), DiameterTlsError> {
        if *self != Self::Fresh {
            return Err(DiameterTlsError::ProtectionPolicyMismatch);
        }
        *self = Self::Dtls;
        Ok(())
    }

    fn begin_inband(&mut self) -> Result<(), DiameterTlsError> {
        if *self != Self::Fresh {
            return Err(DiameterTlsError::ProtectionPolicyMismatch);
        }
        *self = Self::InbandCleartext {
            sent: false,
            received: false,
        };
        Ok(())
    }

    fn mark_cleartext_sent(&mut self) -> Result<(), DiameterTlsError> {
        match self {
            Self::InbandCleartext { sent, .. } if !*sent => {
                *sent = true;
                Ok(())
            }
            _ => Err(DiameterTlsError::ProtectionPolicyMismatch),
        }
    }

    fn mark_cleartext_received(&mut self) -> Result<(), DiameterTlsError> {
        match self {
            Self::InbandCleartext { received, .. } if !*received => {
                *received = true;
                Ok(())
            }
            _ => Err(DiameterTlsError::ProtectionPolicyMismatch),
        }
    }

    fn seal_inband(&mut self) -> Result<(), DiameterTlsError> {
        if *self
            != (Self::InbandCleartext {
                sent: true,
                received: true,
            })
        {
            return Err(DiameterTlsError::ProtectionPolicyMismatch);
        }
        *self = Self::Dtls;
        Ok(())
    }

    fn ensure_dtls(self) -> Result<(), DiameterTlsError> {
        if self == Self::Dtls {
            Ok(())
        } else {
            Err(DiameterTlsError::ProtectionPolicyMismatch)
        }
    }
}

/// One recorded wire emission for deterministic wire-evidence assertions.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SctpWireRecord {
    /// True when endpoint A emitted the record towards endpoint B.
    pub a_to_b: bool,
    /// Payload protocol identifier of the emitted SCTP user message.
    pub ppid: u32,
    /// Emitted payload length in bytes.
    pub payload_bytes: usize,
    /// SCTP-AUTH key identifier active when the message was submitted.
    ///
    /// Identifier 0 is RFC 6083's initial empty key.
    pub auth_key_id: u16,
    /// The first bytes of the emission, enough to parse either DTLS record
    /// header format via [`parse_dtls_record_bounds`]; `None` for cleartext
    /// or truncated payloads so wire assertions can reject them.
    pub record_header: Option<[u8; DTLS_RECORD_HEADER_BYTES]>,
}

/// Shared, bounded wire log for one in-memory link.
#[cfg(test)]
#[derive(Clone)]
pub struct SctpWireLog {
    records: Arc<Mutex<Vec<SctpWireRecord>>>,
    shared: Arc<InMemoryShared>,
}

#[cfg(test)]
impl SctpWireLog {
    /// Snapshot the recorded wire emissions in order.
    pub fn records(&self) -> Vec<SctpWireRecord> {
        match self.records.lock() {
            Ok(records) => records.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Suspend or resume DTLS record sends in one direction. This deterministic
    /// fault seam lets deadline and cancellation tests hold a transport write
    /// after the engine has produced its record.
    pub fn set_dtls_send_blocked(&self, a_to_b: bool, blocked: bool) {
        let direction = if a_to_b {
            &self.shared.block_a_to_b_dtls
        } else {
            &self.shared.block_b_to_a_dtls
        };
        direction.store(blocked, Ordering::Release);
        if !blocked {
            self.shared.notify.notify_waiters();
        }
    }
}

#[cfg(test)]
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

#[cfg(test)]
struct InMemoryShared {
    closed: AtomicBool,
    block_a_to_b_dtls: AtomicBool,
    block_b_to_a_dtls: AtomicBool,
    notify: Notify,
    log: Arc<Mutex<Vec<SctpWireRecord>>>,
}

#[cfg(test)]
struct InMemoryClose {
    shared: Arc<InMemoryShared>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreviousAuthKey {
    Initial,
    Numbered(SctpAuthKeyId),
}

#[cfg(test)]
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
#[cfg(test)]
pub struct InMemorySctpEndpoint {
    tx: mpsc::Sender<SctpUserMessage>,
    rx: mpsc::Receiver<SctpUserMessage>,
    a_side: bool,
    shared: Arc<InMemoryShared>,
    active_auth_key: Option<SctpAuthKeyId>,
    pending_auth_key: Option<SctpAuthKeyId>,
    previous_auth_key: Option<PreviousAuthKey>,
    phase: SctpIoPhase,
}

#[cfg(test)]
impl InMemorySctpEndpoint {
    /// Emit one raw user message with an arbitrary PPID. This bypasses the
    /// protected-record contract of [`SctpMessageIo::send_dtls_record`] and
    /// exists so tests can inject cleartext or foreign-PPID input.
    pub async fn send_raw_message(
        &mut self,
        ppid: u32,
        payload: Bytes,
    ) -> Result<(), DiameterTlsError> {
        self.emit(SctpUserMessage::ordered_record(payload, ppid))
            .await
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
        emit_logged(
            &self.tx,
            &self.shared,
            self.a_side,
            self.active_auth_key.map_or(0, SctpAuthKeyId::get),
            message,
        )
        .await
    }

    async fn wait_for_dtls_send(&self) -> Result<(), DiameterTlsError> {
        loop {
            let notified = self.shared.notify.notified();
            if self.shared.closed.load(Ordering::Acquire) {
                return Err(DiameterTlsError::Transport);
            }
            let blocked = if self.a_side {
                self.shared.block_a_to_b_dtls.load(Ordering::Acquire)
            } else {
                self.shared.block_b_to_a_dtls.load(Ordering::Acquire)
            };
            if !blocked {
                return Ok(());
            }
            notified.await;
        }
    }
}

/// Retained raw-injection handle for one in-memory endpoint; see
/// [`InMemorySctpEndpoint::injector`].
#[cfg(test)]
pub struct InMemorySctpInjector {
    tx: mpsc::Sender<SctpUserMessage>,
    a_side: bool,
    shared: Arc<InMemoryShared>,
}

#[cfg(test)]
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
            0,
            SctpUserMessage::ordered_record(payload, ppid),
        )
        .await
    }
}

#[cfg(test)]
async fn emit_logged(
    tx: &mpsc::Sender<SctpUserMessage>,
    shared: &InMemoryShared,
    a_side: bool,
    auth_key_id: u16,
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
            auth_key_id,
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

#[cfg(test)]
impl sctp_io_sealed::Sealed for InMemorySctpEndpoint {}

#[cfg(test)]
impl SctpMessageIo for InMemorySctpEndpoint {
    fn begin_direct_dtls(&mut self) -> Result<(), DiameterTlsError> {
        if self.active_auth_key.is_some()
            || self.pending_auth_key.is_some()
            || self.previous_auth_key.is_some()
        {
            return Err(DiameterTlsError::ProtectionPolicyMismatch);
        }
        self.phase.begin_direct()
    }

    fn begin_inband_cleartext(&mut self) -> Result<(), DiameterTlsError> {
        if self.active_auth_key.is_some()
            || self.pending_auth_key.is_some()
            || self.previous_auth_key.is_some()
        {
            return Err(DiameterTlsError::ProtectionPolicyMismatch);
        }
        self.phase.begin_inband()
    }

    fn send_inband_cleartext<'a>(&'a mut self, frame: &'a [u8]) -> FrameTransportFuture<'a, ()> {
        Box::pin(async move {
            if !matches!(self.phase, SctpIoPhase::InbandCleartext { sent: false, .. }) {
                return Err(DiameterTlsError::ProtectionPolicyMismatch);
            }
            self.emit(SctpUserMessage::ordered_record(
                Bytes::copy_from_slice(frame),
                DIAMETER_SCTP_PPID.get(),
            ))
            .await?;
            self.phase.mark_cleartext_sent()
        })
    }

    fn receive_inband_cleartext(&mut self) -> FrameTransportFuture<'_, Option<SctpUserMessage>> {
        Box::pin(async move {
            if !matches!(
                self.phase,
                SctpIoPhase::InbandCleartext {
                    received: false,
                    ..
                }
            ) {
                return Err(DiameterTlsError::ProtectionPolicyMismatch);
            }
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
                    message = self.rx.recv() => {
                        if message.is_some() {
                            self.phase.mark_cleartext_received()?;
                        }
                        return Ok(message);
                    },
                }
            }
        })
    }

    fn seal_inband_cleartext(&mut self) -> Result<(), DiameterTlsError> {
        if self.active_auth_key.is_some()
            || self.pending_auth_key.is_some()
            || self.previous_auth_key.is_some()
        {
            return Err(DiameterTlsError::ProtectionPolicyMismatch);
        }
        self.phase.seal_inband()
    }

    fn send_dtls_record<'a>(&'a mut self, record: &'a [u8]) -> FrameTransportFuture<'a, ()> {
        Box::pin(async move {
            self.phase.ensure_dtls()?;
            validate_outbound_dtls_record(record)?;
            self.wait_for_dtls_send().await?;
            self.emit(SctpUserMessage::ordered_record(
                Bytes::copy_from_slice(record),
                DIAMETER_DTLS_SCTP_PPID,
            ))
            .await
        })
    }

    fn receive_message(&mut self) -> FrameTransportFuture<'_, Option<SctpUserMessage>> {
        Box::pin(async move {
            self.phase.ensure_dtls()?;
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

    fn install_epoch_key<'a>(
        &'a mut self,
        material: &'a [u8],
        deadline: Instant,
    ) -> FrameTransportFuture<'a, ()> {
        Box::pin(async move {
            if Instant::now() >= deadline
                || material.len() != 64
                || self.pending_auth_key.is_some()
                || self.previous_auth_key.is_some()
            {
                return Err(DiameterTlsError::Transport);
            }
            let next = match self.active_auth_key {
                Some(current) => current.next_rfc6083(),
                None => SctpAuthKeyId::new(1).ok_or(DiameterTlsError::Transport)?,
            };
            self.pending_auth_key = Some(next);
            Ok(())
        })
    }

    fn prepare_change_cipher_spec(&mut self, deadline: Instant) -> FrameTransportFuture<'_, ()> {
        Box::pin(async move {
            if Instant::now() >= deadline
                || self.pending_auth_key.is_none()
                || self.previous_auth_key.is_some()
            {
                return Err(DiameterTlsError::Transport);
            }
            Ok(())
        })
    }

    fn prepare_epoch(&mut self, deadline: Instant) -> FrameTransportFuture<'_, ()> {
        Box::pin(async move {
            if Instant::now() >= deadline || self.previous_auth_key.is_some() {
                return Err(DiameterTlsError::Transport);
            }
            let next = self
                .pending_auth_key
                .take()
                .ok_or(DiameterTlsError::Transport)?;
            self.previous_auth_key = Some(match self.active_auth_key {
                Some(current) => PreviousAuthKey::Numbered(current),
                None => PreviousAuthKey::Initial,
            });
            self.active_auth_key = Some(next);
            Ok(())
        })
    }

    fn confirm_peer_finished(&mut self, deadline: Instant) -> FrameTransportFuture<'_, ()> {
        Box::pin(async move {
            if Instant::now() >= deadline || self.previous_auth_key.take().is_none() {
                return Err(DiameterTlsError::Transport);
            }
            Ok(())
        })
    }

    fn prepare_close_notify(&mut self, deadline: Instant) -> FrameTransportFuture<'_, ()> {
        Box::pin(async move {
            if Instant::now() >= deadline {
                return Err(DiameterTlsError::DeadlineExceeded);
            }
            Ok(())
        })
    }

    fn close_handle(&self) -> Arc<dyn SctpTransportClose> {
        Arc::new(InMemoryClose {
            shared: Arc::clone(&self.shared),
        })
    }
}

/// Create one in-memory endpoint pair plus its shared wire log.
#[cfg(test)]
pub fn in_memory_sctp_link(
    capacity: usize,
) -> (InMemorySctpEndpoint, InMemorySctpEndpoint, SctpWireLog) {
    let (a_tx, b_rx) = mpsc::channel(capacity.max(1));
    let (b_tx, a_rx) = mpsc::channel(capacity.max(1));
    let shared = Arc::new(InMemoryShared {
        closed: AtomicBool::new(false),
        block_a_to_b_dtls: AtomicBool::new(false),
        block_b_to_a_dtls: AtomicBool::new(false),
        notify: Notify::new(),
        log: Arc::new(Mutex::new(Vec::new())),
    });
    let log = SctpWireLog {
        records: Arc::clone(&shared.log),
        shared: Arc::clone(&shared),
    };
    (
        InMemorySctpEndpoint {
            tx: a_tx,
            rx: a_rx,
            a_side: true,
            shared: Arc::clone(&shared),
            active_auth_key: None,
            pending_auth_key: None,
            previous_auth_key: None,
            phase: SctpIoPhase::Fresh,
        },
        InMemorySctpEndpoint {
            tx: b_tx,
            rx: b_rx,
            a_side: false,
            shared,
            active_auth_key: None,
            pending_auth_key: None,
            previous_auth_key: None,
            phase: SctpIoPhase::Fresh,
        },
        log,
    )
}

struct KernelSctpClose {
    abort: SctpAssociationAbortHandle,
}

impl SctpTransportClose for KernelSctpClose {
    fn close(&self) {
        self.abort.abort();
    }
}

/// RFC 6083 message adapter over a real `opc-sctp` one-to-one association.
///
/// The association must have been created with
/// `SctpAuthenticationConfig::data()` and a receive budget of at least
/// [`MAX_DTLS_SCTP_RECORD_BYTES`]. A dedicated receive task continuously
/// drains SCTP notifications so sender-dry and SCTP-AUTH lifecycle operations
/// cannot deadlock behind user DATA.
pub struct KernelSctpMessageIo {
    send: SctpAssociationSendHalf,
    inbound: mpsc::Receiver<Result<SctpUserMessage, DiameterTlsError>>,
    abort: SctpAssociationAbortHandle,
    receive_task: tokio::task::JoinHandle<()>,
    active_auth_key: Option<SctpAuthKeyId>,
    pending_auth_key: Option<SctpAuthKeyId>,
    previous_auth_key: Option<PreviousAuthKey>,
    phase: SctpIoPhase,
}

impl KernelSctpMessageIo {
    /// Bind an authenticated SCTP association to the RFC 6083 record seam.
    ///
    /// `receive_queue_capacity` must be between
    /// [`MIN_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES`] and
    /// [`MAX_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES`], inclusive.
    pub fn new(
        association: SctpAssociation,
        receive_queue_capacity: usize,
    ) -> Result<Self, DiameterTlsError> {
        if let Err(error) = validate_kernel_receive_queue_capacity(receive_queue_capacity) {
            association.abort_handle().abort();
            return Err(error);
        }
        if !association.authenticates_data_chunks()
            || association.max_message_bytes() < MAX_DTLS_SCTP_RECORD_BYTES
            || !association.is_pristine_rfc6083_auth_state()
        {
            association.abort_handle().abort();
            return Err(DiameterTlsError::ProtectionPolicyMismatch);
        }
        let abort = association.abort_handle();
        let runtime = match tokio::runtime::Handle::try_current() {
            Ok(runtime) => runtime,
            Err(_) => {
                abort.abort();
                return Err(DiameterTlsError::Transport);
            }
        };
        let (send, mut receive) = association.into_split();
        let (inbound_tx, inbound) = mpsc::channel(receive_queue_capacity);
        let task_abort = abort.clone();
        let receive_task = runtime.spawn(async move {
            loop {
                let received = match receive.recv().await {
                    Ok(received) => received,
                    Err(_) => {
                        let _ = inbound_tx.try_send(Err(DiameterTlsError::Transport));
                        break;
                    }
                };
                if received.notification {
                    match received.event {
                        Some(opc_sctp::SctpEvent::Shutdown { .. })
                        | Some(opc_sctp::SctpEvent::Unknown { .. })
                        | None => {
                            let _ = inbound_tx.try_send(Err(DiameterTlsError::Transport));
                            break;
                        }
                        Some(opc_sctp::SctpEvent::AssociationChange {
                            state: 0, error: 0, ..
                        })
                        | Some(
                            opc_sctp::SctpEvent::PeerAddrChange { .. }
                            | opc_sctp::SctpEvent::SenderDry { .. }
                            | opc_sctp::SctpEvent::Authentication { .. },
                        ) => continue,
                        Some(opc_sctp::SctpEvent::AssociationChange { .. }) => {
                            let _ = inbound_tx.try_send(Err(DiameterTlsError::Transport));
                            break;
                        }
                    }
                }
                let order = match received.order {
                    DeliveryOrder::Ordered => SctpDeliveryOrder::Ordered,
                    DeliveryOrder::Unordered => SctpDeliveryOrder::Unordered,
                };
                let message = SctpUserMessage::new(
                    received.payload,
                    received.ppid.get(),
                    received.stream_id,
                    order,
                    received.truncated,
                    received.control_truncated,
                    false,
                );
                // Never await a full DATA queue: doing so would stop the only
                // kernel receiver from dispatching sender-dry and SCTP-AUTH
                // notifications. Capacity exhaustion is terminal and bounded.
                if inbound_tx.try_send(Ok(message)).is_err() {
                    break;
                }
            }
            task_abort.abort();
        });
        Ok(Self {
            send,
            inbound,
            abort,
            receive_task,
            active_auth_key: None,
            pending_auth_key: None,
            previous_auth_key: None,
            phase: SctpIoPhase::Fresh,
        })
    }

    fn remaining(deadline: Instant) -> Result<Duration, DiameterTlsError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(DiameterTlsError::DeadlineExceeded);
        }
        Ok(deadline.saturating_duration_since(now))
    }
}

fn validate_kernel_receive_queue_capacity(capacity: usize) -> Result<(), DiameterTlsError> {
    if !(MIN_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES..=MAX_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES)
        .contains(&capacity)
    {
        Err(DiameterTlsError::SctpReceiveQueueCapacityInvalid)
    } else {
        Ok(())
    }
}

impl sctp_io_sealed::Sealed for KernelSctpMessageIo {}

impl SctpMessageIo for KernelSctpMessageIo {
    fn begin_direct_dtls(&mut self) -> Result<(), DiameterTlsError> {
        if self.active_auth_key.is_some()
            || self.pending_auth_key.is_some()
            || self.previous_auth_key.is_some()
        {
            self.abort.abort();
            return Err(DiameterTlsError::ProtectionPolicyMismatch);
        }
        self.phase.begin_direct()
    }

    fn begin_inband_cleartext(&mut self) -> Result<(), DiameterTlsError> {
        if self.active_auth_key.is_some()
            || self.pending_auth_key.is_some()
            || self.previous_auth_key.is_some()
        {
            self.abort.abort();
            return Err(DiameterTlsError::ProtectionPolicyMismatch);
        }
        self.phase.begin_inband()
    }

    fn send_inband_cleartext<'a>(&'a mut self, frame: &'a [u8]) -> FrameTransportFuture<'a, ()> {
        Box::pin(async move {
            if !matches!(self.phase, SctpIoPhase::InbandCleartext { sent: false, .. }) {
                return Err(DiameterTlsError::ProtectionPolicyMismatch);
            }
            let sent = self
                .send
                .send(OutboundMessage::ordered(
                    Bytes::copy_from_slice(frame),
                    DIAMETER_DTLS_SCTP_STREAM,
                    DIAMETER_SCTP_PPID,
                ))
                .await
                .map_err(|_| DiameterTlsError::Transport)?;
            if sent != frame.len() {
                self.abort.abort();
                return Err(DiameterTlsError::Transport);
            }
            self.phase.mark_cleartext_sent()
        })
    }

    fn receive_inband_cleartext(&mut self) -> FrameTransportFuture<'_, Option<SctpUserMessage>> {
        Box::pin(async move {
            if !matches!(
                self.phase,
                SctpIoPhase::InbandCleartext {
                    received: false,
                    ..
                }
            ) {
                return Err(DiameterTlsError::ProtectionPolicyMismatch);
            }
            match self.inbound.recv().await {
                Some(Ok(message)) => {
                    self.phase.mark_cleartext_received()?;
                    Ok(Some(message))
                }
                Some(Err(error)) => Err(error),
                None => Ok(None),
            }
        })
    }

    fn seal_inband_cleartext(&mut self) -> Result<(), DiameterTlsError> {
        if self.active_auth_key.is_some()
            || self.pending_auth_key.is_some()
            || self.previous_auth_key.is_some()
        {
            self.abort.abort();
            return Err(DiameterTlsError::ProtectionPolicyMismatch);
        }
        self.phase.seal_inband()
    }

    fn send_dtls_record<'a>(&'a mut self, record: &'a [u8]) -> FrameTransportFuture<'a, ()> {
        Box::pin(async move {
            self.phase.ensure_dtls()?;
            validate_outbound_dtls_record(record)?;
            let sent = self
                .send
                .send(OutboundMessage::ordered(
                    Bytes::copy_from_slice(record),
                    DIAMETER_DTLS_SCTP_STREAM,
                    PayloadProtocolIdentifier::new(DIAMETER_DTLS_SCTP_PPID),
                ))
                .await
                .map_err(|_| DiameterTlsError::Transport)?;
            if sent != record.len() {
                self.abort.abort();
                return Err(DiameterTlsError::Transport);
            }
            Ok(())
        })
    }

    fn receive_message(&mut self) -> FrameTransportFuture<'_, Option<SctpUserMessage>> {
        Box::pin(async move {
            self.phase.ensure_dtls()?;
            match self.inbound.recv().await {
                Some(Ok(message)) => Ok(Some(message)),
                Some(Err(error)) => Err(error),
                None => Ok(None),
            }
        })
    }

    fn install_epoch_key<'a>(
        &'a mut self,
        material: &'a [u8],
        deadline: Instant,
    ) -> FrameTransportFuture<'a, ()> {
        Box::pin(async move {
            if self.pending_auth_key.is_some() || self.previous_auth_key.is_some() {
                self.abort.abort();
                return Err(DiameterTlsError::Transport);
            }
            let next = match self.active_auth_key {
                Some(current) => current.next_rfc6083(),
                None => SctpAuthKeyId::new(1).ok_or(DiameterTlsError::Transport)?,
            };
            let key = SctpAuthKey::for_rfc6083(next, material.to_vec())
                .map_err(|_| DiameterTlsError::Transport)?;
            tokio::time::timeout_at(deadline, self.send.install_auth_key(key))
                .await
                .map_err(|_| DiameterTlsError::DeadlineExceeded)?
                .map_err(|_| DiameterTlsError::Transport)?;
            self.pending_auth_key = Some(next);
            Ok(())
        })
    }

    fn prepare_change_cipher_spec(&mut self, deadline: Instant) -> FrameTransportFuture<'_, ()> {
        Box::pin(async move {
            if self.pending_auth_key.is_none() || self.previous_auth_key.is_some() {
                self.abort.abort();
                return Err(DiameterTlsError::Transport);
            }
            let remaining = Self::remaining(deadline)?;
            self.send
                .wait_for_sender_dry_or_shutdown(remaining)
                .await
                .map_err(|_| DiameterTlsError::Transport)?;
            Ok(())
        })
    }

    fn prepare_epoch(&mut self, deadline: Instant) -> FrameTransportFuture<'_, ()> {
        Box::pin(async move {
            if self.previous_auth_key.is_some() {
                self.abort.abort();
                return Err(DiameterTlsError::Transport);
            }
            let next = self.pending_auth_key.ok_or_else(|| {
                self.abort.abort();
                DiameterTlsError::Transport
            })?;
            let remaining = Self::remaining(deadline)?;
            self.send
                .wait_for_sender_dry_or_shutdown(remaining)
                .await
                .map_err(|_| DiameterTlsError::Transport)?;
            tokio::time::timeout_at(deadline, self.send.activate_auth_key(next))
                .await
                .map_err(|_| DiameterTlsError::DeadlineExceeded)?
                .map_err(|_| DiameterTlsError::Transport)?;
            self.pending_auth_key = None;
            self.previous_auth_key = Some(match self.active_auth_key {
                Some(current) => PreviousAuthKey::Numbered(current),
                None => PreviousAuthKey::Initial,
            });
            self.active_auth_key = Some(next);
            Ok(())
        })
    }

    fn confirm_peer_finished(&mut self, deadline: Instant) -> FrameTransportFuture<'_, ()> {
        Box::pin(async move {
            let previous = self
                .previous_auth_key
                .take()
                .ok_or(DiameterTlsError::Transport)?;
            let remaining = Self::remaining(deadline)?;
            let result = match previous {
                PreviousAuthKey::Initial => self.send.retire_initial_auth_key(remaining).await,
                PreviousAuthKey::Numbered(key_id) => {
                    self.send.retire_auth_key(key_id, remaining).await
                }
            };
            if result.is_err() {
                self.abort.abort();
                return Err(DiameterTlsError::Transport);
            }
            Ok(())
        })
    }

    fn prepare_close_notify(&mut self, deadline: Instant) -> FrameTransportFuture<'_, ()> {
        Box::pin(async move {
            let remaining = Self::remaining(deadline)?;
            self.send
                .wait_for_sender_dry_or_shutdown(remaining)
                .await
                .map_err(|_| DiameterTlsError::Transport)?;
            Ok(())
        })
    }

    fn close_handle(&self) -> Arc<dyn SctpTransportClose> {
        Arc::new(KernelSctpClose {
            abort: self.abort.clone(),
        })
    }
}

impl Drop for KernelSctpMessageIo {
    fn drop(&mut self) {
        self.abort.abort();
        self.receive_task.abort();
    }
}

impl fmt::Debug for KernelSctpMessageIo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KernelSctpMessageIo")
            .field("active_auth_key", &self.active_auth_key)
            .field("pending_auth_key", &self.pending_auth_key)
            .field(
                "pending_key_confirmation",
                &self.previous_auth_key.is_some(),
            )
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

/// Opaque, consuming SCTP transport capability for a Diameter DTLS boundary.
///
/// Construct this capability from [`KernelSctpMessageIo`], or pass that
/// adapter directly to connector and acceptor methods. The underlying
/// record/prelude seam is intentionally not public: callers cannot emit PPID
/// 47 records, advance SCTP-AUTH epochs, or bypass the in-band CER/CEA
/// typestate outside the authenticated Diameter boundary.
pub struct DiameterDtlsSctpTransport {
    io: Box<dyn SctpMessageIo>,
}

impl DiameterDtlsSctpTransport {
    fn into_inner(self) -> Box<dyn SctpMessageIo> {
        self.io
    }
}

impl From<KernelSctpMessageIo> for DiameterDtlsSctpTransport {
    fn from(io: KernelSctpMessageIo) -> Self {
        Self { io: Box::new(io) }
    }
}

#[cfg(test)]
impl From<Box<dyn SctpMessageIo>> for DiameterDtlsSctpTransport {
    fn from(io: Box<dyn SctpMessageIo>) -> Self {
        Self { io }
    }
}

#[cfg(test)]
impl From<Box<InMemorySctpEndpoint>> for DiameterDtlsSctpTransport {
    fn from(io: Box<InMemorySctpEndpoint>) -> Self {
        Self { io }
    }
}

#[cfg(test)]
impl From<InMemorySctpEndpoint> for DiameterDtlsSctpTransport {
    fn from(io: InMemorySctpEndpoint) -> Self {
        Self { io: Box::new(io) }
    }
}

impl fmt::Debug for DiameterDtlsSctpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiameterDtlsSctpTransport([redacted])")
    }
}

/// DTLS protocol versions admitted by this transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DtlsSctpVersion {
    /// DTLS 1.2 (RFC 6347) with ECDHE-ECDSA AEAD suites.
    Dtls12,
}

/// Cipher-suite evidence names admitted by this transport.
///
/// RFC 6083 DTLS 1.2 negotiates these as ECDHE-ECDSA AEAD suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DtlsSctpCipher {
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (`0xC02B`).
    Aes128GcmSha256,
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (`0xC02C`).
    Aes256GcmSha384,
    /// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` (`0xCCA9`).
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

    fn from_dtls12_suite(suite: dimpl::crypto::Dtls12CipherSuite) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.dtls12_suite() == suite)
    }
}

/// Maximum Diameter message wire length the DTLS/SCTP path may carry.
///
/// Each Diameter message is carried as the plaintext of exactly one DTLS
/// record. RFC 6083 section 3.2 fixes the DTLS path MTU at 2^14 and requires
/// user data to subtract record and cipher overhead. The admitted AES-GCM
/// suites have the largest overhead: 13-byte classic record header, 8-byte
/// explicit nonce, and 16-byte authentication tag. Therefore 16,347 is the
/// conservative plaintext budget across every admitted suite. The engine
/// does not fragment application data across records, so a larger configured
/// frame limit is rejected during policy construction.
pub const MAX_DTLS_SCTP_MESSAGE_BYTES: usize = DiameterFrameLimits::RFC6083.max_message_len();

/// Typed DTLS/SCTP protocol, cipher, frame, and age policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtlsSctpPolicy {
    allowed_ciphers: [bool; 3],
    frame_limits: DiameterFrameLimits,
    maximum_connection_age: Duration,
}

impl DtlsSctpPolicy {
    /// RFC 6083 DTLS 1.2 policy with modern ECDHE-ECDSA AEAD suites.
    ///
    /// DTLS 1.3 is deliberately not exposed as ready: its exporter secret is
    /// not available until the server Finished, while RFC 6083 requires the
    /// new SCTP-AUTH key before Finished. The expired DTLS-over-SCTP-bis draft
    /// changes that contract and requires directional SCTP-AUTH APIs.
    pub fn rfc6083_dtls12(
        frame_limits: DiameterFrameLimits,
    ) -> Result<Self, DiameterTlsPolicyError> {
        if frame_limits.max_message_len() > MAX_DTLS_SCTP_MESSAGE_BYTES {
            return Err(DiameterTlsPolicyError::FrameLimitExceedsDtlsRecordBudget);
        }
        Ok(Self {
            allowed_ciphers: [true; 3],
            frame_limits,
            maximum_connection_age: Duration::from_secs(60 * 60),
        })
    }

    /// Reject a requested DTLS 1.3/SCTP profile during configuration.
    pub const fn dtls13(
        _frame_limits: DiameterFrameLimits,
    ) -> Result<Self, DiameterTlsPolicyError> {
        Err(DiameterTlsPolicyError::Dtls13OverSctpUnavailable)
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
        let dtls12: Vec<_> = self
            .allowed_ciphers()
            .map(DtlsSctpCipher::dtls12_suite)
            .collect();
        let config = dimpl::Config::builder()
            // Bind this transport to the audited RustCrypto implementation.
            // `dimpl` also supports a process-global default provider, but an
            // unrelated dependency must not be able to replace the provider
            // authority for an already configured Diameter boundary.
            .with_crypto_provider(dimpl::crypto::rust_crypto::default_provider())
            .require_client_certificate(true)
            // A connector must also prove that the remote server requested
            // and authenticated its local certificate. Verifying only the
            // server's certificate would be one-way authentication while
            // incorrectly publishing mutual-authentication evidence.
            .require_server_certificate_request(true)
            .rfc6083_sctp()
            .dtls13_cipher_suites(&[])
            .dtls12_cipher_suites(&dtls12)
            .build()
            .map_err(|_| DiameterTlsError::MaterialNotAdmitted)?;
        Ok(Arc::new(config))
    }
}

impl Default for DtlsSctpPolicy {
    fn default() -> Self {
        Self {
            allowed_ciphers: [true; 3],
            frame_limits: DiameterFrameLimits::RFC6083,
            maximum_connection_age: Duration::from_secs(60 * 60),
        }
    }
}

/// Redaction-safe negotiated evidence for an admitted DTLS/SCTP association.
///
/// Carries the local endpoint role, the exact negotiated DTLS protocol
/// version and cipher suite, the coherent local credential epoch admitted for
/// the handshake, local and peer full-chain expiry evidence, and the exact
/// Diameter generation-bound protection evidence. Peer identity, certificate
/// material, and exporter bytes are never exposed.
#[derive(Clone, PartialEq, Eq)]
pub struct DiameterDtlsSctpEvidence {
    role: DiameterConnectionRole,
    version: DtlsSctpVersion,
    cipher: DtlsSctpCipher,
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

    /// Exact negotiated DTLS 1.2 cipher suite.
    pub const fn cipher(&self) -> DtlsSctpCipher {
        self.cipher
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
            .field("cipher", &self.cipher)
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

/// Coherent local credential snapshot prepared for one external-provider
/// handshake.
struct PreparedMaterial {
    handshake: TlsExternalHandshakeMaterial,
    certificate: dimpl::DtlsCertificate,
    trust_bundles: TrustBundleSet,
}

fn validate_dtls_certificate_chain_bounds(
    chain: &[CertificateDer<'_>],
) -> Result<(), DiameterTlsError> {
    if chain.is_empty() || chain.len() > MAX_DTLS_PEER_CERTIFICATES {
        return Err(DiameterTlsError::MaterialNotAdmitted);
    }
    let mut chain_bytes = 0_usize;
    for certificate in chain {
        if certificate.as_ref().is_empty()
            || certificate.as_ref().len() > MAX_DTLS_PEER_CERTIFICATE_BYTES
        {
            return Err(DiameterTlsError::MaterialNotAdmitted);
        }
        chain_bytes = chain_bytes
            .checked_add(certificate.as_ref().len())
            .ok_or(DiameterTlsError::MaterialNotAdmitted)?;
        if chain_bytes > MAX_DTLS_PEER_CERTIFICATE_CHAIN_BYTES {
            return Err(DiameterTlsError::MaterialNotAdmitted);
        }
    }
    Ok(())
}

async fn prepare_material(
    controller: &TlsMaterialController,
) -> Result<PreparedMaterial, DiameterTlsError> {
    let handshake = controller
        .begin_external_handshake()
        .await
        .map_err(|_| DiameterTlsError::MaterialNotAdmitted)?;
    let chain = handshake.certificate_chain();
    validate_dtls_certificate_chain_bounds(chain)?;
    let leaf = chain.first().ok_or(DiameterTlsError::MaterialNotAdmitted)?;
    // The controller supplies one zeroizing copy. Move that allocation into
    // the engine's forced plain-Vec custody without creating a second adapter
    // copy; the emptied wrapper remains zeroizing on all pre-move failures.
    let mut private_key = handshake.private_key_der_copy();
    let certificate = dimpl::DtlsCertificate {
        certificate: leaf.as_ref().to_vec(),
        intermediates: handshake
            .certificate_chain()
            .iter()
            .skip(1)
            .map(|certificate| certificate.as_ref().to_vec())
            .collect(),
        private_key: std::mem::take(&mut *private_key),
    };
    let trust_bundles = handshake.trust_bundles().clone();
    Ok(PreparedMaterial {
        handshake,
        certificate,
        trust_bundles,
    })
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
}

fn certificate_expiry(der: &[u8]) -> Result<Timestamp, DiameterTlsError> {
    let (_, certificate) =
        X509Certificate::from_der(der).map_err(|_| DiameterTlsError::Authentication)?;
    let not_after = certificate.validity().not_after.timestamp();
    let expiry = time::OffsetDateTime::from_unix_timestamp(not_after)
        .map_err(|_| DiameterTlsError::Authentication)?;
    Ok(Timestamp::from_offset_datetime(expiry))
}

fn validate_presented_chain_order(chain: &[Vec<u8>]) -> Result<(), DiameterTlsError> {
    for certificates in chain.windows(2) {
        let (_, child) = X509Certificate::from_der(&certificates[0])
            .map_err(|_| DiameterTlsError::Authentication)?;
        let (_, issuer) = X509Certificate::from_der(&certificates[1])
            .map_err(|_| DiameterTlsError::Authentication)?;
        if child.issuer() != issuer.subject() {
            return Err(DiameterTlsError::Authentication);
        }
    }
    Ok(())
}

fn validate_peer_certificate_chain(
    chain: &[Vec<u8>],
    validation: &HandshakeValidation,
) -> Result<Timestamp, DiameterTlsError> {
    if chain.is_empty() || chain.len() > MAX_DTLS_PEER_CERTIFICATES {
        return Err(DiameterTlsError::Authentication);
    }
    let mut chain_bytes = 0_usize;
    for certificate in chain {
        if certificate.is_empty() || certificate.len() > MAX_DTLS_PEER_CERTIFICATE_BYTES {
            return Err(DiameterTlsError::Authentication);
        }
        chain_bytes = chain_bytes
            .checked_add(certificate.len())
            .ok_or(DiameterTlsError::Authentication)?;
        if chain_bytes > MAX_DTLS_PEER_CERTIFICATE_CHAIN_BYTES {
            return Err(DiameterTlsError::Authentication);
        }
    }
    // TLS 1.2 Certificate carries the sender's certificate first and each
    // following certificate must directly certify the one before it. WebPKI
    // accepts intermediates as a set, so enforce the wire-order contract
    // explicitly before asking it to validate signatures and trust.
    validate_presented_chain_order(chain)?;
    let leaf = chain.first().ok_or(DiameterTlsError::Authentication)?;
    let mut expiry = certificate_expiry(leaf)?;
    for certificate in chain.iter().skip(1) {
        expiry = expiry.min(certificate_expiry(certificate)?);
    }
    let peer_spiffe = opc_identity::extract_spiffe_id_from_cert_der(leaf)
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
    let cert_der = CertificateDer::from(leaf.clone());
    let intermediates: Vec<_> = chain
        .iter()
        .skip(1)
        .cloned()
        .map(CertificateDer::from)
        .collect();
    let end_entity =
        webpki::EndEntityCert::try_from(&cert_der).map_err(|_| DiameterTlsError::Authentication)?;
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| DiameterTlsError::Authentication)?;
    let usage = match validation.usage {
        PeerUsage::Server => webpki::KeyUsage::server_auth(),
        PeerUsage::Client => webpki::KeyUsage::client_auth(),
    };
    let provider = tokio_rustls::rustls::crypto::ring::default_provider();
    end_entity
        .verify_for_usage(
            provider.signature_verification_algorithms.all,
            &anchors,
            &intermediates,
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

enum EnginePoll {
    Wait(Option<std::time::Instant>),
    InstallEpochKey(dimpl::KeyingMaterial),
    PrepareChangeCipherSpec,
    PrepareEpoch,
    PrepareCloseNotify,
}

fn grow_engine_poll_buffer(buffer: &mut Vec<u8>, needed: usize) -> Result<(), DiameterTlsError> {
    // RFC 6083 fixes the engine path MTU and the adapter rejects any record
    // larger than this same receive bound. Certificate messages are fragmented
    // by the engine across bounded records, so no legitimate local chain
    // requires one larger poll allocation.
    if needed <= buffer.len() || needed > MAX_DTLS_SCTP_RECORD_BYTES {
        return Err(DiameterTlsError::TlsHandshake);
    }
    buffer
        .try_reserve_exact(needed - buffer.len())
        .map_err(|_| DiameterTlsError::TlsHandshake)?;
    buffer.resize(needed, 0);
    Ok(())
}

fn poll_engine(
    engine: &mut dimpl::Dtls,
    validation: Option<&HandshakeValidation>,
    state: &mut PumpState,
    buffer: &mut Vec<u8>,
) -> Result<EnginePoll, DiameterTlsError> {
    loop {
        match engine.poll_output(buffer) {
            dimpl::Output::Packet(packet) => state.outbound.push(Bytes::copy_from_slice(packet)),
            dimpl::Output::BufferTooSmall { needed } => {
                grow_engine_poll_buffer(buffer, needed)?;
            }
            dimpl::Output::Timeout(next) => return Ok(EnginePoll::Wait(Some(next))),
            dimpl::Output::Connected => state.connected = true,
            dimpl::Output::PeerCert(der) => {
                let Some(validation) = validation else {
                    return Err(DiameterTlsError::TlsHandshake);
                };
                state.peer_certificate_expires_at = Some(validate_peer_certificate_chain(
                    &[der.to_vec()],
                    validation,
                )?);
            }
            dimpl::Output::PeerCertChain(chain) => {
                let Some(validation) = validation else {
                    return Err(DiameterTlsError::TlsHandshake);
                };
                state.peer_certificate_expires_at =
                    Some(validate_peer_certificate_chain(&chain, validation)?);
            }
            dimpl::Output::ApplicationData(plaintext) => {
                if !state.connected {
                    return Err(DiameterTlsError::CleartextInput);
                }
                state.inbound.push_back(Bytes::copy_from_slice(plaintext));
            }
            dimpl::Output::Rfc6083KeyingMaterial(material) => {
                return Ok(EnginePoll::InstallEpochKey(material));
            }
            dimpl::Output::Rfc6083PrepareChangeCipherSpec => {
                return Ok(EnginePoll::PrepareChangeCipherSpec);
            }
            dimpl::Output::Rfc6083PrepareEpoch => return Ok(EnginePoll::PrepareEpoch),
            dimpl::Output::Rfc6083PrepareCloseNotify => return Ok(EnginePoll::PrepareCloseNotify),
            dimpl::Output::CloseNotify => state.peer_closed = true,
            // RFC 6083 must not negotiate RFC 5764 use_srtp or surface a
            // second exporter secret. Treat either this impossible output or
            // any future unhandled engine event as a failed handshake rather
            // than silently bypassing a required transport barrier.
            dimpl::Output::KeyingMaterial(_, _) => {
                return Err(DiameterTlsError::TlsHandshake);
            }
            _ => return Err(DiameterTlsError::TlsHandshake),
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

fn validate_received_dtls_record(message: &SctpUserMessage) -> Result<&[u8], DiameterTlsError> {
    if message.ppid() != DIAMETER_DTLS_SCTP_PPID {
        return Err(DiameterTlsError::CleartextInput);
    }
    if message.stream_id() != DIAMETER_DTLS_SCTP_STREAM
        || message.order() != SctpDeliveryOrder::Ordered
        || message.truncated()
        || message.control_truncated()
        || message.notification()
        || message.payload().len() > MAX_DTLS_SCTP_RECORD_BYTES
    {
        return Err(DiameterTlsError::Transport);
    }
    let bounds = parse_dtls_record_bounds(message.payload()).ok_or(DiameterTlsError::Transport)?;
    if bounds.record_bytes != message.payload().len() {
        return Err(DiameterTlsError::Transport);
    }
    Ok(message.payload())
}

fn validate_outbound_dtls_record(record: &[u8]) -> Result<(), DiameterTlsError> {
    if record.len() > MAX_DTLS_SCTP_RECORD_BYTES {
        return Err(DiameterTlsError::Transport);
    }
    let bounds = parse_dtls_record_bounds(record).ok_or(DiameterTlsError::Transport)?;
    if bounds.record_bytes != record.len() {
        return Err(DiameterTlsError::Transport);
    }
    Ok(())
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

fn negotiated_version(engine: &dimpl::Dtls) -> Result<DtlsSctpVersion, DiameterTlsError> {
    match engine.protocol_version() {
        Some(dimpl::ProtocolVersion::DTLS1_2) => Ok(DtlsSctpVersion::Dtls12),
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
) -> Result<(DtlsSctpVersion, DtlsSctpCipher, Timestamp), DiameterTlsError> {
    // dimpl starts the client flight and seeds server state from
    // handle_timeout; the explicit initial kick keeps the handshake
    // deterministic instead of depending on the engine's first timer.
    engine
        .handle_timeout(std::time::Instant::now())
        .map_err(|_| DiameterTlsError::TlsHandshake)?;
    let mut state = PumpState::default();
    let mut buffer = vec![0_u8; ENGINE_POLL_BUFFER];
    let mut auth_key_installed = false;
    let mut change_cipher_spec_prepared = false;
    let mut auth_key_prepared = false;
    loop {
        // Engine progress is evaluated before waiting so a completed
        // handshake never blocks on an event that already arrived.
        let poll = poll_engine(engine, Some(validation), &mut state, &mut buffer)?;
        let next_timer = match poll {
            EnginePoll::InstallEpochKey(material) => {
                flush_outbound(io, &mut state).await?;
                if auth_key_installed || auth_key_prepared {
                    return Err(DiameterTlsError::TlsHandshake);
                }
                io.install_epoch_key(&material, deadline).await?;
                auth_key_installed = true;
                continue;
            }
            EnginePoll::PrepareEpoch => {
                flush_outbound(io, &mut state).await?;
                if !auth_key_installed || !change_cipher_spec_prepared || auth_key_prepared {
                    return Err(DiameterTlsError::TlsHandshake);
                }
                io.prepare_epoch(deadline).await?;
                auth_key_prepared = true;
                continue;
            }
            EnginePoll::PrepareChangeCipherSpec => {
                flush_outbound(io, &mut state).await?;
                if !auth_key_installed || change_cipher_spec_prepared || auth_key_prepared {
                    return Err(DiameterTlsError::TlsHandshake);
                }
                io.prepare_change_cipher_spec(deadline).await?;
                change_cipher_spec_prepared = true;
                continue;
            }
            EnginePoll::PrepareCloseNotify => {
                flush_outbound(io, &mut state).await?;
                io.prepare_close_notify(deadline).await?;
                continue;
            }
            EnginePoll::Wait(next_timer) => next_timer,
        };
        flush_outbound(io, &mut state).await?;
        if state.connected {
            if !auth_key_installed || !auth_key_prepared {
                return Err(DiameterTlsError::ProtectionPolicyMismatch);
            }
            io.confirm_peer_finished(deadline).await?;
            let version = negotiated_version(engine)?;
            let cipher = engine
                .dtls12_cipher_suite()
                .and_then(DtlsSctpCipher::from_dtls12_suite)
                .ok_or(DiameterTlsError::ProtocolRejected)?;
            let expires_at = state
                .peer_certificate_expires_at
                .ok_or(DiameterTlsError::Authentication)?;
            return Ok((version, cipher, expires_at));
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
                let record = validate_received_dtls_record(&message)?;
                engine
                    .handle_packet(record)
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
        let next_timer = match poll_engine(engine, None, state, buffer)? {
            EnginePoll::Wait(next_timer) => next_timer,
            EnginePoll::InstallEpochKey(_)
            | EnginePoll::PrepareChangeCipherSpec
            | EnginePoll::PrepareEpoch => return Err(DiameterTlsError::Transport),
            EnginePoll::PrepareCloseNotify => {
                flush_outbound(io, state).await?;
                io.prepare_close_notify(deadline).await?;
                continue;
            }
        };
        flush_outbound(io, state).await?;
        if !state.inbound.is_empty() {
            return Ok(());
        }
        if state.peer_closed {
            return Err(DiameterTlsError::PeerClosed);
        }
        match pump_wait(io, next_timer, deadline).await? {
            PumpEvent::Deadline => return Err(DiameterTlsError::DeadlineExceeded),
            PumpEvent::Timer => engine
                .handle_timeout(std::time::Instant::now())
                .map_err(|_| DiameterTlsError::Transport)?,
            PumpEvent::Message(None) => return Err(DiameterTlsError::Transport),
            PumpEvent::Message(Some(message)) => {
                let record = validate_received_dtls_record(&message)?;
                engine
                    .handle_packet(record)
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

fn bind_inband_dtls_session(
    local_capabilities: PeerCapabilities,
    session_policy: PeerSessionPolicy,
) -> Result<(PeerSession, PeerSessionGeneration), DiameterTlsError> {
    let required = PeerProtectionRequirement::inband_dtls_sctp();
    let mut session = PeerSession::with_policy_and_protection(
        local_capabilities,
        session_policy,
        opc_proto_diameter::peer::PeerProtectionPolicy::Require(required),
    );
    let generation = begin_generation(&mut session, required)?;
    if session.pending_protection().is_some() {
        let _ = session.fail_on(generation, PeerSessionBlocker::SessionFailed);
        return Err(DiameterTlsError::PeerBinding);
    }
    Ok((session, generation))
}

fn pending_inband_dtls(session: &PeerSession) -> Result<PeerProtectionPending, DiameterTlsError> {
    let pending = session
        .pending_protection()
        .ok_or(DiameterTlsError::CapabilitiesExchangeFailed)?;
    if pending.mechanism() != PeerProtectionMechanism::DtlsSctp
        || pending.sequence() != PeerProtectionSequence::InbandAfterCapabilities
    {
        return Err(DiameterTlsError::CapabilitiesExchangeFailed);
    }
    Ok(pending)
}

fn inband_encode_context(frame_limits: DiameterFrameLimits) -> EncodeContext {
    EncodeContext {
        max_message_len: frame_limits.max_message_len(),
        ..EncodeContext::default()
    }
}

async fn send_inband_cleartext_frame(
    io: &mut Box<dyn SctpMessageIo>,
    wire: &[u8],
    frame_limits: DiameterFrameLimits,
    deadline: Instant,
) -> Result<(), DiameterTlsError> {
    validate_wire_frame(wire, frame_limits)?;
    tokio::time::timeout_at(deadline, io.send_inband_cleartext(wire))
        .await
        .map_err(|_| DiameterTlsError::DeadlineExceeded)??;
    Ok(())
}

async fn receive_inband_cleartext_frame(
    io: &mut Box<dyn SctpMessageIo>,
    frame_limits: DiameterFrameLimits,
    deadline: Instant,
) -> Result<OwnedMessage, DiameterTlsError> {
    let message = tokio::time::timeout_at(deadline, io.receive_inband_cleartext())
        .await
        .map_err(|_| DiameterTlsError::DeadlineExceeded)??
        .ok_or(DiameterTlsError::Transport)?;
    if message.notification()
        || message.truncated()
        || message.control_truncated()
        || message.ppid() != DIAMETER_SCTP_PPID.get()
        || message.stream_id() != DIAMETER_DTLS_SCTP_STREAM
        || message.order() != SctpDeliveryOrder::Ordered
    {
        return Err(DiameterTlsError::CleartextInput);
    }
    decode_wire_frame(Bytes::copy_from_slice(message.payload()), frame_limits)
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

struct SctpTransportLifetimeGuard {
    close: Arc<dyn SctpTransportClose>,
    armed: bool,
}

impl SctpTransportLifetimeGuard {
    fn new(close: Arc<dyn SctpTransportClose>) -> Self {
        Self { close, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SctpTransportLifetimeGuard {
    fn drop(&mut self) {
        if self.armed {
            self.close.close();
        }
    }
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

/// Outbound RFC 6733 in-band DTLS/SCTP typestate before the sole cleartext
/// CER is emitted.
pub struct DiameterInbandDtlsSctpInitiator {
    io: Box<dyn SctpMessageIo>,
    lifetime: SctpTransportLifetimeGuard,
    session: PeerSession,
    generation: PeerSessionGeneration,
    local_capabilities: PeerCapabilities,
    connector: DiameterDtlsSctpConnector,
}

/// Outbound RFC 6733 in-band DTLS/SCTP typestate after CER, permitting only
/// the correlated CEA followed by DTLS on the same SCTP association.
pub struct DiameterInbandDtlsSctpInitiatorAwaitingAnswer {
    io: Box<dyn SctpMessageIo>,
    lifetime: SctpTransportLifetimeGuard,
    session: PeerSession,
    generation: PeerSessionGeneration,
    connector: DiameterDtlsSctpConnector,
}

/// Inbound RFC 6733 in-band DTLS/SCTP typestate before the sole cleartext CER
/// is received.
pub struct DiameterInbandDtlsSctpResponder {
    io: Box<dyn SctpMessageIo>,
    lifetime: SctpTransportLifetimeGuard,
    session: PeerSession,
    generation: PeerSessionGeneration,
    local_capabilities: PeerCapabilities,
    acceptor: DiameterDtlsSctpAcceptor,
}

/// Inbound RFC 6733 in-band DTLS/SCTP typestate after CER, permitting only
/// the canonical CEA followed by DTLS on the same SCTP association.
pub struct DiameterInbandDtlsSctpResponderCerReceived {
    io: Box<dyn SctpMessageIo>,
    lifetime: SctpTransportLifetimeGuard,
    session: PeerSession,
    generation: PeerSessionGeneration,
    local_capabilities: PeerCapabilities,
    acceptor: DiameterDtlsSctpAcceptor,
}

/// Outbound mutually authenticated Diameter DTLS/SCTP connector.
#[derive(Clone)]
pub struct DiameterDtlsSctpConnector {
    material_controller: TlsMaterialController,
    expected_peer: ExpectedPeerIdentity,
    policy: DtlsSctpPolicy,
    engine_config: Arc<dimpl::Config>,
}

impl DiameterDtlsSctpConnector {
    /// Create a connector that requires an exact authenticated peer identity.
    ///
    /// The complete DTLS provider self-test and RFC 6083 configuration
    /// validation run here, before the connector can accept traffic. The
    /// resulting immutable configuration is reused by every handshake so an
    /// unauthenticated peer cannot trigger provider known-answer tests.
    pub fn new(
        material_controller: TlsMaterialController,
        expected_peer: ExpectedPeerIdentity,
        policy: DtlsSctpPolicy,
    ) -> Result<Self, DiameterTlsError> {
        let engine_config = policy.engine_config()?;
        Ok(Self {
            material_controller,
            expected_peer,
            policy,
            engine_config,
        })
    }

    /// Begin the RFC 6733 in-band sequence on one pristine authenticated SCTP
    /// association. The returned typestate owns the only DATA-capable handle;
    /// dropping or cancelling any step aborts the association.
    pub fn begin_inband(
        &self,
        io: impl Into<DiameterDtlsSctpTransport>,
        local_capabilities: PeerCapabilities,
        session_policy: PeerSessionPolicy,
    ) -> Result<DiameterInbandDtlsSctpInitiator, DiameterTlsError> {
        let mut io = io.into().into_inner();
        let close = io.close_handle();
        let (mut session, generation) =
            bind_inband_dtls_session(local_capabilities.clone(), session_policy)?;
        if let Err(error) = io.begin_inband_cleartext() {
            let _ = session.fail_on(generation, PeerSessionBlocker::SessionFailed);
            close.close();
            return Err(error);
        }
        Ok(DiameterInbandDtlsSctpInitiator {
            io,
            lifetime: SctpTransportLifetimeGuard::new(close),
            session,
            generation,
            local_capabilities,
            connector: self.clone(),
        })
    }

    /// Complete mutually authenticated DTLS before any Diameter byte can be
    /// emitted. The SCTP message transport must be freshly established; any
    /// cleartext user message fails the association closed.
    pub async fn connect_direct(
        &self,
        io: impl Into<DiameterDtlsSctpTransport>,
        mut session: PeerSession,
        deadline: Instant,
    ) -> Result<DiameterDtlsSctpConnection, DiameterTlsError> {
        let mut io = io.into().into_inner();
        let (generation, pending) = bind_dtls_session(&mut session)?;
        if let Err(error) = io.begin_direct_dtls() {
            fail_pending(
                &mut session,
                &pending,
                PeerProtectionFailure::HandshakeFailed,
            );
            io.close_handle().close();
            return Err(error);
        }
        self.connect_bound(io, session, generation, pending, deadline)
            .await
    }

    async fn connect_bound(
        &self,
        mut io: Box<dyn SctpMessageIo>,
        mut session: PeerSession,
        generation: PeerSessionGeneration,
        pending: PeerProtectionPending,
        deadline: Instant,
    ) -> Result<DiameterDtlsSctpConnection, DiameterTlsError> {
        // Arm the association lifetime before waiting for the shared external
        // handshake budget. Cancellation, timeout, or material rejection must
        // close the transport just as a failure inside the DTLS engine does.
        let mut lifetime = SctpTransportLifetimeGuard::new(io.close_handle());
        let prepared =
            match tokio::time::timeout_at(deadline, prepare_material(&self.material_controller))
                .await
            {
                Ok(Ok(material)) => material,
                Ok(Err(error)) => {
                    fail_pending(
                        &mut session,
                        &pending,
                        PeerProtectionFailure::HandshakeFailed,
                    );
                    return Err(error);
                }
                Err(_) => {
                    fail_pending(
                        &mut session,
                        &pending,
                        PeerProtectionFailure::HandshakeFailed,
                    );
                    return Err(DiameterTlsError::DeadlineExceeded);
                }
            };
        let PreparedMaterial {
            handshake,
            certificate,
            trust_bundles,
        } = prepared;
        let mut engine = self.new_engine(certificate)?;
        engine.set_active(true);
        let validation = HandshakeValidation {
            expected_peer: self.expected_peer.clone(),
            trust_bundles,
            usage: PeerUsage::Server,
        };
        let established = match tokio::time::timeout_at(
            deadline,
            run_handshake(&mut engine, &mut io, &validation, deadline),
        )
        .await
        {
            Ok(Ok(established)) => established,
            Ok(Err(error)) => {
                fail_pending(
                    &mut session,
                    &pending,
                    PeerProtectionFailure::HandshakeFailed,
                );
                return Err(error);
            }
            Err(_) => {
                fail_pending(
                    &mut session,
                    &pending,
                    PeerProtectionFailure::HandshakeFailed,
                );
                return Err(DiameterTlsError::DeadlineExceeded);
            }
        };
        let admission = handshake
            .admit()
            .map_err(|_| DiameterTlsError::MaterialNotAdmitted)?;
        let result = finish_association(
            engine,
            io,
            admission,
            self.material_controller.subscribe_material_changes(),
            session,
            generation,
            pending,
            self.expected_peer.clone(),
            DiameterConnectionRole::Connector,
            self.policy,
            established,
        );
        if result.is_ok() {
            lifetime.disarm();
        }
        result
    }

    fn new_engine(
        &self,
        certificate: dimpl::DtlsCertificate,
    ) -> Result<dimpl::Dtls, DiameterTlsError> {
        new_policy_engine(Arc::clone(&self.engine_config), certificate)
    }

    #[cfg(test)]
    pub(crate) fn shares_engine_config_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.engine_config, &other.engine_config)
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
#[derive(Clone)]
pub struct DiameterDtlsSctpAcceptor {
    material_controller: TlsMaterialController,
    expected_peer: ExpectedPeerIdentity,
    policy: DtlsSctpPolicy,
    engine_config: Arc<dimpl::Config>,
}

impl DiameterDtlsSctpAcceptor {
    /// Create an acceptor that requires an exact configured inbound identity.
    /// Any other authenticated or unauthenticated peer is failed closed. The
    /// provider self-test and configuration validation complete here, before
    /// any listener-owned association can be handed to this acceptor.
    pub fn new(
        material_controller: TlsMaterialController,
        expected_peer: ExpectedPeerIdentity,
        policy: DtlsSctpPolicy,
    ) -> Result<Self, DiameterTlsError> {
        let engine_config = policy.engine_config()?;
        Ok(Self {
            material_controller,
            expected_peer,
            policy,
            engine_config,
        })
    }

    /// Begin the RFC 6733 in-band sequence on one freshly accepted,
    /// authenticated SCTP association.
    pub fn begin_inband(
        &self,
        io: impl Into<DiameterDtlsSctpTransport>,
        local_capabilities: PeerCapabilities,
        session_policy: PeerSessionPolicy,
    ) -> Result<DiameterInbandDtlsSctpResponder, DiameterTlsError> {
        let mut io = io.into().into_inner();
        let close = io.close_handle();
        let (mut session, generation) =
            bind_inband_dtls_session(local_capabilities.clone(), session_policy)?;
        if let Err(error) = io.begin_inband_cleartext() {
            let _ = session.fail_on(generation, PeerSessionBlocker::SessionFailed);
            close.close();
            return Err(error);
        }
        Ok(DiameterInbandDtlsSctpResponder {
            io,
            lifetime: SctpTransportLifetimeGuard::new(close),
            session,
            generation,
            local_capabilities,
            acceptor: self.clone(),
        })
    }

    /// Complete mutually authenticated DTLS on an accepted SCTP association
    /// before reading any Diameter byte. A stale credential epoch closes this
    /// association; the listener may accept a fresh one with a fresh
    /// generation.
    pub async fn accept_direct(
        &self,
        io: impl Into<DiameterDtlsSctpTransport>,
        mut session: PeerSession,
        deadline: Instant,
    ) -> Result<DiameterDtlsSctpConnection, DiameterTlsError> {
        let mut io = io.into().into_inner();
        let (generation, pending) = bind_dtls_session(&mut session)?;
        if let Err(error) = io.begin_direct_dtls() {
            fail_pending(
                &mut session,
                &pending,
                PeerProtectionFailure::HandshakeFailed,
            );
            io.close_handle().close();
            return Err(error);
        }
        self.accept_bound(io, session, generation, pending, deadline)
            .await
    }

    async fn accept_bound(
        &self,
        mut io: Box<dyn SctpMessageIo>,
        mut session: PeerSession,
        generation: PeerSessionGeneration,
        pending: PeerProtectionPending,
        deadline: Instant,
    ) -> Result<DiameterDtlsSctpConnection, DiameterTlsError> {
        // The acceptor has the same cancellation and deadline contract as the
        // connector, including while it waits for a material snapshot permit.
        let mut lifetime = SctpTransportLifetimeGuard::new(io.close_handle());
        let prepared =
            match tokio::time::timeout_at(deadline, prepare_material(&self.material_controller))
                .await
            {
                Ok(Ok(material)) => material,
                Ok(Err(error)) => {
                    fail_pending(
                        &mut session,
                        &pending,
                        PeerProtectionFailure::HandshakeFailed,
                    );
                    return Err(error);
                }
                Err(_) => {
                    fail_pending(
                        &mut session,
                        &pending,
                        PeerProtectionFailure::HandshakeFailed,
                    );
                    return Err(DiameterTlsError::DeadlineExceeded);
                }
            };
        let PreparedMaterial {
            handshake,
            certificate,
            trust_bundles,
        } = prepared;
        let mut engine = self.new_engine(certificate)?;
        let validation = HandshakeValidation {
            expected_peer: self.expected_peer.clone(),
            trust_bundles,
            usage: PeerUsage::Client,
        };
        let established = match tokio::time::timeout_at(
            deadline,
            run_handshake(&mut engine, &mut io, &validation, deadline),
        )
        .await
        {
            Ok(Ok(established)) => established,
            Ok(Err(error)) => {
                fail_pending(
                    &mut session,
                    &pending,
                    PeerProtectionFailure::HandshakeFailed,
                );
                return Err(error);
            }
            Err(_) => {
                fail_pending(
                    &mut session,
                    &pending,
                    PeerProtectionFailure::HandshakeFailed,
                );
                return Err(DiameterTlsError::DeadlineExceeded);
            }
        };
        let admission = handshake
            .admit()
            .map_err(|_| DiameterTlsError::MaterialNotAdmitted)?;
        let result = finish_association(
            engine,
            io,
            admission,
            self.material_controller.subscribe_material_changes(),
            session,
            generation,
            pending,
            self.expected_peer.clone(),
            DiameterConnectionRole::Acceptor,
            self.policy,
            established,
        );
        if result.is_ok() {
            lifetime.disarm();
        }
        result
    }

    fn new_engine(
        &self,
        certificate: dimpl::DtlsCertificate,
    ) -> Result<dimpl::Dtls, DiameterTlsError> {
        new_policy_engine(Arc::clone(&self.engine_config), certificate)
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

impl DiameterInbandDtlsSctpInitiator {
    /// Exact candidate generation for caller-owned simultaneous-open election.
    pub const fn generation(&self) -> PeerSessionGeneration {
        self.generation
    }

    /// Build and emit the only cleartext request permitted by this typestate.
    pub async fn send_capabilities_request(
        mut self,
        hop_by_hop_identifier: u32,
        end_to_end_identifier: u32,
        deadline: Instant,
    ) -> Result<DiameterInbandDtlsSctpInitiatorAwaitingAnswer, DiameterTlsError> {
        let frame_limits = self.connector.policy.frame_limits();
        let message = build_capabilities_exchange_request(
            &self.local_capabilities,
            hop_by_hop_identifier,
            end_to_end_identifier,
            inband_encode_context(frame_limits),
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
            let _ = self
                .session
                .fail_on(self.generation, PeerSessionBlocker::SessionFailed);
            return Err(DiameterTlsError::CapabilitiesExchangeFailed);
        }
        let wire = encoded_bytes(&message, frame_limits)?;
        if let Err(error) =
            send_inband_cleartext_frame(&mut self.io, &wire, frame_limits, deadline).await
        {
            let _ = self
                .session
                .fail_on(self.generation, PeerSessionBlocker::SessionFailed);
            return Err(error);
        }
        Ok(DiameterInbandDtlsSctpInitiatorAwaitingAnswer {
            io: self.io,
            lifetime: self.lifetime,
            session: self.session,
            generation: self.generation,
            connector: self.connector,
        })
    }
}

impl DiameterInbandDtlsSctpInitiatorAwaitingAnswer {
    /// Receive the exact correlated CEA, permanently close the cleartext gate,
    /// and complete DTLS on the same SCTP association.
    pub async fn receive_capabilities_answer_and_upgrade(
        mut self,
        deadline: Instant,
    ) -> Result<(DiameterDtlsSctpConnection, CapabilitiesExchangeAnswer), DiameterTlsError> {
        let frame_limits = self.connector.policy.frame_limits();
        let message = receive_inband_cleartext_frame(&mut self.io, frame_limits, deadline).await?;
        self.session
            .admit_message(
                self.generation,
                PeerMessageDirection::Inbound,
                &message.header,
            )
            .map_err(|_| DiameterTlsError::CommandNotAdmitted)?;
        let answer = parse_capabilities_exchange_answer(
            &borrowed(&message),
            capabilities_decode_context(frame_limits),
        )
        .map_err(|_| DiameterTlsError::CapabilitiesExchangeFailed)?;
        if !answer
            .capabilities
            .identity
            .semantically_eq(self.connector.expected_peer.diameter_identity())
        {
            return Err(DiameterTlsError::PeerIdentityMismatch);
        }
        self.session
            .observe_capabilities_answer_on(self.generation, &message.header, &answer)
            .map_err(|_| DiameterTlsError::CapabilitiesExchangeFailed)?;
        let pending = pending_inband_dtls(&self.session)?;
        self.io.seal_inband_cleartext()?;
        self.lifetime.disarm();
        let connection = self
            .connector
            .connect_bound(self.io, self.session, self.generation, pending, deadline)
            .await?;
        Ok((connection, answer))
    }
}

impl DiameterInbandDtlsSctpResponder {
    /// Exact candidate generation for caller-owned simultaneous-open election.
    pub const fn generation(&self) -> PeerSessionGeneration {
        self.generation
    }

    /// Receive exactly one cleartext CER. Every other command, malformed
    /// message, or foreign SCTP metadata fails this association closed.
    pub async fn receive_capabilities_request(
        mut self,
        deadline: Instant,
    ) -> Result<(DiameterInbandDtlsSctpResponderCerReceived, PeerCapabilities), DiameterTlsError>
    {
        let frame_limits = self.acceptor.policy.frame_limits();
        let message = receive_inband_cleartext_frame(&mut self.io, frame_limits, deadline).await?;
        self.session
            .admit_message(
                self.generation,
                PeerMessageDirection::Inbound,
                &message.header,
            )
            .map_err(|_| DiameterTlsError::CommandNotAdmitted)?;
        let remote = parse_capabilities_exchange_request(
            &borrowed(&message),
            capabilities_decode_context(frame_limits),
        )
        .map_err(|_| DiameterTlsError::CapabilitiesExchangeFailed)?;
        if !remote
            .identity
            .semantically_eq(self.acceptor.expected_peer.diameter_identity())
        {
            return Err(DiameterTlsError::PeerIdentityMismatch);
        }
        self.session
            .capabilities_request_received_on(self.generation, &message.header, remote.clone())
            .map_err(|_| DiameterTlsError::CapabilitiesExchangeFailed)?;
        Ok((
            DiameterInbandDtlsSctpResponderCerReceived {
                io: self.io,
                lifetime: self.lifetime,
                session: self.session,
                generation: self.generation,
                local_capabilities: self.local_capabilities,
                acceptor: self.acceptor,
            },
            remote,
        ))
    }
}

impl DiameterInbandDtlsSctpResponderCerReceived {
    /// Emit the canonical CEA, permanently close the cleartext gate, and
    /// complete DTLS on the same SCTP association.
    pub async fn send_capabilities_answer_and_upgrade(
        mut self,
        answer: &CapabilitiesExchangeAnswer,
        deadline: Instant,
    ) -> Result<DiameterDtlsSctpConnection, DiameterTlsError> {
        if answer.capabilities != self.local_capabilities {
            return Err(DiameterTlsError::CapabilitiesExchangeFailed);
        }
        let frame_limits = self.acceptor.policy.frame_limits();
        let emission = self
            .session
            .prepare_capabilities_answer_on(
                self.generation,
                answer,
                inband_encode_context(frame_limits),
            )
            .map_err(|_| DiameterTlsError::CapabilitiesExchangeFailed)?;
        send_inband_cleartext_frame(&mut self.io, emission.as_bytes(), frame_limits, deadline)
            .await?;
        let pending = pending_inband_dtls(&self.session)?;
        self.io.seal_inband_cleartext()?;
        self.lifetime.disarm();
        self.acceptor
            .accept_bound(self.io, self.session, self.generation, pending, deadline)
            .await
    }
}

/// Construct the RFC 6083 DTLS 1.2 engine.
fn new_policy_engine(
    config: Arc<dimpl::Config>,
    certificate: dimpl::DtlsCertificate,
) -> Result<dimpl::Dtls, DiameterTlsError> {
    let signing_key = config
        .crypto_provider()
        .key_provider
        .load_private_key(&certificate.private_key)
        .map_err(|_| DiameterTlsError::MaterialNotAdmitted)?;
    drop(signing_key);
    Ok(dimpl::Dtls::new_12(
        config,
        certificate,
        std::time::Instant::now(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn finish_association(
    engine: dimpl::Dtls,
    io: Box<dyn SctpMessageIo>,
    admission: TlsAdmittedConnection,
    material_status: TlsMaterialStatusReceiver,
    mut session: PeerSession,
    generation: PeerSessionGeneration,
    pending: PeerProtectionPending,
    expected_peer: ExpectedPeerIdentity,
    role: DiameterConnectionRole,
    policy: DtlsSctpPolicy,
    established: (DtlsSctpVersion, DtlsSctpCipher, Timestamp),
) -> Result<DiameterDtlsSctpConnection, DiameterTlsError> {
    let (version, cipher, peer_expires_at) = established;
    let transition = session
        .attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::DtlsSctp)
        .map_err(|_| DiameterTlsError::PeerBinding)?;
    let protection = transition
        .protection()
        .protected_ready()
        .then(|| session.protection_evidence())
        .flatten()
        .ok_or(DiameterTlsError::PeerBinding)?;
    if !material_epoch_retained(admission.epoch(), material_status.status()) {
        return Err(DiameterTlsError::Retired);
    }
    let established_at = Instant::now();
    let hard_deadline = association_hard_deadline(
        established_at,
        policy.maximum_connection_age(),
        admission.certificate_chain_expires_at(),
        peer_expires_at,
    );
    let close = io.close_handle();
    let retired = Arc::new(AtomicBool::new(false));
    let retirement_task = spawn_retirement_task(
        material_status.clone(),
        admission.epoch(),
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
            cipher,
            material_epoch: admission.epoch(),
            local_certificate_expires_at: admission.certificate_chain_expires_at(),
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

struct DtlsRuntimeClose {
    close: Arc<dyn SctpTransportClose>,
}

impl ProtectedFrameTransportClose for DtlsRuntimeClose {
    fn close(&self) {
        self.close.close();
    }
}

struct DtlsRuntimeSend {
    commands: mpsc::Sender<DtlsRuntimeSendCommand>,
}

struct DtlsRuntimeReceive {
    commands: mpsc::Sender<DtlsRuntimeReceiveCommand>,
}

struct DtlsRuntimeSendCommand {
    wire: Bytes,
    limits: DiameterFrameLimits,
    deadline: Instant,
    result: oneshot::Sender<Result<(), DiameterTlsError>>,
}

struct DtlsRuntimeReceiveCommand {
    limits: DiameterFrameLimits,
    _completion_timeout: Duration,
    deadline: Instant,
    result: oneshot::Sender<Result<Bytes, DiameterTlsError>>,
}

impl ProtectedFrameSender for DtlsRuntimeSend {
    fn send_frame<'a>(
        &'a mut self,
        wire: &'a [u8],
        limits: DiameterFrameLimits,
        deadline: Instant,
    ) -> FrameTransportFuture<'a, ()> {
        Box::pin(async move {
            validate_wire_frame(wire, limits)?;
            let (result, response) = oneshot::channel();
            self.commands
                .try_send(DtlsRuntimeSendCommand {
                    wire: Bytes::copy_from_slice(wire),
                    limits,
                    deadline,
                    result,
                })
                .map_err(|_| DiameterTlsError::Transport)?;
            response.await.map_err(|_| DiameterTlsError::Transport)?
        })
    }
}

impl ProtectedFrameReceiver for DtlsRuntimeReceive {
    fn receive_frame(
        &mut self,
        limits: DiameterFrameLimits,
        completion_timeout: Duration,
        hard_deadline: Instant,
    ) -> FrameTransportFuture<'_, Bytes> {
        Box::pin(async move {
            let (result, response) = oneshot::channel();
            self.commands
                .try_send(DtlsRuntimeReceiveCommand {
                    limits,
                    _completion_timeout: completion_timeout,
                    deadline: hard_deadline,
                    result,
                })
                .map_err(|_| DiameterTlsError::Transport)?;
            response.await.map_err(|_| DiameterTlsError::Transport)?
        })
    }
}

struct DtlsRuntimeActorGuard {
    task: tokio::task::JoinHandle<()>,
    close: Arc<dyn SctpTransportClose>,
}

impl Drop for DtlsRuntimeActorGuard {
    fn drop(&mut self) {
        self.close.close();
        self.task.abort();
    }
}

struct DtlsRuntimeGuards {
    _retirement: RetirementTask,
    _actor: DtlsRuntimeActorGuard,
}

async fn run_dtls_runtime_actor(
    mut engine: dimpl::Dtls,
    mut io: Box<dyn SctpMessageIo>,
    close: Arc<dyn SctpTransportClose>,
    mut sends: mpsc::Receiver<DtlsRuntimeSendCommand>,
    mut receives: mpsc::Receiver<DtlsRuntimeReceiveCommand>,
    max_buffered_frames: usize,
) {
    let mut state = PumpState {
        connected: true,
        ..PumpState::default()
    };
    let mut buffer = vec![0_u8; ENGINE_POLL_BUFFER];
    let mut pending_receive: Option<DtlsRuntimeReceiveCommand> = None;
    let outcome: Result<(), DiameterTlsError> = async {
        loop {
            let next_timer = match poll_engine(&mut engine, None, &mut state, &mut buffer)? {
                EnginePoll::Wait(next) => next,
                EnginePoll::PrepareCloseNotify => {
                    let deadline = Instant::now()
                        .checked_add(Duration::from_secs(5))
                        .unwrap_or_else(Instant::now);
                    tokio::time::timeout_at(deadline, async {
                        flush_outbound(&mut io, &mut state).await?;
                        io.prepare_close_notify(deadline).await?;
                        let next = match poll_engine(&mut engine, None, &mut state, &mut buffer)? {
                            EnginePoll::Wait(next) => next,
                            EnginePoll::PrepareCloseNotify
                            | EnginePoll::InstallEpochKey(_)
                            | EnginePoll::PrepareChangeCipherSpec
                            | EnginePoll::PrepareEpoch => {
                                return Err(DiameterTlsError::Transport);
                            }
                        };
                        flush_outbound(&mut io, &mut state).await?;
                        Ok(next)
                    })
                    .await
                    .map_err(|_| DiameterTlsError::DeadlineExceeded)??
                }
                EnginePoll::InstallEpochKey(_)
                | EnginePoll::PrepareChangeCipherSpec
                | EnginePoll::PrepareEpoch => return Err(DiameterTlsError::Transport),
            };
            flush_outbound(&mut io, &mut state).await?;
            if state.inbound.len() > max_buffered_frames {
                return Err(DiameterTlsError::Transport);
            }
            if !state.inbound.is_empty() {
                if let Some(request) = pending_receive.take() {
                    let wire = state
                        .inbound
                        .pop_front()
                        .ok_or(DiameterTlsError::Transport)?;
                    let result = validate_wire_frame(&wire, request.limits).map(|()| wire);
                    let failed = result.is_err();
                    let _ = request.result.send(result);
                    if failed {
                        return Err(DiameterTlsError::Transport);
                    }
                    continue;
                }
            }
            if state.peer_closed {
                if state.inbound.is_empty() {
                    // Publish the authenticated orderly-close cause through
                    // the receiver command boundary before terminating the
                    // actor. Otherwise a reader that asks immediately after
                    // actor exit can observe only a closed command channel and
                    // incorrectly classify the close as a generic transport
                    // failure.
                    let request = match pending_receive.take() {
                        Some(request) => request,
                        None => {
                            let Some(request) = receives.recv().await else {
                                return Err(DiameterTlsError::PeerClosed);
                            };
                            request
                        }
                    };
                    let _ = request.result.send(Err(DiameterTlsError::PeerClosed));
                    return Err(DiameterTlsError::PeerClosed);
                }
                // RFC 6083 section 4.9 requires authenticated application
                // records preceding close_notify to be processed first. Stop
                // reading the wire after close_notify, but continue serving
                // the already-decrypted bounded queue in order.
                let Some(command) = receives.recv().await else {
                    return Err(DiameterTlsError::Transport);
                };
                pending_receive = Some(command);
                continue;
            }

            let now = Instant::now();
            if pending_receive
                .as_ref()
                .is_some_and(|request| now >= request.deadline)
            {
                if let Some(request) = pending_receive.take() {
                    let _ = request.result.send(Err(DiameterTlsError::DeadlineExceeded));
                }
                return Err(DiameterTlsError::DeadlineExceeded);
            }
            let fallback = now.checked_add(Duration::from_secs(60 * 60)).unwrap_or(now);
            let engine_deadline = next_timer.map(Instant::from_std).unwrap_or(fallback);
            let receive_deadline = pending_receive
                .as_ref()
                .map(|request| request.deadline)
                .unwrap_or(fallback);
            let wake = engine_deadline.min(receive_deadline);

            tokio::select! {
                message = io.receive_message() => {
                    let message = message?.ok_or(DiameterTlsError::Transport)?;
                    let record = validate_received_dtls_record(&message)?;
                    engine
                        .handle_packet(record)
                        .map_err(|_| DiameterTlsError::Transport)?;
                }
                command = sends.recv() => {
                    let Some(command) = command else {
                        return Err(DiameterTlsError::Transport);
                    };
                    if Instant::now() >= command.deadline {
                        let _ = command.result.send(Err(DiameterTlsError::DeadlineExceeded));
                        continue;
                    }
                    let result = write_wire_frame_via(
                        &mut engine,
                        &mut io,
                        &mut state,
                        &mut buffer,
                        command.limits,
                        &command.wire,
                        command.deadline,
                    ).await;
                    let failed = result.is_err();
                    let _ = command.result.send(result);
                    if failed {
                        return Err(DiameterTlsError::Transport);
                    }
                }
                command = receives.recv(), if pending_receive.is_none() => {
                    let Some(command) = command else {
                        return Err(DiameterTlsError::Transport);
                    };
                    pending_receive = Some(command);
                }
                () = tokio::time::sleep_until(wake) => {
                    let now = Instant::now();
                    if pending_receive
                        .as_ref()
                        .is_some_and(|request| now >= request.deadline)
                    {
                        if let Some(request) = pending_receive.take() {
                            let _ = request
                                .result
                                .send(Err(DiameterTlsError::DeadlineExceeded));
                        }
                        return Err(DiameterTlsError::DeadlineExceeded);
                    }
                    if now >= engine_deadline {
                        engine
                            .handle_timeout(std::time::Instant::now())
                            .map_err(|_| DiameterTlsError::Transport)?;
                    }
                }
            }
        }
    }
    .await;
    if let Some(request) = pending_receive {
        let _ = request
            .result
            .send(Err(outcome.err().unwrap_or(DiameterTlsError::Transport)));
    }
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
    /// by the full-duplex runtime; consume this sequential connection with
    /// `into_peer_runtime` for long-lived concurrent operation.
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

    pub(crate) fn into_runtime_parts(
        self,
        runtime: &tokio::runtime::Handle,
        max_buffered_frames: usize,
    ) -> Result<DiameterProtectedRuntimeParts<DiameterDtlsSctpEvidence>, DiameterTlsError> {
        let Self {
            engine,
            io,
            close,
            session,
            generation,
            evidence,
            expected_peer,
            frame_limits,
            material_status,
            hard_deadline,
            retired,
            _retirement_task,
            pump_state,
            poll_buffer,
            closed,
        } = self;
        if closed || !pump_state.inbound.is_empty() || !pump_state.outbound.is_empty() {
            close.close();
            return Err(DiameterTlsError::Transport);
        }
        drop(pump_state);
        drop(poll_buffer);
        let (send_tx, send_rx) = mpsc::channel(1);
        let (receive_tx, receive_rx) = mpsc::channel(1);
        let actor_close = Arc::clone(&close);
        let task = runtime.spawn(run_dtls_runtime_actor(
            engine,
            io,
            Arc::clone(&actor_close),
            send_rx,
            receive_rx,
            max_buffered_frames,
        ));
        let transport_close: Arc<dyn ProtectedFrameTransportClose> = Arc::new(DtlsRuntimeClose {
            close: Arc::clone(&close),
        });
        Ok(DiameterProtectedRuntimeParts {
            frame_transport: ProtectedFrameTransportParts::new(
                Box::new(DtlsRuntimeReceive {
                    commands: receive_tx,
                }),
                Box::new(DtlsRuntimeSend { commands: send_tx }),
                transport_close,
            ),
            session,
            generation,
            admitted_epoch: evidence.material_epoch(),
            evidence,
            expected_peer,
            frame_limits,
            material_status,
            hard_deadline,
            retired,
            transport_guard: Box::new(DtlsRuntimeGuards {
                _retirement: _retirement_task,
                _actor: DtlsRuntimeActorGuard {
                    task,
                    close: actor_close,
                },
            }),
        })
    }

    /// Send close_notify, close the association, and revoke this generation's
    /// readiness. The close-notify flush is bounded by `deadline`; a peer that
    /// never acknowledges still observes the closed transport.
    pub async fn close(mut self, deadline: Instant) -> Result<PeerSession, DiameterTlsError> {
        let already_closed = self.closed || self.retired.load(Ordering::Acquire);
        let mut close_error = None;
        if !already_closed {
            let Self {
                engine,
                io,
                pump_state,
                poll_buffer,
                ..
            } = &mut self;
            let close_protocol = async {
                // This consuming API has no application-delivery channel.
                // Never claim an orderly close while silently discarding an
                // authenticated application record that preceded the alert.
                if !pump_state.inbound.is_empty() || !pump_state.outbound.is_empty() {
                    return Err(DiameterTlsError::Transport);
                }
                io.prepare_close_notify(deadline).await?;
                engine.close().map_err(|_| DiameterTlsError::Transport)?;
                loop {
                    match poll_engine(engine, None, pump_state, poll_buffer)? {
                        EnginePoll::Wait(_) => break,
                        EnginePoll::PrepareCloseNotify => {
                            // The transport sender-dry barrier completed before
                            // the engine was asked to emit this alert.
                        }
                        EnginePoll::InstallEpochKey(_)
                        | EnginePoll::PrepareChangeCipherSpec
                        | EnginePoll::PrepareEpoch => {
                            return Err(DiameterTlsError::Transport);
                        }
                    }
                }
                flush_outbound(io, pump_state).await?;

                // Keep SCTP alive until the peer's reciprocal close_notify is
                // authenticated. Every operation, including alert emission,
                // remains under the caller's one absolute deadline.
                loop {
                    let next_timer = match poll_engine(engine, None, pump_state, poll_buffer)? {
                        EnginePoll::Wait(next_timer) => next_timer,
                        EnginePoll::PrepareCloseNotify => {
                            flush_outbound(io, pump_state).await?;
                            io.prepare_close_notify(deadline).await?;
                            continue;
                        }
                        EnginePoll::InstallEpochKey(_)
                        | EnginePoll::PrepareChangeCipherSpec
                        | EnginePoll::PrepareEpoch => {
                            return Err(DiameterTlsError::Transport);
                        }
                    };
                    flush_outbound(io, pump_state).await?;
                    if !pump_state.inbound.is_empty() {
                        return Err(DiameterTlsError::Transport);
                    }
                    if pump_state.peer_closed {
                        return Ok(());
                    }
                    match pump_wait(io, next_timer, deadline).await? {
                        PumpEvent::Deadline => {
                            return Err(DiameterTlsError::DeadlineExceeded);
                        }
                        PumpEvent::Timer => engine
                            .handle_timeout(std::time::Instant::now())
                            .map_err(|_| DiameterTlsError::Transport)?,
                        PumpEvent::Message(None) => {
                            return Err(DiameterTlsError::Transport);
                        }
                        PumpEvent::Message(Some(message)) => {
                            let record = validate_received_dtls_record(&message)?;
                            engine
                                .handle_packet(record)
                                .map_err(|_| DiameterTlsError::Transport)?;
                        }
                    }
                }
            };
            close_error = match tokio::time::timeout_at(deadline, close_protocol).await {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(error),
                Err(_) => Some(DiameterTlsError::DeadlineExceeded),
            };
        }
        poison_association(
            &mut self.session,
            self.generation,
            &mut self.closed,
            &*self.close,
        );
        match close_error {
            Some(error) => Err(error),
            None => Ok(self.session),
        }
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
        loop {
            match poll_engine(engine, None, pump_state, poll_buffer)? {
                EnginePoll::Wait(_) => break,
                EnginePoll::PrepareCloseNotify => {
                    flush_outbound(io, pump_state).await?;
                    io.prepare_close_notify(deadline).await?;
                }
                EnginePoll::InstallEpochKey(_)
                | EnginePoll::PrepareChangeCipherSpec
                | EnginePoll::PrepareEpoch => {
                    return Err(DiameterTlsError::Transport);
                }
            }
        }
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
    tokio::time::timeout_at(
        deadline,
        pump_until_inbound(engine, io, pump_state, poll_buffer, deadline),
    )
    .await
    .map_err(|_| DiameterTlsError::DeadlineExceeded)??;
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

    fn classic_dtls_record(payload: &[u8]) -> Bytes {
        let payload_len = u16::try_from(payload.len()).expect("test record length");
        let mut record = vec![0_u8; DTLS_RECORD_HEADER_BYTES];
        record[0] = 23;
        record[1..3].copy_from_slice(&[0xfe, 0xfd]);
        record[11..13].copy_from_slice(&payload_len.to_be_bytes());
        record.extend_from_slice(payload);
        Bytes::from(record)
    }

    #[test]
    fn policy_rejects_empty_cipher_set() {
        let policy = DtlsSctpPolicy::default();
        assert_eq!(
            policy.with_allowed_ciphers(&[]),
            Err(DiameterTlsPolicyError::EmptyCipherSet)
        );
    }

    #[test]
    fn kernel_receive_queue_capacity_is_finite_and_boundary_checked() {
        assert_eq!(
            validate_kernel_receive_queue_capacity(
                MIN_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES.saturating_sub(1)
            ),
            Err(DiameterTlsError::SctpReceiveQueueCapacityInvalid)
        );
        assert!(
            validate_kernel_receive_queue_capacity(MIN_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES).is_ok()
        );
        assert!(
            validate_kernel_receive_queue_capacity(MAX_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES).is_ok()
        );
        assert_eq!(
            validate_kernel_receive_queue_capacity(
                MAX_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES.saturating_add(1)
            ),
            Err(DiameterTlsError::SctpReceiveQueueCapacityInvalid)
        );
    }

    #[test]
    fn engine_poll_buffer_growth_is_bounded_by_the_record_contract() {
        let mut buffer = vec![0_u8; 16];
        assert_eq!(
            grow_engine_poll_buffer(&mut buffer, 16),
            Err(DiameterTlsError::TlsHandshake)
        );
        assert_eq!(
            grow_engine_poll_buffer(&mut buffer, MAX_DTLS_SCTP_RECORD_BYTES + 1),
            Err(DiameterTlsError::TlsHandshake)
        );
        grow_engine_poll_buffer(&mut buffer, MAX_DTLS_SCTP_RECORD_BYTES)
            .expect("grow to exact record ceiling");
        assert_eq!(buffer.len(), MAX_DTLS_SCTP_RECORD_BYTES);
    }

    #[test]
    fn local_certificate_chain_count_is_bounded_before_engine_custody() {
        assert_eq!(
            validate_dtls_certificate_chain_bounds(&[]),
            Err(DiameterTlsError::MaterialNotAdmitted)
        );
        let maximum: Vec<CertificateDer<'static>> = (0..MAX_DTLS_PEER_CERTIFICATES)
            .map(|_| CertificateDer::from(vec![1_u8]))
            .collect();
        assert!(validate_dtls_certificate_chain_bounds(&maximum).is_ok());
        let too_many: Vec<CertificateDer<'static>> = (0..=MAX_DTLS_PEER_CERTIFICATES)
            .map(|_| CertificateDer::from(vec![1_u8]))
            .collect();
        assert_eq!(
            validate_dtls_certificate_chain_bounds(&too_many),
            Err(DiameterTlsError::MaterialNotAdmitted)
        );
    }

    #[test]
    fn local_certificate_size_is_bounded_before_engine_custody() {
        assert_eq!(
            validate_dtls_certificate_chain_bounds(&[CertificateDer::from(Vec::new())]),
            Err(DiameterTlsError::MaterialNotAdmitted)
        );
        assert!(
            validate_dtls_certificate_chain_bounds(&[CertificateDer::from(vec![
            1_u8;
            MAX_DTLS_PEER_CERTIFICATE_BYTES
        ])])
            .is_ok()
        );
        assert_eq!(
            validate_dtls_certificate_chain_bounds(&[CertificateDer::from(vec![
                1_u8;
                MAX_DTLS_PEER_CERTIFICATE_BYTES
                    + 1
            ])]),
            Err(DiameterTlsError::MaterialNotAdmitted)
        );
    }

    #[test]
    fn local_certificate_chain_aggregate_is_bounded_before_engine_custody() {
        let exact: Vec<CertificateDer<'static>> = (0..4)
            .map(|_| CertificateDer::from(vec![1_u8; MAX_DTLS_PEER_CERTIFICATE_BYTES]))
            .collect();
        assert_eq!(
            exact
                .iter()
                .map(|certificate| certificate.len())
                .sum::<usize>(),
            MAX_DTLS_PEER_CERTIFICATE_CHAIN_BYTES
        );
        assert!(validate_dtls_certificate_chain_bounds(&exact).is_ok());

        let mut too_large = exact;
        too_large.push(CertificateDer::from(vec![1_u8]));
        assert_eq!(
            validate_dtls_certificate_chain_bounds(&too_large),
            Err(DiameterTlsError::MaterialNotAdmitted)
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
    fn policy_defaults_to_rfc6083_dtls12() {
        let policy = DtlsSctpPolicy::default();
        assert_eq!(
            policy.allowed_ciphers().collect::<Vec<_>>(),
            DtlsSctpCipher::ALL
        );
        assert_eq!(
            DtlsSctpPolicy::dtls13(policy.frame_limits()),
            Err(DiameterTlsPolicyError::Dtls13OverSctpUnavailable)
        );
    }

    #[test]
    fn policy_ignores_process_global_crypto_provider_replacement() {
        let mut unusable_global = dimpl::crypto::rust_crypto::default_provider();
        unusable_global.cipher_suites = &[];
        unusable_global.dtls13_cipher_suites = &[];
        dimpl::crypto::CryptoProvider::install_default(unusable_global)
            .expect("no prior dimpl default provider in this test process");

        let config = DtlsSctpPolicy::default()
            .engine_config()
            .expect("Diameter binds the audited RustCrypto provider explicitly");
        assert_eq!(
            config.dtls12_cipher_suites().count(),
            DtlsSctpCipher::ALL.len()
        );
        assert_eq!(config.dtls13_cipher_suites().count(), 0);
    }

    #[test]
    fn policy_rejects_zero_connection_age() {
        assert_eq!(
            DtlsSctpPolicy::default().with_maximum_connection_age(Duration::ZERO),
            Err(DiameterTlsPolicyError::InvalidConnectionAge)
        );
    }

    #[test]
    fn received_record_requires_complete_ordered_stream_zero_metadata() {
        let record = classic_dtls_record(b"ciphertext");
        let valid = SctpUserMessage::new(
            record.clone(),
            DIAMETER_DTLS_SCTP_PPID,
            DIAMETER_DTLS_SCTP_STREAM,
            SctpDeliveryOrder::Ordered,
            false,
            false,
            false,
        );
        assert_eq!(
            validate_received_dtls_record(&valid).expect("valid record"),
            record.as_ref()
        );

        for invalid in [
            SctpUserMessage::new(
                record.clone(),
                DIAMETER_DTLS_SCTP_PPID,
                1,
                SctpDeliveryOrder::Ordered,
                false,
                false,
                false,
            ),
            SctpUserMessage::new(
                record.clone(),
                DIAMETER_DTLS_SCTP_PPID,
                DIAMETER_DTLS_SCTP_STREAM,
                SctpDeliveryOrder::Unordered,
                false,
                false,
                false,
            ),
            SctpUserMessage::new(
                record.clone(),
                DIAMETER_DTLS_SCTP_PPID,
                DIAMETER_DTLS_SCTP_STREAM,
                SctpDeliveryOrder::Ordered,
                true,
                false,
                false,
            ),
            SctpUserMessage::new(
                record.clone(),
                DIAMETER_DTLS_SCTP_PPID,
                DIAMETER_DTLS_SCTP_STREAM,
                SctpDeliveryOrder::Ordered,
                false,
                true,
                false,
            ),
            SctpUserMessage::new(
                record.clone(),
                DIAMETER_DTLS_SCTP_PPID,
                DIAMETER_DTLS_SCTP_STREAM,
                SctpDeliveryOrder::Ordered,
                false,
                false,
                true,
            ),
        ] {
            assert_eq!(
                validate_received_dtls_record(&invalid),
                Err(DiameterTlsError::Transport)
            );
        }
    }

    #[test]
    fn received_record_rejects_foreign_ppid_coalescing_and_oversize() {
        let record = classic_dtls_record(b"ciphertext");
        let foreign = SctpUserMessage::ordered_record(record.clone(), 46);
        assert_eq!(
            validate_received_dtls_record(&foreign),
            Err(DiameterTlsError::CleartextInput)
        );

        let mut coalesced = record.to_vec();
        coalesced.extend_from_slice(&record);
        let coalesced =
            SctpUserMessage::ordered_record(Bytes::from(coalesced), DIAMETER_DTLS_SCTP_PPID);
        assert_eq!(
            validate_received_dtls_record(&coalesced),
            Err(DiameterTlsError::Transport)
        );

        let oversized = SctpUserMessage::ordered_record(
            Bytes::from(vec![0_u8; MAX_DTLS_SCTP_RECORD_BYTES + 1]),
            DIAMETER_DTLS_SCTP_PPID,
        );
        assert_eq!(
            validate_received_dtls_record(&oversized),
            Err(DiameterTlsError::Transport)
        );
    }

    #[test]
    fn outbound_record_requires_one_complete_bounded_record() {
        let record = classic_dtls_record(b"ciphertext");
        assert_eq!(validate_outbound_dtls_record(&record), Ok(()));
        assert_eq!(
            validate_outbound_dtls_record(b"not-a-record"),
            Err(DiameterTlsError::Transport)
        );

        let mut coalesced = record.to_vec();
        coalesced.extend_from_slice(&record);
        assert_eq!(
            validate_outbound_dtls_record(&coalesced),
            Err(DiameterTlsError::Transport)
        );
        assert_eq!(
            validate_outbound_dtls_record(&vec![0_u8; MAX_DTLS_SCTP_RECORD_BYTES + 1]),
            Err(DiameterTlsError::Transport)
        );
    }

    #[tokio::test]
    async fn in_memory_link_enforces_close_and_records_ppid() {
        let (mut a, mut b, log) = in_memory_sctp_link(4);
        a.begin_direct_dtls().expect("bind direct sender");
        b.begin_direct_dtls().expect("bind direct receiver");
        let record = classic_dtls_record(b"dtls-bytes");
        a.send_dtls_record(&record).await.expect("send");
        let received = b.receive_message().await.expect("receive").expect("open");
        assert_eq!(received.ppid(), DIAMETER_DTLS_SCTP_PPID);
        assert_eq!(received.payload(), record.as_ref());
        assert_eq!(
            log.records(),
            vec![SctpWireRecord {
                a_to_b: true,
                ppid: DIAMETER_DTLS_SCTP_PPID,
                payload_bytes: DTLS_RECORD_HEADER_BYTES + 10,
                auth_key_id: 0,
                record_header: Some(
                    record[..DTLS_RECORD_HEADER_BYTES]
                        .try_into()
                        .expect("header")
                ),
            }]
        );
        a.close_handle().close();
        assert_eq!(b.receive_message().await.expect("closed"), None);
        assert_eq!(
            a.send_dtls_record(&classic_dtls_record(b"late")).await,
            Err(DiameterTlsError::Transport)
        );
    }

    #[tokio::test]
    async fn in_memory_link_injects_raw_cleartext() {
        let (mut a, mut b, log) = in_memory_sctp_link(4);
        b.begin_direct_dtls().expect("bind direct receiver");
        a.send_raw_message(0, Bytes::from_static(b"clear"))
            .await
            .expect("inject");
        let received = b.receive_message().await.expect("receive").expect("open");
        assert_eq!(received.ppid(), 0);
        assert_eq!(log.records()[0].ppid, 0);
    }
}
