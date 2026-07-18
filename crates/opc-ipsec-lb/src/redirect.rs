//! Authenticated, replay-protected cross-node ingress redirect primitives.
//!
//! Redirect frames carry only the original ingress IP packet, its canonical
//! [`SessionOwnershipKey`], public fencing metadata, and a digest of the
//! authenticated sender identity. They never carry IKE/ESP SA key material.
//! Protection keys are private implementation details derived exclusively by
//! the mTLS exporter bootstrap in this module; there is no public raw-key
//! constructor.
//!
//! A bounded endpoint owns every admitted operation after
//! [`IngressRedirectEndpoint::begin_redirect`] or
//! [`IngressRedirectEndpoint::begin_forward`] returns. It retries the exact
//! sealed datagram under one absolute deadline and distinguishes proven-not-sent,
//! authenticated-receipt, and unknown-delivery outcomes. Receipt-cache state is
//! committed before bounded application-queue publication and is never evicted
//! while live. Every receive authenticates before inspecting packet metadata,
//! reclassifies the original packet, and requires a fresh exact fenced-owner
//! lookup both before admission and at dequeue. A one-time opaque forwardable
//! capability preserves authenticated hop state so product routing cannot
//! inspect or accidentally restart a cycle at hop one.
//!
//! Certificate/trust rotation performs another full mTLS handshake, stages a
//! receive epoch, and acknowledges activation before retiring the prior epoch.
//! Authentication is always bounded by certificate expiry and maximum age.
//! Ambiguous rotation state is retained only for fresh authenticated
//! reconciliation; ambiguous initial installation returns no usable session.
//! One peer session is permanently consumed by exactly one endpoint so receipts
//! cannot be consumed by another endpoint's independent pending map. Endpoint
//! shutdown drains admitted work and cannot be cancelled by dropping one waiter.
//! The Linux UDP adapter enforces non-fragmenting path-MTU discovery and reports
//! a shrinking ceiling through the mandatory packet-too-big boundary.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU8, NonZeroUsize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, Key, KeyInit, Nonce, Payload};
use aes_gcm::Aes256Gcm;
use opc_ipsec_lb_ebpf_common::{
    IngressRedirectFrameHeader, IngressRedirectFrameKind, IngressRedirectHeaderError,
    INGRESS_REDIRECT_HEADER_LEN, INGRESS_REDIRECT_OWNERSHIP_KEY_MAX_LEN,
    INGRESS_REDIRECT_SENDER_DIGEST_LEN,
};
pub use opc_ipsec_lb_ebpf_common::{IngressRedirectReceiptCode, IngressRedirectSecurityMode};
use opc_session_store::{
    Clock, FencedOwnershipCache, FencedOwnershipCacheLookup, FencedOwnershipGeneration,
    FencedOwnershipKey, OwnerId,
};
use opc_tls::{TlsAdmittedConnection, TlsMaterialEpoch};
use opc_types::Timestamp;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{classify_keyless_ingress_packet, RoutingDomainTag, SessionOwnershipKey};

mod control;
mod hmac_sha2;
mod transport;
pub use control::{
    establish_ingress_redirect_client, establish_ingress_redirect_server,
    ingress_redirect_client_tls_config, ingress_redirect_server_tls_config,
    reconcile_ingress_redirect_client, reconcile_ingress_redirect_server,
    rotate_ingress_redirect_client, rotate_ingress_redirect_server, IngressRedirectPeerExpectation,
    IngressRedirectPeerManifest, INGRESS_REDIRECT_CONTROL_ALPN,
};
use hmac_sha2::hmac_sha2_256;
pub use transport::{
    ForwardableIngressRedirectPacket, InMemoryIngressRedirectDatagram, IngressRedirectDatagram,
    IngressRedirectDatagramError, IngressRedirectDeliveryReceiver, IngressRedirectEndpoint,
    IngressRedirectEndpointMetricsSnapshot, IngressRedirectInboundOutcome,
    IngressRedirectNotSentReason, IngressRedirectOperation, IngressRedirectOperationOutcome,
    IngressRedirectPacketTooBigEvent, IngressRedirectPacketTooBigReportError,
    IngressRedirectPacketTooBigReporter, RejectedIngressRedirectPacket, UdpIngressRedirectDatagram,
};

const IPV4_HEADER_BYTES: usize = 20;
const IPV6_HEADER_BYTES: usize = 40;
const UDP_HEADER_BYTES: usize = 8;
const MIN_STEERING_PATH_MTU: u16 = 1_280;
const MAX_REPLAY_WINDOW: u16 = 4_096;
const MAX_QUEUE_PACKETS: usize = 65_536;
const MAX_QUEUE_BYTES: usize = 256 * 1024 * 1024;
const MAX_RECEIPT_CACHE_ENTRIES: usize = 1_048_576;
const AES_GCM_MAX_PROTECTED_FRAMES_PER_DIRECTIONAL_EPOCH: u64 = 1 << 23;
const AES_GCM_PROACTIVE_FRAME_ROTATION_HEADROOM: u64 = 1 << 20;
const AES_GCM_MAX_FAILED_AUTHENTICATIONS_PER_RECEIVE_KEY: u64 = 1 << 36;
const AES_GCM_FAILED_AUTHENTICATION_REAUTH_THRESHOLD: u64 =
    AES_GCM_MAX_FAILED_AUTHENTICATIONS_PER_RECEIVE_KEY * 3 / 4;
const MAX_REDIRECT_RETRIES: u8 = 8;
const MAX_REDIRECT_ROUTING_DOMAINS: usize = 256;
const MAX_ROTATION_OVERLAP: Duration = Duration::from_secs(10 * 60);
const MIN_ROTATION_OVERLAP: Duration = Duration::from_secs(5);
const MAX_RECEIPT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_AUTHENTICATION_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const ROTATION_STAGING_TIMEOUT: Duration = Duration::from_secs(45);
const ROTATION_RECONCILIATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Default authenticated ingress redirect protection.
pub const DEFAULT_INGRESS_REDIRECT_SECURITY_MODE: IngressRedirectSecurityMode =
    IngressRedirectSecurityMode::Aes256Gcm;

/// Fixed-width protection epoch derived from one admitted mTLS connection.
///
/// Epochs are identifiers, not keys. Construction is intentionally private so
/// an executable peer session can originate only from the authenticated TLS
/// exporter boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IngressRedirectProtectionEpoch(u64);

impl IngressRedirectProtectionEpoch {
    /// Return the on-wire epoch identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Bounded production profile for one authenticated redirect peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressRedirectProfile {
    security_mode: IngressRedirectSecurityMode,
    steering_path_mtu: NonZeroU16,
    hop_limit: NonZeroU8,
    replay_window: NonZeroU16,
    rotation_overlap: Duration,
    queue_packets: NonZeroUsize,
    queue_bytes: NonZeroUsize,
    receipt_cache_entries: NonZeroUsize,
    receipt_timeout: Duration,
    max_retries: u8,
    maximum_authentication_age: Duration,
}

impl IngressRedirectProfile {
    /// Construct the default confidential profile for one steering-path MTU.
    ///
    /// `steering_path_mtu` is the complete outer IP packet MTU. The SDK
    /// subtracts the outer IP and UDP headers, the fixed redirect header, the
    /// exact canonical-key width, and the negotiated authentication tag before
    /// admitting an original packet.
    pub fn production(steering_path_mtu: u16) -> Result<Self, IngressRedirectConfigError> {
        let steering_path_mtu =
            NonZeroU16::new(steering_path_mtu).ok_or(IngressRedirectConfigError::InvalidPathMtu)?;
        let profile = Self {
            security_mode: DEFAULT_INGRESS_REDIRECT_SECURITY_MODE,
            steering_path_mtu,
            hop_limit: NonZeroU8::new(4).ok_or(IngressRedirectConfigError::InvalidHopLimit)?,
            replay_window: NonZeroU16::new(1_024)
                .ok_or(IngressRedirectConfigError::InvalidReplayWindow)?,
            rotation_overlap: Duration::from_secs(60),
            queue_packets: NonZeroUsize::new(1_024)
                .ok_or(IngressRedirectConfigError::InvalidQueueLimits)?,
            queue_bytes: NonZeroUsize::new(16 * 1024 * 1024)
                .ok_or(IngressRedirectConfigError::InvalidQueueLimits)?,
            receipt_cache_entries: NonZeroUsize::new(65_536)
                .ok_or(IngressRedirectConfigError::InvalidReceiptCache)?,
            receipt_timeout: Duration::from_millis(250),
            max_retries: 2,
            maximum_authentication_age: Duration::from_secs(15 * 60),
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Select confidentiality or the explicit integrity-only deployment mode.
    #[must_use]
    pub fn with_security_mode(mut self, mode: IngressRedirectSecurityMode) -> Self {
        self.security_mode = mode;
        self
    }

    /// Select a redirect hop bound of at least two.
    ///
    /// The first redirect is stamped as hop one. A receiver rejects a packet
    /// when the authenticated count reaches the bound, so two is the smallest
    /// profile that can deliver one redirected packet.
    pub fn with_hop_limit(mut self, limit: u8) -> Result<Self, IngressRedirectConfigError> {
        self.hop_limit =
            NonZeroU8::new(limit).ok_or(IngressRedirectConfigError::InvalidHopLimit)?;
        self.validate()?;
        Ok(self)
    }

    /// Select a bounded out-of-order replay window.
    pub fn with_replay_window(mut self, width: u16) -> Result<Self, IngressRedirectConfigError> {
        self.replay_window =
            NonZeroU16::new(width).ok_or(IngressRedirectConfigError::InvalidReplayWindow)?;
        self.validate()?;
        Ok(self)
    }

    /// Select the current-plus-previous epoch overlap.
    pub fn with_rotation_overlap(
        mut self,
        overlap: Duration,
    ) -> Result<Self, IngressRedirectConfigError> {
        self.rotation_overlap = overlap;
        self.validate()?;
        Ok(self)
    }

    /// Select exact packet and aggregate-byte queue ceilings.
    pub fn with_queue_limits(
        mut self,
        packets: usize,
        bytes: usize,
    ) -> Result<Self, IngressRedirectConfigError> {
        self.queue_packets =
            NonZeroUsize::new(packets).ok_or(IngressRedirectConfigError::InvalidQueueLimits)?;
        self.queue_bytes =
            NonZeroUsize::new(bytes).ok_or(IngressRedirectConfigError::InvalidQueueLimits)?;
        self.validate()?;
        Ok(self)
    }

    /// Select the maximum number of exact committed receipts retained per peer.
    ///
    /// Every entry is retained for [`Self::receipt_retry_horizon`]. The
    /// sustainable unique-frame rate is therefore bounded by
    /// `entries / retry_horizon_seconds`; bursts cannot exceed `entries` until
    /// earlier receipts expire. Saturation sheds a new frame before replay or
    /// delivery state advances.
    pub fn with_receipt_cache_entries(
        mut self,
        entries: usize,
    ) -> Result<Self, IngressRedirectConfigError> {
        self.receipt_cache_entries =
            NonZeroUsize::new(entries).ok_or(IngressRedirectConfigError::InvalidReceiptCache)?;
        self.validate()?;
        Ok(self)
    }

    /// Select the exact receipt deadline and retry count.
    pub fn with_receipt_policy(
        mut self,
        timeout: Duration,
        max_retries: u8,
    ) -> Result<Self, IngressRedirectConfigError> {
        self.receipt_timeout = timeout;
        self.max_retries = max_retries;
        self.validate()?;
        Ok(self)
    }

    /// Bound how long one completed mTLS authentication can authorize packet
    /// protection, even when both certificate chains live longer.
    pub fn with_maximum_authentication_age(
        mut self,
        maximum_age: Duration,
    ) -> Result<Self, IngressRedirectConfigError> {
        self.maximum_authentication_age = maximum_age;
        self.validate()?;
        Ok(self)
    }

    /// Negotiated frame protection.
    #[must_use]
    pub const fn security_mode(self) -> IngressRedirectSecurityMode {
        self.security_mode
    }

    /// Complete outer steering-path IP MTU.
    #[must_use]
    pub const fn steering_path_mtu(self) -> u16 {
        self.steering_path_mtu.get()
    }

    /// Maximum permitted redirect count. The first redirect is count one.
    #[must_use]
    pub const fn hop_limit(self) -> u8 {
        self.hop_limit.get()
    }

    /// Out-of-order replay window width.
    #[must_use]
    pub const fn replay_window(self) -> u16 {
        self.replay_window.get()
    }

    /// Previous receive-epoch overlap after a successful rotation.
    #[must_use]
    pub const fn rotation_overlap(self) -> Duration {
        self.rotation_overlap
    }

    /// Maximum queued packets in either bounded endpoint queue.
    #[must_use]
    pub const fn queue_packets(self) -> usize {
        self.queue_packets.get()
    }

    /// Maximum aggregate original-packet bytes in either bounded endpoint queue.
    #[must_use]
    pub const fn queue_bytes(self) -> usize {
        self.queue_bytes.get()
    }

    /// Maximum exact committed receipts retained for this peer.
    ///
    /// The production default is 65,536 entries. With the default 750 ms retry
    /// horizon this supports at least 87,381 unique frames per second at steady
    /// state, subject to queue, CPU, and transport limits.
    #[must_use]
    pub const fn receipt_cache_entries(self) -> usize {
        self.receipt_cache_entries.get()
    }

    /// Deadline for one authenticated receipt attempt.
    #[must_use]
    pub const fn receipt_timeout(self) -> Duration {
        self.receipt_timeout
    }

    /// Number of exact-frame retries after the first send.
    #[must_use]
    pub const fn max_retries(self) -> u8 {
        self.max_retries
    }

    /// Complete absolute sender retry horizon and receipt retention duration.
    #[must_use]
    pub fn receipt_retry_horizon(self) -> Duration {
        self.receipt_timeout
            .checked_mul(u32::from(self.max_retries).saturating_add(1))
            .unwrap_or(Duration::MAX)
    }

    /// Maximum lifetime of one exporter epoch after mTLS admission.
    #[must_use]
    pub const fn maximum_authentication_age(self) -> Duration {
        self.maximum_authentication_age
    }

    fn validate(self) -> Result<(), IngressRedirectConfigError> {
        if self.steering_path_mtu.get() < MIN_STEERING_PATH_MTU {
            return Err(IngressRedirectConfigError::InvalidPathMtu);
        }
        if self.hop_limit.get() < 2 {
            return Err(IngressRedirectConfigError::InvalidHopLimit);
        }
        if self.replay_window.get() > MAX_REPLAY_WINDOW {
            return Err(IngressRedirectConfigError::InvalidReplayWindow);
        }
        if self.rotation_overlap < MIN_ROTATION_OVERLAP
            || self.rotation_overlap > MAX_ROTATION_OVERLAP
        {
            return Err(IngressRedirectConfigError::InvalidRotationOverlap);
        }
        if !self
            .rotation_overlap
            .subsec_nanos()
            .is_multiple_of(1_000_000)
        {
            return Err(IngressRedirectConfigError::InvalidRotationOverlap);
        }
        if self.queue_packets.get() > MAX_QUEUE_PACKETS || self.queue_bytes.get() > MAX_QUEUE_BYTES
        {
            return Err(IngressRedirectConfigError::InvalidQueueLimits);
        }
        if self.receipt_cache_entries.get() < self.queue_packets.get()
            || self.receipt_cache_entries.get() > MAX_RECEIPT_CACHE_ENTRIES
        {
            return Err(IngressRedirectConfigError::InvalidReceiptCache);
        }
        if self.receipt_timeout.is_zero()
            || self.receipt_timeout > MAX_RECEIPT_TIMEOUT
            || !self
                .receipt_timeout
                .subsec_nanos()
                .is_multiple_of(1_000_000)
            || self.max_retries > MAX_REDIRECT_RETRIES
        {
            return Err(IngressRedirectConfigError::InvalidReceiptPolicy);
        }
        let receipt_attempts = u32::from(self.max_retries).saturating_add(1);
        if self
            .receipt_timeout
            .checked_mul(receipt_attempts)
            .is_none_or(|retry_horizon| self.rotation_overlap < retry_horizon)
        {
            return Err(IngressRedirectConfigError::InvalidRotationOverlap);
        }
        if self.maximum_authentication_age.is_zero()
            || self.maximum_authentication_age > MAX_AUTHENTICATION_AGE
            || self.maximum_authentication_age
                <= self.rotation_overlap.max(ROTATION_STAGING_TIMEOUT)
            || !self
                .maximum_authentication_age
                .subsec_nanos()
                .is_multiple_of(1_000_000)
        {
            return Err(IngressRedirectConfigError::InvalidAuthenticationAge);
        }
        Ok(())
    }
}

/// Stable, redaction-safe profile construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum IngressRedirectConfigError {
    /// The complete outer path MTU is below the production minimum.
    #[error("invalid ingress redirect steering-path MTU")]
    InvalidPathMtu,
    /// The redirect hop limit was below two.
    #[error("invalid ingress redirect hop limit")]
    InvalidHopLimit,
    /// The replay window was zero or exceeded its fixed bound.
    #[error("invalid ingress redirect replay window")]
    InvalidReplayWindow,
    /// The previous-epoch overlap was zero or exceeded its fixed bound.
    #[error("invalid ingress redirect rotation overlap")]
    InvalidRotationOverlap,
    /// Packet or aggregate-byte queue limits were zero or too large.
    #[error("invalid ingress redirect queue limits")]
    InvalidQueueLimits,
    /// Exact receipt-cache capacity was zero, below the packet queue, or too large.
    #[error("invalid ingress redirect receipt cache")]
    InvalidReceiptCache,
    /// Receipt timeout or retry count was outside its fixed bound.
    #[error("invalid ingress redirect receipt policy")]
    InvalidReceiptPolicy,
    /// Maximum authentication age was zero, too large, or not millisecond-exact.
    #[error("invalid ingress redirect maximum authentication age")]
    InvalidAuthenticationAge,
}

impl IngressRedirectConfigError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPathMtu => "redirect_config_invalid_path_mtu",
            Self::InvalidHopLimit => "redirect_config_invalid_hop_limit",
            Self::InvalidReplayWindow => "redirect_config_invalid_replay_window",
            Self::InvalidRotationOverlap => "redirect_config_invalid_rotation_overlap",
            Self::InvalidQueueLimits => "redirect_config_invalid_queue_limits",
            Self::InvalidReceiptCache => "redirect_config_invalid_receipt_cache",
            Self::InvalidReceiptPolicy => "redirect_config_invalid_receipt_policy",
            Self::InvalidAuthenticationAge => "redirect_config_invalid_authentication_age",
        }
    }
}

/// Exact MTU accounting for one peer address, key width, and protection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressRedirectMtuBudget {
    path_mtu: usize,
    outer_headers: usize,
    redirect_overhead: usize,
    maximum_original_packet: usize,
}

impl IngressRedirectMtuBudget {
    /// Calculate the full overhead for one peer and canonical ownership key.
    pub fn new(
        profile: IngressRedirectProfile,
        peer: IpAddr,
        ownership_key_len: usize,
    ) -> Result<Self, IngressRedirectError> {
        if ownership_key_len == 0 || ownership_key_len > INGRESS_REDIRECT_OWNERSHIP_KEY_MAX_LEN {
            return Err(IngressRedirectError::InvalidOwnershipKey);
        }
        let outer_headers = match peer {
            IpAddr::V4(_) => IPV4_HEADER_BYTES + UDP_HEADER_BYTES,
            IpAddr::V6(_) => IPV6_HEADER_BYTES + UDP_HEADER_BYTES,
        };
        let redirect_overhead = INGRESS_REDIRECT_HEADER_LEN
            .checked_add(ownership_key_len)
            .and_then(|value| value.checked_add(profile.security_mode.tag_len()))
            .ok_or(IngressRedirectError::PacketTooLarge)?;
        let path_mtu = usize::from(profile.steering_path_mtu.get());
        let maximum_original_packet = path_mtu
            .checked_sub(outer_headers)
            .and_then(|value| value.checked_sub(redirect_overhead))
            .ok_or(IngressRedirectError::PacketTooLarge)?;
        if maximum_original_packet == 0 {
            return Err(IngressRedirectError::PacketTooLarge);
        }
        Ok(Self {
            path_mtu,
            outer_headers,
            redirect_overhead,
            maximum_original_packet,
        })
    }

    /// Complete configured outer path MTU.
    #[must_use]
    pub const fn path_mtu(self) -> usize {
        self.path_mtu
    }

    /// Outer IP plus UDP header width.
    #[must_use]
    pub const fn outer_headers(self) -> usize {
        self.outer_headers
    }

    /// Redirect header, canonical key, and authentication-tag width.
    #[must_use]
    pub const fn redirect_overhead(self) -> usize {
        self.redirect_overhead
    }

    /// Largest original packet that fits without steering-layer fragmentation.
    #[must_use]
    pub const fn maximum_original_packet(self) -> usize {
        self.maximum_original_packet
    }

    /// Return whether the original packet fits the exact computed budget.
    #[must_use]
    pub const fn admits(self, packet_len: usize) -> bool {
        packet_len > 0 && packet_len <= self.maximum_original_packet
    }
}

/// Stable redaction-safe failure from frame, crypto, ownership, or transport handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum IngressRedirectError {
    /// Fixed header or exact frame length was malformed.
    #[error("malformed ingress redirect frame")]
    MalformedFrame,
    /// The unauthenticated wire mode differed from the mTLS-negotiated mode.
    #[error("ingress redirect protection mode mismatch")]
    ProtectionModeMismatch,
    /// The protection epoch is neither the current nor bounded previous epoch.
    #[error("unknown or retired ingress redirect protection epoch")]
    UnknownEpoch,
    /// The exporter epoch exceeded its certificate or authentication-age bound.
    #[error("ingress redirect authentication epoch expired")]
    AuthenticationExpired,
    /// Authentication failed; packet contents were not examined.
    #[error("ingress redirect authentication failed")]
    AuthenticationFailed,
    /// Authenticated sender digest did not match the mTLS peer.
    #[error("ingress redirect sender identity mismatch")]
    SenderIdentityMismatch,
    /// A sequence was duplicated or older than the replay window.
    #[error("ingress redirect replay rejected")]
    ReplayRejected,
    /// The monotonic send sequence was exhausted.
    #[error("ingress redirect sequence exhausted")]
    SequenceExhausted,
    /// An AES-GCM directional epoch reached a mandatory usage bound.
    #[error("ingress redirect AES-GCM epoch usage exhausted")]
    AeadUsageExhausted,
    /// The authenticated wire hop bound differed from the negotiated profile.
    #[error("ingress redirect hop profile mismatch")]
    HopLimitMismatch,
    /// The frame reached its authenticated hop bound.
    #[error("ingress redirect hop limit reached")]
    HopLimitReached,
    /// The authenticated peer is not admitted for the carried routing domain.
    #[error("ingress redirect routing domain is not authorized")]
    RoutingDomainNotAuthorized,
    /// The committed fenced-ownership cache was not fresh.
    #[error("ingress redirect ownership view is stale")]
    OwnershipViewStale,
    /// A fresh committed view contains no record for the carried key.
    #[error("ingress redirect ownership record is missing")]
    OwnershipMissing,
    /// The authenticated receiver is not the current owner.
    #[error("ingress redirect receiver is not the fenced owner")]
    NotOwner,
    /// The sender's ownership generation was superseded.
    #[error("ingress redirect ownership generation is stale")]
    StaleOwnershipGeneration,
    /// The sender claimed an ownership generation newer than receiver evidence.
    #[error("ingress redirect ownership generation is unproven")]
    UnprovenOwnershipGeneration,
    /// Receiver classification did not exactly reproduce the carried key.
    #[error("ingress redirect classification mismatch")]
    ClassificationMismatch,
    /// A queued or forwarding capability no longer has the exact authority
    /// that existed when its authenticated receipt was committed.
    #[error("ingress redirect delivery capability is stale")]
    DeliveryCapabilityStale,
    /// Canonical ownership-key bytes were invalid.
    #[error("invalid ingress redirect ownership key")]
    InvalidOwnershipKey,
    /// No structurally present original packet was supplied.
    #[error("invalid empty ingress redirect original packet")]
    InvalidOriginalPacket,
    /// The original packet cannot fit the exact steering MTU budget.
    #[error("ingress redirect packet exceeds steering-path MTU")]
    PacketTooLarge,
    /// A bounded packet or aggregate-byte queue was full.
    #[error("ingress redirect queue is full")]
    QueueFull,
    /// The mandatory packet-too-big feedback hook failed.
    #[error("ingress redirect packet-too-big feedback failed")]
    PacketTooBigFeedbackFailed,
    /// The datagram adapter failed without exposing peer or packet data.
    #[error("ingress redirect transport failed")]
    TransportFailed,
    /// No authenticated receipt arrived within the bounded retry policy.
    #[error("ingress redirect receipt timed out")]
    ReceiptTimeout,
    /// Endpoint shutdown rejected or interrupted new work.
    #[error("ingress redirect endpoint is shutting down")]
    ShuttingDown,
    /// This authenticated peer session has already been consumed by an endpoint.
    ///
    /// Endpoint ownership is permanently one-shot. Shutdown, task failure, or
    /// dropping the endpoint never makes the same authenticated session safe to
    /// reuse; replacement requires a fresh authenticated control bootstrap.
    #[error("ingress redirect peer session has already been consumed")]
    EndpointAlreadyConsumed,
    /// The authenticated TLS control bootstrap failed closed.
    #[error("ingress redirect TLS bootstrap failed")]
    TlsBootstrapFailed,
    /// The manifest identity or owner did not match the authenticated peer.
    #[error("ingress redirect peer identity mismatch")]
    PeerIdentityMismatch,
    /// The bounded peer control manifest was invalid.
    #[error("invalid ingress redirect peer manifest")]
    InvalidPeerManifest,
    /// One peer may have installed the initial epoch, but acknowledgement was
    /// lost; the unreturned local session must be discarded and retried with
    /// a fresh full TLS bootstrap.
    #[error("ingress redirect initial installation outcome is unknown")]
    InitialOutcomeUnknown,
    /// A synchronization boundary was poisoned or unavailable.
    #[error("ingress redirect state is unavailable")]
    StateUnavailable,
    /// Another unactivated receive epoch is already staged.
    #[error("ingress redirect rotation is already staged")]
    RotationInProgress,
    /// The activation token does not name the currently staged epoch.
    #[error("ingress redirect rotation activation does not match staged epoch")]
    RotationNotStaged,
    /// Peer activation may have committed; pending/current state is retained
    /// for authenticated data-plane reconciliation rather than rolled back.
    #[error("ingress redirect rotation outcome is unknown")]
    RotationOutcomeUnknown,
}

impl IngressRedirectError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedFrame => "redirect_malformed_frame",
            Self::ProtectionModeMismatch => "redirect_protection_mode_mismatch",
            Self::UnknownEpoch => "redirect_unknown_epoch",
            Self::AuthenticationExpired => "redirect_authentication_expired",
            Self::AuthenticationFailed => "redirect_authentication_failed",
            Self::SenderIdentityMismatch => "redirect_sender_identity_mismatch",
            Self::ReplayRejected => "redirect_replay_rejected",
            Self::SequenceExhausted => "redirect_sequence_exhausted",
            Self::AeadUsageExhausted => "redirect_aead_usage_exhausted",
            Self::HopLimitMismatch => "redirect_hop_limit_mismatch",
            Self::HopLimitReached => "redirect_hop_limit_reached",
            Self::RoutingDomainNotAuthorized => "redirect_routing_domain_not_authorized",
            Self::OwnershipViewStale => "redirect_ownership_view_stale",
            Self::OwnershipMissing => "redirect_ownership_missing",
            Self::NotOwner => "redirect_not_owner",
            Self::StaleOwnershipGeneration => "redirect_stale_ownership_generation",
            Self::UnprovenOwnershipGeneration => "redirect_unproven_ownership_generation",
            Self::ClassificationMismatch => "redirect_classification_mismatch",
            Self::DeliveryCapabilityStale => "redirect_delivery_capability_stale",
            Self::InvalidOwnershipKey => "redirect_invalid_ownership_key",
            Self::InvalidOriginalPacket => "redirect_invalid_original_packet",
            Self::PacketTooLarge => "redirect_packet_too_large",
            Self::QueueFull => "redirect_queue_full",
            Self::PacketTooBigFeedbackFailed => "redirect_ptb_feedback_failed",
            Self::TransportFailed => "redirect_transport_failed",
            Self::ReceiptTimeout => "redirect_receipt_timeout",
            Self::ShuttingDown => "redirect_shutting_down",
            Self::EndpointAlreadyConsumed => "redirect_endpoint_already_consumed",
            Self::TlsBootstrapFailed => "redirect_tls_bootstrap_failed",
            Self::PeerIdentityMismatch => "redirect_peer_identity_mismatch",
            Self::InvalidPeerManifest => "redirect_invalid_peer_manifest",
            Self::InitialOutcomeUnknown => "redirect_initial_outcome_unknown",
            Self::StateUnavailable => "redirect_state_unavailable",
            Self::RotationInProgress => "redirect_rotation_in_progress",
            Self::RotationNotStaged => "redirect_rotation_not_staged",
            Self::RotationOutcomeUnknown => "redirect_rotation_outcome_unknown",
        }
    }
}

impl From<IngressRedirectHeaderError> for IngressRedirectError {
    fn from(_: IngressRedirectHeaderError) -> Self {
        Self::MalformedFrame
    }
}

/// Fixed-cardinality, redaction-safe peer-session metrics snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IngressRedirectMetricsSnapshot {
    /// Newly sealed data and receipt frames.
    pub frames_sealed: u64,
    /// Authenticated non-replayed frames.
    pub frames_authenticated: u64,
    /// Malformed or length-inconsistent frames.
    pub malformed_drops: u64,
    /// Wire protection modes that differed from the negotiated profile.
    pub mode_mismatch_drops: u64,
    /// Unknown or retired epochs.
    pub unknown_epoch_drops: u64,
    /// Current or overlapping exporter epochs past their hard auth deadline.
    pub authentication_expired_drops: u64,
    /// Cryptographic authentication failures.
    pub authentication_drops: u64,
    /// Authenticated sender digests that differed from the mTLS peer.
    pub sender_identity_drops: u64,
    /// Replayed or too-old frames.
    pub replay_drops: u64,
    /// Authenticated hop limits that differed from the peer profile.
    pub hop_profile_drops: u64,
    /// Hop-bound drops.
    pub hop_limit_drops: u64,
    /// Authenticated routing domains outside the peer manifest.
    pub routing_domain_drops: u64,
    /// Fail-closed stale committed ownership views.
    pub ownership_view_stale_drops: u64,
    /// Fresh committed ownership views with no record for the key.
    pub ownership_missing_drops: u64,
    /// Fresh records owned by another replica.
    pub not_owner_drops: u64,
    /// Sender generations older than the fresh current record.
    pub stale_generation_drops: u64,
    /// Sender generations ahead of the receiver's committed evidence.
    pub receiver_view_behind_drops: u64,
    /// Exact classification mismatches.
    pub classification_drops: u64,
    /// Authenticated frames carrying a non-canonical ownership key.
    pub invalid_ownership_key_drops: u64,
    /// Oversize original packets.
    pub oversize_drops: u64,
    /// Bounded queue rejections.
    pub queue_drops: u64,
    /// Original packets admitted to the bounded local delivery queue.
    pub delivery_admissions: u64,
    /// Original packets materialized after dequeue-time fence revalidation.
    pub delivered: u64,
    /// Queued capabilities rejected by dequeue-time lifetime/fence validation.
    pub delivery_capability_stale_drops: u64,
    /// New AES-GCM seals rejected at the per-epoch frame limit.
    pub aead_seal_budget_exhausted: u64,
    /// Successful AES-GCM opens rejected at the per-epoch frame limit.
    pub aead_open_budget_exhausted: u64,
    /// Receive epochs that crossed the fixed failed-auth reauthentication threshold.
    pub aead_failed_auth_reauth_signals: u64,
    /// Receive keys disabled after the failed-auth hard cap.
    pub aead_failed_auth_budget_exhausted: u64,
}

/// Redaction-safe lifecycle evidence for the current authenticated epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressRedirectAuthenticationStatus {
    epoch: IngressRedirectProtectionEpoch,
    local_material_epoch: TlsMaterialEpoch,
    authenticated_at: Timestamp,
    local_certificate_chain_expires_at: Timestamp,
    peer_certificate_chain_expires_at: Timestamp,
    hard_lifetime_remaining: Duration,
    reauthenticate_after: Duration,
}

impl IngressRedirectAuthenticationStatus {
    /// Current exporter protection epoch.
    #[must_use]
    pub const fn epoch(self) -> IngressRedirectProtectionEpoch {
        self.epoch
    }

    /// Coherent local certificate/key/trust material epoch used by TLS.
    #[must_use]
    pub const fn local_material_epoch(self) -> TlsMaterialEpoch {
        self.local_material_epoch
    }

    /// Wall-clock time at which application negotiation was admitted.
    #[must_use]
    pub const fn authenticated_at(self) -> Timestamp {
        self.authenticated_at
    }

    /// Earliest expiry in the local certificate chain used by TLS.
    #[must_use]
    pub const fn local_certificate_chain_expires_at(self) -> Timestamp {
        self.local_certificate_chain_expires_at
    }

    /// Earliest expiry in the authenticated peer certificate chain.
    #[must_use]
    pub const fn peer_certificate_chain_expires_at(self) -> Timestamp {
        self.peer_certificate_chain_expires_at
    }

    /// Time remaining until packet open/seal fails closed.
    #[must_use]
    pub const fn hard_lifetime_remaining(self) -> Duration {
        self.hard_lifetime_remaining
    }

    /// Time until the configured rotation-overlap lead begins.
    ///
    /// Zero means the consumer should establish and activate a fresh mTLS
    /// exporter epoch immediately, before the hard deadline.
    #[must_use]
    pub const fn reauthenticate_after(self) -> Duration {
        self.reauthenticate_after
    }
}

/// Fixed-cardinality AES-GCM usage evidence for proactive epoch rotation.
///
/// Data and receipt seals share the per-direction epoch budget. Peer opens and
/// known-epoch authentication failures have independent hard limits. Consumers
/// should replace the authenticated session whenever
/// [`Self::reauthentication_required`] becomes true; cryptographic operations
/// fail closed once a hard limit is exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressRedirectAeadUsageStatus {
    epoch: IngressRedirectProtectionEpoch,
    newly_protected_frames_remaining: Option<u64>,
    successful_peer_opens_remaining: Option<u64>,
    failed_authentications_remaining: Option<u64>,
    reauthentication_required: bool,
}

impl IngressRedirectAeadUsageStatus {
    /// Current exporter protection epoch.
    #[must_use]
    pub const fn epoch(self) -> IngressRedirectProtectionEpoch {
        self.epoch
    }

    /// Remaining new seals for AES-GCM, or `None` for HMAC mode.
    #[must_use]
    pub const fn newly_protected_frames_remaining(self) -> Option<u64> {
        self.newly_protected_frames_remaining
    }

    /// Remaining successful peer opens for AES-GCM, or `None` for HMAC mode.
    #[must_use]
    pub const fn successful_peer_opens_remaining(self) -> Option<u64> {
        self.successful_peer_opens_remaining
    }

    /// Remaining failed authentication attempts before key retirement.
    #[must_use]
    pub const fn failed_authentications_remaining(self) -> Option<u64> {
        self.failed_authentications_remaining
    }

    /// Whether the consumer must proactively establish a fresh mTLS epoch.
    #[must_use]
    pub const fn reauthentication_required(self) -> bool {
        self.reauthentication_required
    }
}

/// Redaction-safe epoch state for rotation recovery and operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressRedirectRotationStatus {
    current: IngressRedirectProtectionEpoch,
    pending_receive: Option<IngressRedirectProtectionEpoch>,
    previous_receive: Option<IngressRedirectProtectionEpoch>,
    pending_lifetime_remaining: Duration,
}

impl IngressRedirectRotationStatus {
    /// Epoch used for all newly sealed frames.
    #[must_use]
    pub const fn current(self) -> IngressRedirectProtectionEpoch {
        self.current
    }

    /// Receive-installed epoch awaiting authenticated peer activation proof.
    #[must_use]
    pub const fn pending_receive(self) -> Option<IngressRedirectProtectionEpoch> {
        self.pending_receive
    }

    /// Bounded prior receive epoch retained during overlap.
    #[must_use]
    pub const fn previous_receive(self) -> Option<IngressRedirectProtectionEpoch> {
        self.previous_receive
    }

    /// Remaining bounded lifetime of the pending receive epoch.
    #[must_use]
    pub const fn pending_lifetime_remaining(self) -> Duration {
        self.pending_lifetime_remaining
    }
}

#[derive(Default)]
struct IngressRedirectMetrics {
    frames_sealed: AtomicU64,
    frames_authenticated: AtomicU64,
    malformed_drops: AtomicU64,
    mode_mismatch_drops: AtomicU64,
    unknown_epoch_drops: AtomicU64,
    authentication_expired_drops: AtomicU64,
    authentication_drops: AtomicU64,
    sender_identity_drops: AtomicU64,
    replay_drops: AtomicU64,
    hop_profile_drops: AtomicU64,
    hop_limit_drops: AtomicU64,
    routing_domain_drops: AtomicU64,
    ownership_view_stale_drops: AtomicU64,
    ownership_missing_drops: AtomicU64,
    not_owner_drops: AtomicU64,
    stale_generation_drops: AtomicU64,
    receiver_view_behind_drops: AtomicU64,
    classification_drops: AtomicU64,
    invalid_ownership_key_drops: AtomicU64,
    oversize_drops: AtomicU64,
    queue_drops: AtomicU64,
    delivery_admissions: AtomicU64,
    delivered: AtomicU64,
    delivery_capability_stale_drops: AtomicU64,
    aead_seal_budget_exhausted: AtomicU64,
    aead_open_budget_exhausted: AtomicU64,
    aead_failed_auth_reauth_signals: AtomicU64,
    aead_failed_auth_budget_exhausted: AtomicU64,
}

impl IngressRedirectMetrics {
    fn snapshot(&self) -> IngressRedirectMetricsSnapshot {
        IngressRedirectMetricsSnapshot {
            frames_sealed: self.frames_sealed.load(Ordering::Relaxed),
            frames_authenticated: self.frames_authenticated.load(Ordering::Relaxed),
            malformed_drops: self.malformed_drops.load(Ordering::Relaxed),
            mode_mismatch_drops: self.mode_mismatch_drops.load(Ordering::Relaxed),
            unknown_epoch_drops: self.unknown_epoch_drops.load(Ordering::Relaxed),
            authentication_expired_drops: self.authentication_expired_drops.load(Ordering::Relaxed),
            authentication_drops: self.authentication_drops.load(Ordering::Relaxed),
            sender_identity_drops: self.sender_identity_drops.load(Ordering::Relaxed),
            replay_drops: self.replay_drops.load(Ordering::Relaxed),
            hop_profile_drops: self.hop_profile_drops.load(Ordering::Relaxed),
            hop_limit_drops: self.hop_limit_drops.load(Ordering::Relaxed),
            routing_domain_drops: self.routing_domain_drops.load(Ordering::Relaxed),
            ownership_view_stale_drops: self.ownership_view_stale_drops.load(Ordering::Relaxed),
            ownership_missing_drops: self.ownership_missing_drops.load(Ordering::Relaxed),
            not_owner_drops: self.not_owner_drops.load(Ordering::Relaxed),
            stale_generation_drops: self.stale_generation_drops.load(Ordering::Relaxed),
            receiver_view_behind_drops: self.receiver_view_behind_drops.load(Ordering::Relaxed),
            classification_drops: self.classification_drops.load(Ordering::Relaxed),
            invalid_ownership_key_drops: self.invalid_ownership_key_drops.load(Ordering::Relaxed),
            oversize_drops: self.oversize_drops.load(Ordering::Relaxed),
            queue_drops: self.queue_drops.load(Ordering::Relaxed),
            delivery_admissions: self.delivery_admissions.load(Ordering::Relaxed),
            delivered: self.delivered.load(Ordering::Relaxed),
            delivery_capability_stale_drops: self
                .delivery_capability_stale_drops
                .load(Ordering::Relaxed),
            aead_seal_budget_exhausted: self.aead_seal_budget_exhausted.load(Ordering::Relaxed),
            aead_open_budget_exhausted: self.aead_open_budget_exhausted.load(Ordering::Relaxed),
            aead_failed_auth_reauth_signals: self
                .aead_failed_auth_reauth_signals
                .load(Ordering::Relaxed),
            aead_failed_auth_budget_exhausted: self
                .aead_failed_auth_budget_exhausted
                .load(Ordering::Relaxed),
        }
    }

    fn record_queue_drop(&self) {
        increment(&self.queue_drops);
    }

    fn record_delivered(&self) {
        increment(&self.delivered);
    }

    fn record_delivery_admitted(&self) {
        increment(&self.delivery_admissions);
    }

    fn record_delivery_capability_stale(&self) {
        increment(&self.delivery_capability_stale_drops);
    }
}

fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

struct ReplayWindow {
    width: u64,
    highest: u64,
    accepted: BTreeSet<u64>,
}

impl ReplayWindow {
    fn new(width: NonZeroU16) -> Self {
        Self {
            width: u64::from(width.get()),
            highest: 0,
            accepted: BTreeSet::new(),
        }
    }

    fn accept(&mut self, sequence: u64) -> Result<(), IngressRedirectError> {
        if sequence == 0 {
            return Err(IngressRedirectError::ReplayRejected);
        }
        if self.highest != 0
            && sequence < self.highest
            && self.highest.saturating_sub(sequence) >= self.width
        {
            return Err(IngressRedirectError::ReplayRejected);
        }
        if !self.accepted.insert(sequence) {
            return Err(IngressRedirectError::ReplayRejected);
        }
        self.highest = self.highest.max(sequence);
        let oldest = self.highest.saturating_sub(self.width.saturating_sub(1));
        self.accepted = self.accepted.split_off(&oldest);
        Ok(())
    }
}

struct DirectionalEpoch {
    epoch: IngressRedirectProtectionEpoch,
    send_key: Zeroizing<[u8; 32]>,
    receive_key: Zeroizing<[u8; 32]>,
    send_nonce_prefix: [u8; 4],
    receive_nonce_prefix: [u8; 4],
    next_send_sequence: AtomicU64,
    replay: Mutex<ReplayWindow>,
    newly_sealed_frames: AtomicU64,
    successful_opened_frames: AtomicU64,
    failed_aead_authentications: AtomicU64,
    aead_reauth_signaled: AtomicBool,
    aead_frame_limit: AtomicU64,
    aead_failed_auth_limit: AtomicU64,
    aead_failed_auth_warning: AtomicU64,
    hard_authenticated_deadline: Instant,
    authentication_evidence: EpochAuthenticationEvidence,
}

enum EpochAuthenticationEvidence {
    Tls {
        local_admission: TlsAdmittedConnection,
        peer_certificate_chain_expires_at: Timestamp,
        authenticated_at: Timestamp,
    },
    #[cfg(test)]
    TestOnly,
}

impl fmt::Debug for DirectionalEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectionalEpoch")
            .field("epoch", &self.epoch)
            .field("send_key", &"[redacted]")
            .field("receive_key", &"[redacted]")
            .field("nonce_prefixes", &"[redacted]")
            .field("authentication_evidence", &"[redacted]")
            .finish_non_exhaustive()
    }
}

struct PreviousReceiveEpoch {
    epoch: Arc<DirectionalEpoch>,
    valid_until: Instant,
}

struct PendingReceiveEpoch {
    epoch: Arc<DirectionalEpoch>,
    valid_until: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReceiveEpochKind {
    Current,
    Pending,
    Previous,
}

struct SessionEpochState {
    current: Arc<DirectionalEpoch>,
    previous: Option<PreviousReceiveEpoch>,
    pending: Option<PendingReceiveEpoch>,
}

fn purge_expired_receive_epochs(state: &mut SessionEpochState, now: Instant) {
    if state.pending.as_ref().is_some_and(|pending| {
        now >= pending.valid_until || now >= pending.epoch.hard_authenticated_deadline
    }) {
        state.pending = None;
    }
    if state.previous.as_ref().is_some_and(|previous| {
        now >= previous.valid_until || now >= previous.epoch.hard_authenticated_deadline
    }) {
        state.previous = None;
    }
}

struct IngressRedirectControlOperationGuard<'a> {
    active: &'a AtomicBool,
}

impl Drop for IngressRedirectControlOperationGuard<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct IngressRedirectPendingRotation {
    epoch: IngressRedirectProtectionEpoch,
}

impl IngressRedirectPendingRotation {
    const fn epoch(&self) -> IngressRedirectProtectionEpoch {
        self.epoch
    }
}

/// Private authenticated crypto material produced by one mTLS control bootstrap.
struct IngressRedirectBootstrap {
    profile: IngressRedirectProfile,
    local_owner: OwnerId,
    peer_owner: OwnerId,
    local_sender_digest: [u8; INGRESS_REDIRECT_SENDER_DIGEST_LEN],
    peer_sender_digest: [u8; INGRESS_REDIRECT_SENDER_DIGEST_LEN],
    routing_domains: Arc<[RoutingDomainTag]>,
    local_udp_endpoint: SocketAddr,
    peer_udp_endpoint: SocketAddr,
    epoch: IngressRedirectProtectionEpoch,
    send_key: Zeroizing<[u8; 32]>,
    receive_key: Zeroizing<[u8; 32]>,
    send_nonce_prefix: [u8; 4],
    receive_nonce_prefix: [u8; 4],
    authentication_evidence: EpochAuthenticationEvidence,
    hard_authenticated_deadline: Instant,
}

impl fmt::Debug for IngressRedirectBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngressRedirectBootstrap")
            .field("profile", &self.profile)
            .field("local_owner", &"[redacted]")
            .field("peer_owner", &"[redacted]")
            .field("sender_digests", &"[redacted]")
            .field("udp_endpoints", &"[redacted]")
            .field("epoch", &self.epoch)
            .field("keys", &"[redacted]")
            .field("authentication_evidence", &"[redacted]")
            .finish()
    }
}

fn epoch_from_bootstrap(
    profile: IngressRedirectProfile,
    bootstrap: IngressRedirectBootstrap,
) -> DirectionalEpoch {
    DirectionalEpoch {
        epoch: bootstrap.epoch,
        send_key: bootstrap.send_key,
        receive_key: bootstrap.receive_key,
        send_nonce_prefix: bootstrap.send_nonce_prefix,
        receive_nonce_prefix: bootstrap.receive_nonce_prefix,
        next_send_sequence: AtomicU64::new(1),
        replay: Mutex::new(ReplayWindow::new(profile.replay_window)),
        newly_sealed_frames: AtomicU64::new(0),
        successful_opened_frames: AtomicU64::new(0),
        failed_aead_authentications: AtomicU64::new(0),
        aead_reauth_signaled: AtomicBool::new(false),
        aead_frame_limit: AtomicU64::new(AES_GCM_MAX_PROTECTED_FRAMES_PER_DIRECTIONAL_EPOCH),
        aead_failed_auth_limit: AtomicU64::new(AES_GCM_MAX_FAILED_AUTHENTICATIONS_PER_RECEIVE_KEY),
        aead_failed_auth_warning: AtomicU64::new(AES_GCM_FAILED_AUTHENTICATION_REAUTH_THRESHOLD),
        hard_authenticated_deadline: bootstrap.hard_authenticated_deadline,
        authentication_evidence: bootstrap.authentication_evidence,
    }
}

fn authenticated_epoch_deadline(
    monotonic_now: Instant,
    wall_now: Timestamp,
    local_certificate_chain_expires_at: Timestamp,
    peer_certificate_chain_expires_at: Timestamp,
    maximum_authentication_age: Duration,
) -> Result<Instant, IngressRedirectError> {
    let certificate_expiry =
        local_certificate_chain_expires_at.min(peer_certificate_chain_expires_at);
    let wall_now_nanos = wall_now.as_offset_datetime().unix_timestamp_nanos();
    let expiry_nanos = certificate_expiry
        .as_offset_datetime()
        .unix_timestamp_nanos();
    let maximum_age_nanos = i128::try_from(maximum_authentication_age.as_nanos())
        .map_err(|_| IngressRedirectError::StateUnavailable)?;
    let certificate_remaining = expiry_nanos
        .checked_sub(wall_now_nanos)
        .map(|value| value.min(maximum_age_nanos))
        .and_then(|value| u64::try_from(value).ok())
        .map(Duration::from_nanos)
        .ok_or(IngressRedirectError::AuthenticationExpired)?;
    if certificate_remaining.is_zero() {
        return Err(IngressRedirectError::AuthenticationExpired);
    }
    monotonic_now
        .checked_add(certificate_remaining)
        .ok_or(IngressRedirectError::StateUnavailable)
}

/// One authenticated redirect peer with current-plus-previous receive epochs.
pub struct IngressRedirectPeerSession {
    profile: IngressRedirectProfile,
    local_owner: OwnerId,
    peer_owner: OwnerId,
    local_sender_digest: [u8; INGRESS_REDIRECT_SENDER_DIGEST_LEN],
    peer_sender_digest: [u8; INGRESS_REDIRECT_SENDER_DIGEST_LEN],
    routing_domains: Arc<[RoutingDomainTag]>,
    local_udp_endpoint: SocketAddr,
    peer_udp_endpoint: SocketAddr,
    epochs: RwLock<SessionEpochState>,
    metrics: Arc<IngressRedirectMetrics>,
    endpoint_consumed: AtomicBool,
    control_operation_active: AtomicBool,
}

impl IngressRedirectPeerSession {
    /// Consume an admitted mTLS exporter bootstrap into an executable session.
    fn from_bootstrap(bootstrap: IngressRedirectBootstrap) -> Result<Self, IngressRedirectError> {
        let routing_domains = canonical_routing_domains(&bootstrap.routing_domains)?;
        let profile = bootstrap.profile;
        let local_owner = bootstrap.local_owner.clone();
        let peer_owner = bootstrap.peer_owner.clone();
        let local_sender_digest = bootstrap.local_sender_digest;
        let peer_sender_digest = bootstrap.peer_sender_digest;
        let local_udp_endpoint = bootstrap.local_udp_endpoint;
        let peer_udp_endpoint = bootstrap.peer_udp_endpoint;
        let current = Arc::new(epoch_from_bootstrap(profile, bootstrap));
        Ok(Self {
            profile,
            local_owner,
            peer_owner,
            local_sender_digest,
            peer_sender_digest,
            routing_domains,
            local_udp_endpoint,
            peer_udp_endpoint,
            epochs: RwLock::new(SessionEpochState {
                current,
                previous: None,
                pending: None,
            }),
            metrics: Arc::new(IngressRedirectMetrics::default()),
            endpoint_consumed: AtomicBool::new(false),
            control_operation_active: AtomicBool::new(false),
        })
    }

    fn begin_control_operation(
        &self,
    ) -> Result<IngressRedirectControlOperationGuard<'_>, IngressRedirectError> {
        self.control_operation_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| IngressRedirectError::RotationInProgress)?;
        Ok(IngressRedirectControlOperationGuard {
            active: &self.control_operation_active,
        })
    }

    fn ensure_current_authentication_valid_at(
        &self,
        now: Instant,
    ) -> Result<(), IngressRedirectError> {
        let state = self
            .epochs
            .read()
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        if now >= state.current.hard_authenticated_deadline {
            return Err(IngressRedirectError::AuthenticationExpired);
        }
        Ok(())
    }

    fn ensure_current_epoch_authentication_valid_at(
        &self,
        epoch: IngressRedirectProtectionEpoch,
        now: Instant,
    ) -> Result<(), IngressRedirectError> {
        let state = self
            .epochs
            .read()
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        if state.current.epoch != epoch {
            return Err(IngressRedirectError::UnknownEpoch);
        }
        if now >= state.current.hard_authenticated_deadline {
            return Err(IngressRedirectError::AuthenticationExpired);
        }
        Ok(())
    }

    fn consume_for_endpoint(&self) -> Result<(), IngressRedirectError> {
        self.endpoint_consumed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| IngressRedirectError::EndpointAlreadyConsumed)
    }

    /// Return the immutable negotiated peer profile.
    #[must_use]
    pub const fn profile(&self) -> IngressRedirectProfile {
        self.profile
    }

    /// Return fixed-cardinality redaction-safe session counters.
    #[must_use]
    pub fn metrics(&self) -> IngressRedirectMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Return current TLS lifecycle evidence and the proactive rotation lead.
    ///
    /// The method obtains monotonic time internally. A consumer should begin a
    /// new mTLS bootstrap when `reauthenticate_after()` reaches zero; the hard
    /// packet deadline remains enforced even when rotation stalls.
    pub fn authentication_status(
        &self,
    ) -> Result<IngressRedirectAuthenticationStatus, IngressRedirectError> {
        let now = Instant::now();
        let epoch = self
            .epochs
            .read()
            .map(|state| Arc::clone(&state.current))
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        let hard_lifetime_remaining = epoch
            .hard_authenticated_deadline
            .saturating_duration_since(now);
        let reauthenticate_after =
            hard_lifetime_remaining.saturating_sub(self.profile.rotation_overlap);
        match &epoch.authentication_evidence {
            EpochAuthenticationEvidence::Tls {
                local_admission,
                peer_certificate_chain_expires_at,
                authenticated_at,
            } => Ok(IngressRedirectAuthenticationStatus {
                epoch: epoch.epoch,
                local_material_epoch: local_admission.epoch(),
                authenticated_at: *authenticated_at,
                local_certificate_chain_expires_at: local_admission.certificate_chain_expires_at(),
                peer_certificate_chain_expires_at: *peer_certificate_chain_expires_at,
                hard_lifetime_remaining,
                reauthenticate_after,
            }),
            #[cfg(test)]
            EpochAuthenticationEvidence::TestOnly => Err(IngressRedirectError::StateUnavailable),
        }
    }

    /// Return AES-GCM directional usage headroom for proactive reauthentication.
    ///
    /// Data and receipt frames share a `2^23` new-seal budget. Successful peer
    /// opens are independently capped at `2^23`, while failed known-epoch
    /// authentications are capped at `2^36`. HMAC mode is not subject to
    /// AES-GCM invocation limits and therefore reports `None` for every
    /// remaining counter.
    pub fn aead_usage_status(
        &self,
    ) -> Result<IngressRedirectAeadUsageStatus, IngressRedirectError> {
        let epoch = self
            .epochs
            .read()
            .map(|state| Arc::clone(&state.current))
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        if self.profile.security_mode != IngressRedirectSecurityMode::Aes256Gcm {
            return Ok(IngressRedirectAeadUsageStatus {
                epoch: epoch.epoch,
                newly_protected_frames_remaining: None,
                successful_peer_opens_remaining: None,
                failed_authentications_remaining: None,
                reauthentication_required: false,
            });
        }
        let frame_limit = epoch.aead_frame_limit.load(Ordering::Acquire);
        let failed_limit = epoch.aead_failed_auth_limit.load(Ordering::Acquire);
        let newly_protected_frames_remaining =
            frame_limit.saturating_sub(epoch.newly_sealed_frames.load(Ordering::Acquire));
        let successful_peer_opens_remaining =
            frame_limit.saturating_sub(epoch.successful_opened_frames.load(Ordering::Acquire));
        let failed_authentications_remaining =
            failed_limit.saturating_sub(epoch.failed_aead_authentications.load(Ordering::Acquire));
        let proactive_headroom =
            AES_GCM_PROACTIVE_FRAME_ROTATION_HEADROOM.min((frame_limit / 8).max(1));
        Ok(IngressRedirectAeadUsageStatus {
            epoch: epoch.epoch,
            newly_protected_frames_remaining: Some(newly_protected_frames_remaining),
            successful_peer_opens_remaining: Some(successful_peer_opens_remaining),
            failed_authentications_remaining: Some(failed_authentications_remaining),
            reauthentication_required: epoch.aead_reauth_signaled.load(Ordering::Acquire)
                || newly_protected_frames_remaining <= proactive_headroom
                || successful_peer_opens_remaining <= proactive_headroom,
        })
    }

    /// Inspect bounded current/pending/previous epoch state.
    ///
    /// After [`IngressRedirectError::RotationOutcomeUnknown`], an authenticated
    /// frame from `pending_receive()` automatically proves peer cutover and
    /// promotes that epoch without accepting any caller assertion.
    pub fn rotation_status(&self) -> Result<IngressRedirectRotationStatus, IngressRedirectError> {
        let now = Instant::now();
        let mut state = self
            .epochs
            .write()
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        purge_expired_receive_epochs(&mut state, now);
        Ok(IngressRedirectRotationStatus {
            current: state.current.epoch,
            pending_receive: state.pending.as_ref().map(|pending| pending.epoch.epoch),
            previous_receive: state.previous.as_ref().map(|previous| previous.epoch.epoch),
            pending_lifetime_remaining: state.pending.as_ref().map_or(Duration::ZERO, |pending| {
                pending.valid_until.saturating_duration_since(now)
            }),
        })
    }

    /// Local authenticated UDP data endpoint.
    #[must_use]
    pub const fn local_udp_endpoint(&self) -> SocketAddr {
        self.local_udp_endpoint
    }

    /// Authenticated peer UDP data endpoint.
    #[must_use]
    pub const fn peer_udp_endpoint(&self) -> SocketAddr {
        self.peer_udp_endpoint
    }

    fn stage_rotation(
        &self,
        bootstrap: IngressRedirectBootstrap,
    ) -> Result<IngressRedirectPendingRotation, IngressRedirectError> {
        self.stage_rotation_at(bootstrap, Instant::now())
    }

    fn stage_rotation_at(
        &self,
        bootstrap: IngressRedirectBootstrap,
        now: Instant,
    ) -> Result<IngressRedirectPendingRotation, IngressRedirectError> {
        let routing_domains = canonical_routing_domains(&bootstrap.routing_domains)?;
        if bootstrap.profile != self.profile
            || bootstrap.local_owner != self.local_owner
            || bootstrap.peer_owner != self.peer_owner
            || bootstrap.local_sender_digest != self.local_sender_digest
            || bootstrap.peer_sender_digest != self.peer_sender_digest
            || routing_domains != self.routing_domains
            || bootstrap.local_udp_endpoint != self.local_udp_endpoint
            || bootstrap.peer_udp_endpoint != self.peer_udp_endpoint
        {
            return Err(IngressRedirectError::PeerIdentityMismatch);
        }
        if now >= bootstrap.hard_authenticated_deadline {
            return Err(IngressRedirectError::AuthenticationExpired);
        }
        let minimum_stage_deadline = now
            .checked_add(ROTATION_STAGING_TIMEOUT)
            .ok_or(IngressRedirectError::StateUnavailable)?;
        if bootstrap.hard_authenticated_deadline < minimum_stage_deadline {
            return Err(IngressRedirectError::AuthenticationExpired);
        }
        let replacement = Arc::new(epoch_from_bootstrap(self.profile, bootstrap));
        let mut state = self
            .epochs
            .write()
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        purge_expired_receive_epochs(&mut state, now);
        if state.pending.is_some() || state.previous.is_some() {
            return Err(IngressRedirectError::RotationInProgress);
        }
        if replacement.epoch == state.current.epoch
            || state
                .previous
                .as_ref()
                .is_some_and(|previous| previous.epoch.epoch == replacement.epoch)
        {
            return Err(IngressRedirectError::TlsBootstrapFailed);
        }
        let valid_until = minimum_stage_deadline.min(replacement.hard_authenticated_deadline);
        let token = IngressRedirectPendingRotation {
            epoch: replacement.epoch,
        };
        state.pending = Some(PendingReceiveEpoch {
            epoch: replacement,
            valid_until,
        });
        Ok(token)
    }

    fn activate_rotation(
        &self,
        token: &IngressRedirectPendingRotation,
    ) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError> {
        self.activate_rotation_at(token, Instant::now())
    }

    fn activate_rotation_at(
        &self,
        token: &IngressRedirectPendingRotation,
        now: Instant,
    ) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError> {
        let mut state = self
            .epochs
            .write()
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        purge_expired_receive_epochs(&mut state, now);
        if state.current.epoch == token.epoch {
            return Ok(state.current.epoch);
        }
        if state.previous.is_some() {
            return Err(IngressRedirectError::RotationInProgress);
        }
        let Some(pending) = state.pending.as_ref() else {
            return Err(IngressRedirectError::RotationNotStaged);
        };
        if pending.epoch.epoch != token.epoch {
            return Err(IngressRedirectError::RotationNotStaged);
        }
        if now >= pending.valid_until || now >= pending.epoch.hard_authenticated_deadline {
            state.pending = None;
            return Err(IngressRedirectError::AuthenticationExpired);
        }
        let pending = state
            .pending
            .take()
            .ok_or(IngressRedirectError::RotationNotStaged)?;
        let previous = Arc::clone(&state.current);
        let previous_hard_deadline = previous.hard_authenticated_deadline;
        state.current = pending.epoch;
        state.previous = Some(PreviousReceiveEpoch {
            epoch: previous,
            valid_until: now
                .checked_add(self.profile.rotation_overlap)
                .ok_or(IngressRedirectError::StateUnavailable)?
                .min(previous_hard_deadline),
        });
        Ok(state.current.epoch)
    }

    fn abort_rotation(
        &self,
        token: &IngressRedirectPendingRotation,
    ) -> Result<(), IngressRedirectError> {
        let now = Instant::now();
        let mut state = self
            .epochs
            .write()
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        purge_expired_receive_epochs(&mut state, now);
        if state
            .pending
            .as_ref()
            .is_none_or(|pending| pending.epoch.epoch != token.epoch)
        {
            return Err(IngressRedirectError::RotationNotStaged);
        }
        state.pending = None;
        Ok(())
    }

    fn retain_pending_for_reconciliation(
        &self,
        token: &IngressRedirectPendingRotation,
    ) -> Result<(), IngressRedirectError> {
        let now = Instant::now();
        let mut state = self
            .epochs
            .write()
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        purge_expired_receive_epochs(&mut state, now);
        let pending = state
            .pending
            .as_mut()
            .filter(|pending| pending.epoch.epoch == token.epoch)
            .ok_or(IngressRedirectError::RotationNotStaged)?;
        let reconciliation_deadline = now
            .checked_add(ROTATION_RECONCILIATION_TIMEOUT)
            .ok_or(IngressRedirectError::StateUnavailable)?
            .min(pending.epoch.hard_authenticated_deadline);
        if reconciliation_deadline <= now {
            return Err(IngressRedirectError::AuthenticationExpired);
        }
        pending.valid_until = reconciliation_deadline;
        Ok(())
    }

    fn reconcile_authenticated_epoch(
        &self,
        epoch: IngressRedirectProtectionEpoch,
    ) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError> {
        self.reconcile_authenticated_epoch_at(epoch, Instant::now(), Instant::now)
    }

    fn reconcile_authenticated_epoch_at<F>(
        &self,
        epoch: IngressRedirectProtectionEpoch,
        now: Instant,
        completion_now: F,
    ) -> Result<IngressRedirectProtectionEpoch, IngressRedirectError>
    where
        F: FnOnce() -> Instant,
    {
        {
            let mut state = self
                .epochs
                .write()
                .map_err(|_| IngressRedirectError::StateUnavailable)?;
            purge_expired_receive_epochs(&mut state, now);
            if state.current.epoch == epoch {
                if now >= state.current.hard_authenticated_deadline {
                    return Err(IngressRedirectError::AuthenticationExpired);
                }
                state.pending = None;
                drop(state);
                self.ensure_current_epoch_authentication_valid_at(epoch, completion_now())?;
                return Ok(epoch);
            }
        }
        self.activate_pending_from_authenticated_peer(epoch.get(), now)?;
        self.ensure_current_epoch_authentication_valid_at(epoch, completion_now())?;
        Ok(epoch)
    }

    /// Seal one newly observed original packet with the fixed first redirect
    /// count of one.
    #[cfg(test)]
    pub(crate) fn seal_data(
        &self,
        packet: &[u8],
        ownership_key: SessionOwnershipKey,
        ownership_generation: FencedOwnershipGeneration,
    ) -> Result<Vec<u8>, IngressRedirectError> {
        self.seal_data_for_endpoint(packet, ownership_key, ownership_generation, Instant::now())
            .map(|sealed| sealed.bytes.as_ref().to_vec())
    }

    fn seal_data_for_endpoint(
        &self,
        packet: &[u8],
        ownership_key: SessionOwnershipKey,
        ownership_generation: FencedOwnershipGeneration,
        required_valid_until: Instant,
    ) -> Result<SealedIngressRedirectFrame, IngressRedirectError> {
        if packet.is_empty() {
            return Err(IngressRedirectError::InvalidOriginalPacket);
        }
        if packet.len() > usize::from(u16::MAX) {
            increment(&self.metrics.oversize_drops);
            return Err(IngressRedirectError::PacketTooLarge);
        }
        let key = ownership_key.to_canonical_bytes();
        if !self.routing_domain_allowed(ownership_key.destination().routing_domain()) {
            increment(&self.metrics.routing_domain_drops);
            return Err(IngressRedirectError::RoutingDomainNotAuthorized);
        }
        if key.is_empty() || key.len() > INGRESS_REDIRECT_OWNERSHIP_KEY_MAX_LEN {
            return Err(IngressRedirectError::InvalidOwnershipKey);
        }
        self.seal_data_with_generation_for_endpoint(
            packet,
            key,
            ownership_generation.get(),
            1,
            required_valid_until,
        )
    }

    /// Forward a frame authenticated by another peer session while preserving
    /// and checked-incrementing its hop state.
    ///
    /// Consuming the authenticated value makes resetting a cycle to hop one
    /// unavailable through the public API. The caller supplies fresh fenced
    /// generation evidence for the newly selected owner; packet bytes and the
    /// canonical ownership key are retained exactly.
    fn seal_forwarded_data_for_endpoint(
        &self,
        prior: &AuthenticatedIngressRedirectData,
        ownership_generation: FencedOwnershipGeneration,
        required_valid_until: Instant,
    ) -> Result<SealedIngressRedirectFrame, IngressRedirectError> {
        if prior.hop_limit != self.profile.hop_limit.get() {
            return Err(IngressRedirectError::HopLimitMismatch);
        }
        if !self.routing_domain_allowed(prior.ownership_key.destination().routing_domain()) {
            increment(&self.metrics.routing_domain_drops);
            return Err(IngressRedirectError::RoutingDomainNotAuthorized);
        }
        if prior.hop_count >= prior.hop_limit {
            increment(&self.metrics.hop_limit_drops);
            return Err(IngressRedirectError::HopLimitReached);
        }
        let next_hop = prior
            .hop_count
            .checked_add(1)
            .ok_or(IngressRedirectError::HopLimitReached)?;
        self.seal_data_with_generation_for_endpoint(
            &prior.packet,
            prior.ownership_key.to_canonical_bytes(),
            ownership_generation.get(),
            next_hop,
            required_valid_until,
        )
    }

    #[cfg(test)]
    fn seal_data_with_generation(
        &self,
        packet: &[u8],
        key: Vec<u8>,
        ownership_generation: u64,
        hop_count: u8,
    ) -> Result<Vec<u8>, IngressRedirectError> {
        self.seal_data_with_generation_for_endpoint(
            packet,
            key,
            ownership_generation,
            hop_count,
            Instant::now(),
        )
        .map(|sealed| sealed.bytes.as_ref().to_vec())
    }

    fn seal_data_with_generation_for_endpoint(
        &self,
        packet: &[u8],
        key: Vec<u8>,
        ownership_generation: u64,
        hop_count: u8,
        required_valid_until: Instant,
    ) -> Result<SealedIngressRedirectFrame, IngressRedirectError> {
        let budget =
            IngressRedirectMtuBudget::new(self.profile, self.peer_udp_endpoint.ip(), key.len())?;
        if !budget.admits(packet.len()) {
            increment(&self.metrics.oversize_drops);
            return Err(IngressRedirectError::PacketTooLarge);
        }
        let epoch = self.current_epoch_at(Instant::now())?;
        if epoch.hard_authenticated_deadline <= required_valid_until {
            increment(&self.metrics.authentication_expired_drops);
            return Err(IngressRedirectError::AuthenticationExpired);
        }
        reserve_new_aead_seal(self.profile.security_mode, &epoch, &self.metrics)?;
        let sequence = next_sequence(&epoch.next_send_sequence)?;
        let key_len =
            u16::try_from(key.len()).map_err(|_| IngressRedirectError::InvalidOwnershipKey)?;
        let packet_len =
            u16::try_from(packet.len()).map_err(|_| IngressRedirectError::PacketTooLarge)?;
        let header = IngressRedirectFrameHeader::data(
            self.profile.security_mode,
            hop_count,
            self.profile.hop_limit.get(),
            epoch.epoch.get(),
            sequence,
            ownership_generation,
            self.local_sender_digest,
            key_len,
            packet_len,
        )?;
        let sealed = seal_frame(&epoch, self.profile.security_mode, header, &key, packet)?;
        increment(&self.metrics.frames_sealed);
        Ok(SealedIngressRedirectFrame {
            bytes: Arc::from(sealed),
            epoch: epoch.epoch,
            sequence,
            valid_until: epoch.hard_authenticated_deadline,
        })
    }

    /// Seal an authenticated typed receipt for one data epoch/sequence.
    #[cfg(test)]
    pub(crate) fn seal_receipt(
        &self,
        acknowledged_epoch: IngressRedirectProtectionEpoch,
        acknowledged_sequence: u64,
        code: IngressRedirectReceiptCode,
    ) -> Result<Vec<u8>, IngressRedirectError> {
        self.seal_receipt_for_cache(acknowledged_epoch, acknowledged_sequence, code)
            .map(|sealed| sealed.bytes.as_ref().to_vec())
    }

    fn seal_receipt_for_cache(
        &self,
        acknowledged_epoch: IngressRedirectProtectionEpoch,
        acknowledged_sequence: u64,
        code: IngressRedirectReceiptCode,
    ) -> Result<SealedIngressRedirectFrame, IngressRedirectError> {
        let epoch = self.current_epoch_at(Instant::now())?;
        reserve_new_aead_seal(self.profile.security_mode, &epoch, &self.metrics)?;
        let sequence = next_sequence(&epoch.next_send_sequence)?;
        let header = IngressRedirectFrameHeader::receipt(
            self.profile.security_mode,
            epoch.epoch.get(),
            sequence,
            self.local_sender_digest,
            acknowledged_epoch.get(),
            acknowledged_sequence,
            code,
        )?;
        let sealed = seal_frame(&epoch, self.profile.security_mode, header, &[], &[])?;
        increment(&self.metrics.frames_sealed);
        Ok(SealedIngressRedirectFrame {
            bytes: Arc::from(sealed),
            epoch: epoch.epoch,
            sequence,
            valid_until: epoch.hard_authenticated_deadline,
        })
    }

    /// Authenticate, decrypt when selected, bind the sender, and enforce the
    /// per-direction replay window at caller-supplied monotonic time.
    ///
    /// The wire mode is never used to select an algorithm or tag width. The
    /// session first requires it to equal the exporter-negotiated profile,
    /// then authenticates with that profile. Sender digest comparison occurs
    /// only after successful authentication.
    fn open_at(
        &self,
        datagram: &[u8],
        now: Instant,
    ) -> Result<AuthenticatedIngressRedirectFrame, IngressRedirectError> {
        let header = match IngressRedirectFrameHeader::decode(datagram) {
            Ok(header) => header,
            Err(_) => {
                increment(&self.metrics.malformed_drops);
                return Err(IngressRedirectError::MalformedFrame);
            }
        };
        if header.security_mode() != self.profile.security_mode {
            increment(&self.metrics.mode_mismatch_drops);
            return Err(IngressRedirectError::ProtectionModeMismatch);
        }
        let (epoch, receive_epoch_kind) = match self.receive_epoch(header.epoch(), now) {
            Ok(epoch) => epoch,
            Err(IngressRedirectError::UnknownEpoch) => {
                increment(&self.metrics.unknown_epoch_drops);
                return Err(IngressRedirectError::UnknownEpoch);
            }
            Err(IngressRedirectError::AuthenticationExpired) => {
                increment(&self.metrics.authentication_expired_drops);
                return Err(IngressRedirectError::AuthenticationExpired);
            }
            Err(error) => return Err(error),
        };
        enforce_aead_receive_budget(self.profile.security_mode, &epoch, &self.metrics)?;
        let opened = open_frame(&epoch, self.profile.security_mode, header, datagram);
        let (ownership_key_bytes, packet) = match opened {
            Ok(opened) => {
                reserve_successful_aead_open(self.profile.security_mode, &epoch, &self.metrics)?;
                opened
            }
            Err(error) => {
                match error {
                    IngressRedirectError::AuthenticationFailed => {
                        increment(&self.metrics.authentication_drops);
                        record_failed_aead_authentication(
                            self.profile.security_mode,
                            &epoch,
                            &self.metrics,
                        );
                    }
                    IngressRedirectError::MalformedFrame => {
                        increment(&self.metrics.malformed_drops);
                    }
                    _ => {}
                }
                return Err(error);
            }
        };
        if header
            .sender_digest()
            .ct_eq(&self.peer_sender_digest)
            .unwrap_u8()
            != 1
        {
            increment(&self.metrics.sender_identity_drops);
            return Err(IngressRedirectError::SenderIdentityMismatch);
        }
        if header.kind() == IngressRedirectFrameKind::Data
            && header.hop_limit() != self.profile.hop_limit.get()
        {
            increment(&self.metrics.hop_profile_drops);
            return Err(IngressRedirectError::HopLimitMismatch);
        }
        let replay_result = epoch
            .replay
            .lock()
            .map_err(|_| IngressRedirectError::StateUnavailable)?
            .accept(header.sequence());
        if replay_result.is_err() {
            increment(&self.metrics.replay_drops);
            return Err(IngressRedirectError::ReplayRejected);
        }
        if receive_epoch_kind == ReceiveEpochKind::Pending {
            self.activate_pending_from_authenticated_peer(header.epoch(), now)?;
        }
        increment(&self.metrics.frames_authenticated);

        match header.kind() {
            IngressRedirectFrameKind::Data => {
                let ownership_key =
                    match SessionOwnershipKey::from_canonical_bytes(&ownership_key_bytes) {
                        Ok(key) => key,
                        Err(_) => {
                            increment(&self.metrics.invalid_ownership_key_drops);
                            return Err(IngressRedirectError::InvalidOwnershipKey);
                        }
                    };
                Ok(AuthenticatedIngressRedirectFrame::Data(
                    AuthenticatedIngressRedirectData {
                        epoch: IngressRedirectProtectionEpoch(header.epoch()),
                        hop_count: header.hop_count(),
                        hop_limit: header.hop_limit(),
                        ownership_generation: header.ownership_generation(),
                        ownership_key,
                        packet,
                    },
                ))
            }
            IngressRedirectFrameKind::Receipt => Ok(AuthenticatedIngressRedirectFrame::Receipt(
                AuthenticatedIngressRedirectReceipt {
                    acknowledged_epoch: IngressRedirectProtectionEpoch(header.acknowledged_epoch()),
                    acknowledged_sequence: header.acknowledged_sequence(),
                    code: header
                        .receipt_code()
                        .ok_or(IngressRedirectError::MalformedFrame)?,
                },
            )),
        }
    }

    /// Authenticate a datagram using the process monotonic clock.
    pub(crate) fn open(
        &self,
        datagram: &[u8],
    ) -> Result<AuthenticatedIngressRedirectFrame, IngressRedirectError> {
        self.open_at(datagram, Instant::now())
    }

    /// Reclassify one authenticated data packet and require a fresh, exact
    /// fenced-ownership record for this receiver and stamped generation.
    #[cfg(test)]
    pub(crate) fn validate_delivery<C>(
        &self,
        data: AuthenticatedIngressRedirectData,
        ownership: &FencedOwnershipCache<C>,
    ) -> Result<DeliveredIngressRedirectPacket, IngressRedirectError>
    where
        C: Clock,
    {
        let ownership_generation = self.validate_delivery_evidence(&data, ownership)?;
        Ok(DeliveredIngressRedirectPacket {
            ownership_key: data.ownership_key,
            ownership_generation,
            hop_count: data.hop_count,
            packet: data.packet,
        })
    }

    fn validate_delivery_evidence<C>(
        &self,
        data: &AuthenticatedIngressRedirectData,
        ownership: &FencedOwnershipCache<C>,
    ) -> Result<FencedOwnershipGeneration, IngressRedirectError>
    where
        C: Clock,
    {
        self.validate_delivery_evidence_inner(data, ownership, true)
    }

    fn revalidate_delivery_evidence<C>(
        &self,
        data: &AuthenticatedIngressRedirectData,
        ownership: &FencedOwnershipCache<C>,
    ) -> Result<FencedOwnershipGeneration, IngressRedirectError>
    where
        C: Clock,
    {
        self.validate_delivery_evidence_inner(data, ownership, false)
    }

    fn validate_delivery_evidence_inner<C>(
        &self,
        data: &AuthenticatedIngressRedirectData,
        ownership: &FencedOwnershipCache<C>,
        record_metrics: bool,
    ) -> Result<FencedOwnershipGeneration, IngressRedirectError>
    where
        C: Clock,
    {
        if data.hop_count >= data.hop_limit {
            if record_metrics {
                increment(&self.metrics.hop_limit_drops);
            }
            return Err(IngressRedirectError::HopLimitReached);
        }
        let routing_domain: RoutingDomainTag = data.ownership_key.destination().routing_domain();
        if self.routing_domains.binary_search(&routing_domain).is_err() {
            if record_metrics {
                increment(&self.metrics.routing_domain_drops);
            }
            return Err(IngressRedirectError::RoutingDomainNotAuthorized);
        }
        let classified = classify_keyless_ingress_packet(&data.packet, routing_domain);
        if classified
            .matched()
            .and_then(|matched| matched.ownership_key())
            != Some(data.ownership_key)
        {
            if record_metrics {
                increment(&self.metrics.classification_drops);
            }
            return Err(IngressRedirectError::ClassificationMismatch);
        }
        let canonical = data.ownership_key.to_canonical_bytes();
        let store_key = FencedOwnershipKey::new(&canonical)
            .map_err(|_| IngressRedirectError::InvalidOwnershipKey)?;
        let current = match ownership.lookup(&store_key) {
            FencedOwnershipCacheLookup::Hit(record) => record,
            FencedOwnershipCacheLookup::Miss => {
                if record_metrics {
                    increment(&self.metrics.ownership_missing_drops);
                }
                return Err(IngressRedirectError::OwnershipMissing);
            }
            FencedOwnershipCacheLookup::Stale => {
                if record_metrics {
                    increment(&self.metrics.ownership_view_stale_drops);
                }
                return Err(IngressRedirectError::OwnershipViewStale);
            }
        };
        match data.ownership_generation.cmp(&current.generation().get()) {
            std::cmp::Ordering::Less => {
                if record_metrics {
                    increment(&self.metrics.stale_generation_drops);
                }
                return Err(IngressRedirectError::StaleOwnershipGeneration);
            }
            std::cmp::Ordering::Greater => {
                if record_metrics {
                    increment(&self.metrics.receiver_view_behind_drops);
                }
                return Err(IngressRedirectError::UnprovenOwnershipGeneration);
            }
            std::cmp::Ordering::Equal => {}
        }
        if current.owner() != &self.local_owner {
            if record_metrics {
                increment(&self.metrics.not_owner_drops);
            }
            return Err(IngressRedirectError::NotOwner);
        }
        Ok(current.generation())
    }

    fn current_epoch_at(
        &self,
        now: Instant,
    ) -> Result<Arc<DirectionalEpoch>, IngressRedirectError> {
        let epoch = self
            .epochs
            .read()
            .map(|state| Arc::clone(&state.current))
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        if now >= epoch.hard_authenticated_deadline {
            increment(&self.metrics.authentication_expired_drops);
            return Err(IngressRedirectError::AuthenticationExpired);
        }
        Ok(epoch)
    }

    #[cfg(test)]
    fn current_epoch(&self) -> Result<Arc<DirectionalEpoch>, IngressRedirectError> {
        self.current_epoch_at(Instant::now())
    }

    #[cfg(test)]
    fn set_current_aead_limits(
        &self,
        frame_limit: u64,
        failed_auth_limit: u64,
        failed_auth_warning: u64,
    ) -> Result<(), IngressRedirectError> {
        if frame_limit == 0
            || failed_auth_limit == 0
            || failed_auth_warning == 0
            || failed_auth_warning > failed_auth_limit
        {
            return Err(IngressRedirectError::StateUnavailable);
        }
        let epoch = self.current_epoch()?;
        epoch.aead_frame_limit.store(frame_limit, Ordering::Release);
        epoch
            .aead_failed_auth_limit
            .store(failed_auth_limit, Ordering::Release);
        epoch
            .aead_failed_auth_warning
            .store(failed_auth_warning, Ordering::Release);
        Ok(())
    }

    fn routing_domain_allowed(&self, routing_domain: RoutingDomainTag) -> bool {
        self.routing_domains.binary_search(&routing_domain).is_ok()
    }

    fn receive_epoch(
        &self,
        wire_epoch: u64,
        now: Instant,
    ) -> Result<(Arc<DirectionalEpoch>, ReceiveEpochKind), IngressRedirectError> {
        let mut state = self
            .epochs
            .write()
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        purge_expired_receive_epochs(&mut state, now);
        if state.current.epoch.get() == wire_epoch {
            if now >= state.current.hard_authenticated_deadline {
                return Err(IngressRedirectError::AuthenticationExpired);
            }
            return Ok((Arc::clone(&state.current), ReceiveEpochKind::Current));
        }
        if let Some(pending) = state
            .pending
            .as_ref()
            .filter(|pending| pending.epoch.epoch.get() == wire_epoch)
        {
            return Ok((Arc::clone(&pending.epoch), ReceiveEpochKind::Pending));
        }
        if let Some(previous) = state
            .previous
            .as_ref()
            .filter(|previous| previous.epoch.epoch.get() == wire_epoch)
        {
            return Ok((Arc::clone(&previous.epoch), ReceiveEpochKind::Previous));
        }
        Err(IngressRedirectError::UnknownEpoch)
    }

    fn receive_epoch_valid_until(
        &self,
        wire_epoch: u64,
        now: Instant,
    ) -> Result<Instant, IngressRedirectError> {
        let mut state = self
            .epochs
            .write()
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        purge_expired_receive_epochs(&mut state, now);
        let valid_until = if state.current.epoch.get() == wire_epoch {
            state.current.hard_authenticated_deadline
        } else if let Some(pending) = state
            .pending
            .as_ref()
            .filter(|pending| pending.epoch.epoch.get() == wire_epoch)
        {
            pending
                .valid_until
                .min(pending.epoch.hard_authenticated_deadline)
        } else if let Some(previous) = state
            .previous
            .as_ref()
            .filter(|previous| previous.epoch.epoch.get() == wire_epoch)
        {
            previous
                .valid_until
                .min(previous.epoch.hard_authenticated_deadline)
        } else {
            return Err(IngressRedirectError::UnknownEpoch);
        };
        if now >= valid_until {
            Err(IngressRedirectError::AuthenticationExpired)
        } else {
            Ok(valid_until)
        }
    }

    fn activate_pending_from_authenticated_peer(
        &self,
        wire_epoch: u64,
        now: Instant,
    ) -> Result<(), IngressRedirectError> {
        let mut state = self
            .epochs
            .write()
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        purge_expired_receive_epochs(&mut state, now);
        if state.current.epoch.get() == wire_epoch {
            return Ok(());
        }
        if state.previous.is_some() {
            return Err(IngressRedirectError::RotationInProgress);
        }
        let Some(pending) = state.pending.as_ref() else {
            return Err(IngressRedirectError::RotationNotStaged);
        };
        if pending.epoch.epoch.get() != wire_epoch {
            return Err(IngressRedirectError::RotationNotStaged);
        }
        if now >= pending.valid_until || now >= pending.epoch.hard_authenticated_deadline {
            state.pending = None;
            return Err(IngressRedirectError::AuthenticationExpired);
        }
        let pending = state
            .pending
            .take()
            .ok_or(IngressRedirectError::RotationNotStaged)?;
        let previous = Arc::clone(&state.current);
        let previous_hard_deadline = previous.hard_authenticated_deadline;
        state.current = pending.epoch;
        state.previous = Some(PreviousReceiveEpoch {
            epoch: previous,
            valid_until: now
                .checked_add(self.profile.rotation_overlap)
                .ok_or(IngressRedirectError::StateUnavailable)?
                .min(previous_hard_deadline),
        });
        Ok(())
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn for_test(
        profile: IngressRedirectProfile,
        local_owner: OwnerId,
        peer_owner: OwnerId,
        epoch: u64,
        send_key: [u8; 32],
        receive_key: [u8; 32],
        send_nonce_prefix: [u8; 4],
        receive_nonce_prefix: [u8; 4],
        local_sender_digest: [u8; 32],
        peer_sender_digest: [u8; 32],
    ) -> Self {
        let hard_authenticated_deadline = Instant::now()
            .checked_add(Duration::from_secs(60 * 60))
            .unwrap_or_else(|| panic!("valid test deadline"));
        Self::for_test_with_deadline(
            profile,
            local_owner,
            peer_owner,
            epoch,
            send_key,
            receive_key,
            send_nonce_prefix,
            receive_nonce_prefix,
            local_sender_digest,
            peer_sender_digest,
            hard_authenticated_deadline,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn for_test_with_deadline(
        profile: IngressRedirectProfile,
        local_owner: OwnerId,
        peer_owner: OwnerId,
        epoch: u64,
        send_key: [u8; 32],
        receive_key: [u8; 32],
        send_nonce_prefix: [u8; 4],
        receive_nonce_prefix: [u8; 4],
        local_sender_digest: [u8; 32],
        peer_sender_digest: [u8; 32],
        hard_authenticated_deadline: Instant,
    ) -> Self {
        let current = Arc::new(DirectionalEpoch {
            epoch: IngressRedirectProtectionEpoch(epoch),
            send_key: Zeroizing::new(send_key),
            receive_key: Zeroizing::new(receive_key),
            send_nonce_prefix,
            receive_nonce_prefix,
            next_send_sequence: AtomicU64::new(1),
            replay: Mutex::new(ReplayWindow::new(profile.replay_window)),
            newly_sealed_frames: AtomicU64::new(0),
            successful_opened_frames: AtomicU64::new(0),
            failed_aead_authentications: AtomicU64::new(0),
            aead_reauth_signaled: AtomicBool::new(false),
            aead_frame_limit: AtomicU64::new(AES_GCM_MAX_PROTECTED_FRAMES_PER_DIRECTIONAL_EPOCH),
            aead_failed_auth_limit: AtomicU64::new(
                AES_GCM_MAX_FAILED_AUTHENTICATIONS_PER_RECEIVE_KEY,
            ),
            aead_failed_auth_warning: AtomicU64::new(
                AES_GCM_FAILED_AUTHENTICATION_REAUTH_THRESHOLD,
            ),
            hard_authenticated_deadline,
            authentication_evidence: EpochAuthenticationEvidence::TestOnly,
        });
        Self {
            profile,
            local_owner,
            peer_owner,
            local_sender_digest,
            peer_sender_digest,
            routing_domains: Arc::from([RoutingDomainTag::new(7)]),
            local_udp_endpoint: "127.0.0.1:32001"
                .parse()
                .unwrap_or_else(|error| panic!("valid test endpoint: {error}")),
            peer_udp_endpoint: "127.0.0.1:32002"
                .parse()
                .unwrap_or_else(|error| panic!("valid test endpoint: {error}")),
            epochs: RwLock::new(SessionEpochState {
                current,
                previous: None,
                pending: None,
            }),
            metrics: Arc::new(IngressRedirectMetrics::default()),
            endpoint_consumed: AtomicBool::new(false),
            control_operation_active: AtomicBool::new(false),
        }
    }
}

impl fmt::Debug for IngressRedirectPeerSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngressRedirectPeerSession")
            .field("profile", &self.profile)
            .field("local_owner", &"[redacted]")
            .field("peer_owner", &"[redacted]")
            .field("sender_digests", &"[redacted]")
            .field("udp_endpoints", &"[redacted]")
            .field("epochs", &"[redacted]")
            .finish()
    }
}

fn next_sequence(counter: &AtomicU64) -> Result<u64, IngressRedirectError> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            if value == u64::MAX {
                None
            } else {
                value.checked_add(1)
            }
        })
        .map_err(|_| IngressRedirectError::SequenceExhausted)
}

fn reserve_new_aead_seal(
    mode: IngressRedirectSecurityMode,
    epoch: &DirectionalEpoch,
    metrics: &IngressRedirectMetrics,
) -> Result<(), IngressRedirectError> {
    if mode != IngressRedirectSecurityMode::Aes256Gcm {
        return Ok(());
    }
    let limit = epoch.aead_frame_limit.load(Ordering::Acquire);
    if epoch
        .newly_sealed_frames
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
            (used < limit).then(|| used.saturating_add(1))
        })
        .is_err()
    {
        increment(&metrics.aead_seal_budget_exhausted);
        return Err(IngressRedirectError::AeadUsageExhausted);
    }
    Ok(())
}

fn enforce_aead_receive_budget(
    mode: IngressRedirectSecurityMode,
    epoch: &DirectionalEpoch,
    metrics: &IngressRedirectMetrics,
) -> Result<(), IngressRedirectError> {
    if mode != IngressRedirectSecurityMode::Aes256Gcm {
        return Ok(());
    }
    let frame_limit = epoch.aead_frame_limit.load(Ordering::Acquire);
    if epoch.successful_opened_frames.load(Ordering::Acquire) >= frame_limit {
        increment(&metrics.aead_open_budget_exhausted);
        return Err(IngressRedirectError::AeadUsageExhausted);
    }
    let failed_limit = epoch.aead_failed_auth_limit.load(Ordering::Acquire);
    if epoch.failed_aead_authentications.load(Ordering::Acquire) >= failed_limit {
        increment(&metrics.aead_failed_auth_budget_exhausted);
        return Err(IngressRedirectError::AeadUsageExhausted);
    }
    Ok(())
}

fn reserve_successful_aead_open(
    mode: IngressRedirectSecurityMode,
    epoch: &DirectionalEpoch,
    metrics: &IngressRedirectMetrics,
) -> Result<(), IngressRedirectError> {
    if mode != IngressRedirectSecurityMode::Aes256Gcm {
        return Ok(());
    }
    let limit = epoch.aead_frame_limit.load(Ordering::Acquire);
    if epoch
        .successful_opened_frames
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
            (used < limit).then(|| used.saturating_add(1))
        })
        .is_err()
    {
        increment(&metrics.aead_open_budget_exhausted);
        return Err(IngressRedirectError::AeadUsageExhausted);
    }
    Ok(())
}

fn record_failed_aead_authentication(
    mode: IngressRedirectSecurityMode,
    epoch: &DirectionalEpoch,
    metrics: &IngressRedirectMetrics,
) {
    if mode != IngressRedirectSecurityMode::Aes256Gcm {
        return;
    }
    let limit = epoch.aead_failed_auth_limit.load(Ordering::Acquire);
    let prior = epoch.failed_aead_authentications.fetch_update(
        Ordering::AcqRel,
        Ordering::Acquire,
        |failed| (failed < limit).then(|| failed.saturating_add(1)),
    );
    let Ok(prior) = prior else {
        increment(&metrics.aead_failed_auth_budget_exhausted);
        return;
    };
    let failed = prior.saturating_add(1);
    let warning = epoch.aead_failed_auth_warning.load(Ordering::Acquire);
    if failed >= warning && !epoch.aead_reauth_signaled.swap(true, Ordering::AcqRel) {
        increment(&metrics.aead_failed_auth_reauth_signals);
    }
    if failed >= limit {
        increment(&metrics.aead_failed_auth_budget_exhausted);
    }
}

fn frame_nonce(prefix: [u8; 4], sequence: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&prefix);
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn seal_frame(
    epoch: &DirectionalEpoch,
    mode: IngressRedirectSecurityMode,
    header: IngressRedirectFrameHeader,
    ownership_key: &[u8],
    packet: &[u8],
) -> Result<Vec<u8>, IngressRedirectError> {
    let encoded_header = header.encode();
    let mut authenticated_prefix = Vec::with_capacity(encoded_header.len() + ownership_key.len());
    authenticated_prefix.extend_from_slice(&encoded_header);
    authenticated_prefix.extend_from_slice(ownership_key);
    match mode {
        IngressRedirectSecurityMode::Aes256Gcm => {
            let key = <&Key<Aes256Gcm>>::try_from(epoch.send_key.as_slice())
                .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
            let nonce_bytes = frame_nonce(epoch.send_nonce_prefix, header.sequence());
            let nonce = <&Nonce<Aes256Gcm>>::try_from(nonce_bytes.as_slice())
                .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
            let sealed = Aes256Gcm::new(key)
                .encrypt(
                    nonce,
                    Payload {
                        msg: packet,
                        aad: &authenticated_prefix,
                    },
                )
                .map_err(|_| IngressRedirectError::AuthenticationFailed)?;
            authenticated_prefix.extend_from_slice(&sealed);
        }
        IngressRedirectSecurityMode::HmacSha256 => {
            authenticated_prefix.extend_from_slice(packet);
            let tag = hmac_sha2_256(epoch.send_key.as_slice(), &[&authenticated_prefix]);
            authenticated_prefix.extend_from_slice(tag.as_slice());
        }
    }
    Ok(authenticated_prefix)
}

fn open_frame(
    epoch: &DirectionalEpoch,
    mode: IngressRedirectSecurityMode,
    header: IngressRedirectFrameHeader,
    datagram: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), IngressRedirectError> {
    let key_len = usize::from(header.ownership_key_len());
    let packet_len = usize::from(header.packet_len());
    let body_start = INGRESS_REDIRECT_HEADER_LEN
        .checked_add(key_len)
        .ok_or(IngressRedirectError::MalformedFrame)?;
    let exact_len = body_start
        .checked_add(packet_len)
        .and_then(|value| value.checked_add(mode.tag_len()))
        .ok_or(IngressRedirectError::MalformedFrame)?;
    if datagram.len() != exact_len {
        return Err(IngressRedirectError::MalformedFrame);
    }
    let ownership_key = datagram
        .get(INGRESS_REDIRECT_HEADER_LEN..body_start)
        .ok_or(IngressRedirectError::MalformedFrame)?
        .to_vec();
    let authenticated_prefix = datagram
        .get(..body_start)
        .ok_or(IngressRedirectError::MalformedFrame)?;
    let protected_packet_and_tag = datagram
        .get(body_start..)
        .ok_or(IngressRedirectError::MalformedFrame)?;

    let packet = match mode {
        IngressRedirectSecurityMode::Aes256Gcm => {
            let key = <&Key<Aes256Gcm>>::try_from(epoch.receive_key.as_slice())
                .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
            let nonce_bytes = frame_nonce(epoch.receive_nonce_prefix, header.sequence());
            let nonce = <&Nonce<Aes256Gcm>>::try_from(nonce_bytes.as_slice())
                .map_err(|_| IngressRedirectError::TlsBootstrapFailed)?;
            Aes256Gcm::new(key)
                .decrypt(
                    nonce,
                    Payload {
                        msg: protected_packet_and_tag,
                        aad: authenticated_prefix,
                    },
                )
                .map_err(|_| IngressRedirectError::AuthenticationFailed)?
        }
        IngressRedirectSecurityMode::HmacSha256 => {
            let tag_start = datagram
                .len()
                .checked_sub(mode.tag_len())
                .ok_or(IngressRedirectError::MalformedFrame)?;
            let authenticated = datagram
                .get(..tag_start)
                .ok_or(IngressRedirectError::MalformedFrame)?;
            let tag = datagram
                .get(tag_start..)
                .ok_or(IngressRedirectError::MalformedFrame)?;
            let expected = hmac_sha2_256(epoch.receive_key.as_slice(), &[authenticated]);
            if expected.as_slice().ct_eq(tag).unwrap_u8() != 1 {
                return Err(IngressRedirectError::AuthenticationFailed);
            }
            authenticated
                .get(body_start..)
                .ok_or(IngressRedirectError::MalformedFrame)?
                .to_vec()
        }
    };
    if packet.len() != packet_len {
        return Err(IngressRedirectError::MalformedFrame);
    }
    Ok((ownership_key, packet))
}

/// Exact newly protected frame plus the epoch lifetime that authorized it.
struct SealedIngressRedirectFrame {
    bytes: Arc<[u8]>,
    epoch: IngressRedirectProtectionEpoch,
    sequence: u64,
    valid_until: Instant,
}

/// Authenticated frame after cryptographic sender binding and replay checks.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AuthenticatedIngressRedirectFrame {
    /// One original data packet awaiting fresh ownership validation.
    Data(AuthenticatedIngressRedirectData),
    /// One authenticated delivery or typed-rejection receipt.
    Receipt(AuthenticatedIngressRedirectReceipt),
}

/// Authenticated packet metadata and exact original packet bytes.
#[derive(PartialEq, Eq)]
pub(crate) struct AuthenticatedIngressRedirectData {
    epoch: IngressRedirectProtectionEpoch,
    hop_count: u8,
    hop_limit: u8,
    ownership_generation: u64,
    ownership_key: SessionOwnershipKey,
    packet: Vec<u8>,
}

impl AuthenticatedIngressRedirectData {
    /// Protection epoch of the received frame.
    #[must_use]
    pub const fn epoch(&self) -> IngressRedirectProtectionEpoch {
        self.epoch
    }

    /// Number of redirects already performed, beginning at one.
    #[must_use]
    pub const fn hop_count(&self) -> u8 {
        self.hop_count
    }

    /// Authenticated hop limit.
    #[must_use]
    pub const fn hop_limit(&self) -> u8 {
        self.hop_limit
    }

    /// Canonical destination-scoped ownership key.
    #[must_use]
    pub const fn ownership_key(&self) -> SessionOwnershipKey {
        self.ownership_key
    }

    /// Exact original ingress packet bytes.
    #[must_use]
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }
}

impl fmt::Debug for AuthenticatedIngressRedirectData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedIngressRedirectData")
            .field("frame_identity", &"[redacted]")
            .field("hop_count", &self.hop_count)
            .field("hop_limit", &self.hop_limit)
            .field("ownership_generation", &"[redacted]")
            .field("ownership_key", &"[redacted]")
            .field("packet_len", &self.packet.len())
            .finish()
    }
}

/// Authenticated receipt correlated to one exact data epoch and sequence.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticatedIngressRedirectReceipt {
    acknowledged_epoch: IngressRedirectProtectionEpoch,
    acknowledged_sequence: u64,
    code: IngressRedirectReceiptCode,
}

impl fmt::Debug for AuthenticatedIngressRedirectReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedIngressRedirectReceipt")
            .field("correlation", &"[redacted]")
            .field("code", &self.code)
            .finish()
    }
}

impl AuthenticatedIngressRedirectReceipt {
    /// Acknowledged data epoch.
    #[must_use]
    pub const fn acknowledged_epoch(self) -> IngressRedirectProtectionEpoch {
        self.acknowledged_epoch
    }

    /// Acknowledged data sequence.
    #[must_use]
    pub const fn acknowledged_sequence(self) -> u64 {
        self.acknowledged_sequence
    }

    /// Delivery or typed-rejection result.
    #[must_use]
    pub const fn code(self) -> IngressRedirectReceiptCode {
        self.code
    }
}

/// Original packet admitted at the exact fresh fenced-owner effect point.
#[derive(PartialEq, Eq)]
pub struct DeliveredIngressRedirectPacket {
    ownership_key: SessionOwnershipKey,
    ownership_generation: FencedOwnershipGeneration,
    hop_count: u8,
    packet: Vec<u8>,
}

impl DeliveredIngressRedirectPacket {
    /// Exact canonical ownership key proven at delivery.
    #[must_use]
    pub const fn ownership_key(&self) -> SessionOwnershipKey {
        self.ownership_key
    }

    /// Exact fresh fenced generation proven at delivery.
    #[must_use]
    pub const fn ownership_generation(&self) -> FencedOwnershipGeneration {
        self.ownership_generation
    }

    /// Authenticated redirect count at delivery.
    #[must_use]
    pub const fn hop_count(&self) -> u8 {
        self.hop_count
    }

    /// Exact original ingress packet bytes.
    #[must_use]
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Consume the value into exact original ingress packet bytes.
    #[must_use]
    pub fn into_packet(self) -> Vec<u8> {
        self.packet
    }
}

impl fmt::Debug for DeliveredIngressRedirectPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveredIngressRedirectPacket")
            .field("ownership_key", &"[redacted]")
            .field("ownership_generation", &"[redacted]")
            .field("hop_count", &self.hop_count)
            .field("packet_len", &self.packet.len())
            .finish()
    }
}

fn sender_identity_digest(identity: &str) -> [u8; INGRESS_REDIRECT_SENDER_DIGEST_LEN] {
    let mut digest = Sha256::new();
    digest.update(b"opc-ipsec-lb/ingress-redirect/sender/v1");
    digest.update((identity.len() as u64).to_be_bytes());
    digest.update(identity.as_bytes());
    digest.finalize().into()
}

fn canonical_routing_domains(
    domains: &[RoutingDomainTag],
) -> Result<Arc<[RoutingDomainTag]>, IngressRedirectError> {
    if domains.is_empty() || domains.len() > MAX_REDIRECT_ROUTING_DOMAINS {
        return Err(IngressRedirectError::InvalidPeerManifest);
    }
    let mut canonical = domains.to_vec();
    canonical.sort_unstable();
    canonical.dedup();
    if canonical.is_empty() || canonical.len() > MAX_REDIRECT_ROUTING_DOMAINS {
        return Err(IngressRedirectError::InvalidPeerManifest);
    }
    Ok(Arc::from(canonical))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DestinationContext, EspEncapsulationKind, EspOwnershipKey, EspSpi, IpAddress};
    use opc_session_store::{
        FencedOwnershipCacheConfig, FencedOwnershipNamespace, TokioVirtualClock,
    };
    use opc_types::{NetworkFunctionKind, TenantId};

    fn owner(value: &str) -> OwnerId {
        OwnerId::new(value).expect("valid owner")
    }

    fn profile(mode: IngressRedirectSecurityMode) -> IngressRedirectProfile {
        IngressRedirectProfile::production(1_500)
            .expect("valid profile")
            .with_security_mode(mode)
    }

    fn key() -> SessionOwnershipKey {
        SessionOwnershipKey::Esp(EspOwnershipKey::new(
            DestinationContext::new(IpAddress::V4([192, 0, 2, 10]), RoutingDomainTag::new(7)),
            EspEncapsulationKind::Native,
            EspSpi::new(0x0102_0304).expect("valid ESP SPI"),
        ))
    }

    fn pair(
        mode: IngressRedirectSecurityMode,
    ) -> (IngressRedirectPeerSession, IngressRedirectPeerSession) {
        let a_digest = sender_identity_digest("spiffe://example.test/a");
        let b_digest = sender_identity_digest("spiffe://example.test/b");
        let a_to_b = [0x11; 32];
        let b_to_a = [0x22; 32];
        let a = IngressRedirectPeerSession::for_test(
            profile(mode),
            owner("owner-a"),
            owner("owner-b"),
            9,
            a_to_b,
            b_to_a,
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            a_digest,
            b_digest,
        );
        let b = IngressRedirectPeerSession::for_test(
            profile(mode),
            owner("owner-b"),
            owner("owner-a"),
            9,
            b_to_a,
            a_to_b,
            [5, 6, 7, 8],
            [1, 2, 3, 4],
            b_digest,
            a_digest,
        );
        (a, b)
    }

    #[allow(clippy::too_many_arguments)]
    fn rotation_bootstrap(
        session: &IngressRedirectPeerSession,
        epoch: u64,
        send_key: [u8; 32],
        receive_key: [u8; 32],
        send_nonce_prefix: [u8; 4],
        receive_nonce_prefix: [u8; 4],
        hard_authenticated_deadline: Instant,
    ) -> IngressRedirectBootstrap {
        IngressRedirectBootstrap {
            profile: session.profile,
            local_owner: session.local_owner.clone(),
            peer_owner: session.peer_owner.clone(),
            local_sender_digest: session.local_sender_digest,
            peer_sender_digest: session.peer_sender_digest,
            routing_domains: Arc::clone(&session.routing_domains),
            local_udp_endpoint: session.local_udp_endpoint,
            peer_udp_endpoint: session.peer_udp_endpoint,
            epoch: IngressRedirectProtectionEpoch(epoch),
            send_key: Zeroizing::new(send_key),
            receive_key: Zeroizing::new(receive_key),
            send_nonce_prefix,
            receive_nonce_prefix,
            authentication_evidence: EpochAuthenticationEvidence::TestOnly,
            hard_authenticated_deadline,
        }
    }

    #[test]
    fn mtu_budget_accounts_for_outer_family_key_and_tag() {
        let aes = profile(IngressRedirectSecurityMode::Aes256Gcm);
        let hmac = profile(IngressRedirectSecurityMode::HmacSha256);
        let v4 = IngressRedirectMtuBudget::new(aes, "192.0.2.20".parse().unwrap(), 20)
            .expect("v4 budget");
        let v6 = IngressRedirectMtuBudget::new(aes, "2001:db8::20".parse().unwrap(), 20)
            .expect("v6 budget");
        let integrity = IngressRedirectMtuBudget::new(hmac, "192.0.2.20".parse().unwrap(), 20)
            .expect("integrity budget");
        assert_eq!(v4.outer_headers(), 28);
        assert_eq!(v6.outer_headers(), 48);
        assert_eq!(
            v4.maximum_original_packet() - v6.maximum_original_packet(),
            20
        );
        assert_eq!(
            v4.maximum_original_packet() - integrity.maximum_original_packet(),
            16
        );
        assert!(v4.admits(v4.maximum_original_packet()));
        assert!(!v4.admits(v4.maximum_original_packet() + 1));
    }

    #[test]
    fn profile_rejects_a_hop_limit_that_cannot_deliver_first_redirect() {
        assert_eq!(
            profile(IngressRedirectSecurityMode::Aes256Gcm).with_hop_limit(1),
            Err(IngressRedirectConfigError::InvalidHopLimit)
        );
        assert!(profile(IngressRedirectSecurityMode::Aes256Gcm)
            .with_hop_limit(2)
            .is_ok());
    }

    #[test]
    fn profile_authentication_age_must_exceed_staging_and_overlap_horizons() {
        let profile = profile(IngressRedirectSecurityMode::HmacSha256)
            .with_rotation_overlap(Duration::from_secs(5))
            .unwrap_or_else(|error| panic!("valid short overlap: {error}"));
        assert_eq!(
            profile.with_maximum_authentication_age(ROTATION_STAGING_TIMEOUT),
            Err(IngressRedirectConfigError::InvalidAuthenticationAge)
        );
        assert!(profile
            .with_maximum_authentication_age(
                ROTATION_STAGING_TIMEOUT.saturating_add(Duration::from_millis(1)),
            )
            .is_ok());

        let longer_overlap = profile
            .with_rotation_overlap(Duration::from_secs(60))
            .unwrap_or_else(|error| panic!("valid longer overlap: {error}"));
        assert_eq!(
            longer_overlap.with_maximum_authentication_age(Duration::from_secs(60)),
            Err(IngressRedirectConfigError::InvalidAuthenticationAge)
        );
    }

    #[test]
    fn profile_receipt_cache_is_manifest_bounded_and_covers_packet_queue() {
        let profile = profile(IngressRedirectSecurityMode::HmacSha256);
        assert_eq!(
            profile.with_receipt_cache_entries(profile.queue_packets() - 1),
            Err(IngressRedirectConfigError::InvalidReceiptCache)
        );
        assert_eq!(
            profile.with_receipt_cache_entries(MAX_RECEIPT_CACHE_ENTRIES + 1),
            Err(IngressRedirectConfigError::InvalidReceiptCache)
        );
        let small = profile
            .with_queue_limits(1, 4_096)
            .and_then(|profile| profile.with_receipt_cache_entries(1))
            .unwrap_or_else(|error| panic!("valid one-entry cache: {error}"));
        assert_eq!(small.receipt_cache_entries(), 1);
    }

    #[test]
    fn control_operation_guard_serializes_rotation_lifecycle_mutations() {
        let (session, _) = pair(IngressRedirectSecurityMode::HmacSha256);
        let guard = session
            .begin_control_operation()
            .unwrap_or_else(|error| panic!("first control operation: {error}"));
        assert!(matches!(
            session.begin_control_operation(),
            Err(IngressRedirectError::RotationInProgress)
        ));
        drop(guard);
        assert!(session.begin_control_operation().is_ok());
    }

    #[test]
    fn hard_auth_deadline_is_capped_by_earliest_certificate_and_max_age() {
        let monotonic = Instant::now();
        let wall: Timestamp = "2026-07-18T00:00:00Z"
            .parse()
            .unwrap_or_else(|error| panic!("valid wall time: {error}"));
        let local_expiry: Timestamp = "2026-07-18T00:00:30Z"
            .parse()
            .unwrap_or_else(|error| panic!("valid local expiry: {error}"));
        let peer_expiry: Timestamp = "2026-07-18T00:00:10Z"
            .parse()
            .unwrap_or_else(|error| panic!("valid peer expiry: {error}"));
        assert_eq!(
            authenticated_epoch_deadline(
                monotonic,
                wall,
                local_expiry,
                peer_expiry,
                Duration::from_secs(20),
            ),
            monotonic
                .checked_add(Duration::from_secs(10))
                .ok_or(IngressRedirectError::StateUnavailable)
        );
        assert_eq!(
            authenticated_epoch_deadline(
                monotonic,
                wall,
                local_expiry,
                peer_expiry,
                Duration::from_secs(5),
            ),
            monotonic
                .checked_add(Duration::from_secs(5))
                .ok_or(IngressRedirectError::StateUnavailable)
        );
        assert_eq!(
            authenticated_epoch_deadline(
                monotonic,
                peer_expiry,
                local_expiry,
                peer_expiry,
                Duration::from_secs(5),
            ),
            Err(IngressRedirectError::AuthenticationExpired)
        );
    }

    #[test]
    fn hard_auth_deadline_rejects_open_at_the_exact_boundary() {
        let mode = IngressRedirectSecurityMode::HmacSha256;
        let (sender, _) = pair(mode);
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(10))
            .unwrap_or_else(|| panic!("valid deadline"));
        let receiver = IngressRedirectPeerSession::for_test_with_deadline(
            profile(mode),
            owner("owner-b"),
            owner("owner-a"),
            9,
            [0x22; 32],
            [0x11; 32],
            [5, 6, 7, 8],
            [1, 2, 3, 4],
            sender_identity_digest("spiffe://example.test/b"),
            sender_identity_digest("spiffe://example.test/a"),
            deadline,
        );
        let packet = synthetic_native_esp_packet();
        let sealed = sender
            .seal_data_with_generation(&packet, key().to_canonical_bytes(), 3, 1)
            .unwrap_or_else(|error| panic!("seal before deadline: {error}"));
        assert_eq!(
            receiver.open_at(&sealed, deadline),
            Err(IngressRedirectError::AuthenticationExpired)
        );
        assert_eq!(receiver.metrics().authentication_expired_drops, 1);
    }

    #[test]
    fn staged_rotation_accepts_new_receive_before_ack_and_bounds_old_epoch() {
        let mode = IngressRedirectSecurityMode::HmacSha256;
        let (a, b) = pair(mode);
        let now = Instant::now();
        let hard_deadline = now
            .checked_add(Duration::from_secs(120))
            .unwrap_or_else(|| panic!("valid deadline"));
        let old_packet = synthetic_native_esp_packet();
        let old_frame = a
            .seal_data_with_generation(&old_packet, key().to_canonical_bytes(), 3, 1)
            .unwrap_or_else(|error| panic!("seal old frame: {error}"));

        let a_token = a
            .stage_rotation_at(
                rotation_bootstrap(
                    &a,
                    10,
                    [0x33; 32],
                    [0x44; 32],
                    [9, 10, 11, 12],
                    [13, 14, 15, 16],
                    hard_deadline,
                ),
                now,
            )
            .unwrap_or_else(|error| panic!("stage A: {error}"));
        let b_token = b
            .stage_rotation_at(
                rotation_bootstrap(
                    &b,
                    10,
                    [0x44; 32],
                    [0x33; 32],
                    [13, 14, 15, 16],
                    [9, 10, 11, 12],
                    hard_deadline,
                ),
                now,
            )
            .unwrap_or_else(|error| panic!("stage B: {error}"));

        a.activate_rotation_at(&a_token, now + Duration::from_millis(1))
            .unwrap_or_else(|error| panic!("activate A after peer stage: {error}"));
        let new_frame = a
            .seal_data_with_generation(&old_packet, key().to_canonical_bytes(), 3, 1)
            .unwrap_or_else(|error| panic!("seal new frame: {error}"));
        assert!(b
            .open_at(&new_frame, now + Duration::from_millis(2))
            .is_ok());

        let reconciled = b
            .rotation_status()
            .unwrap_or_else(|error| panic!("rotation status: {error}"));
        assert_eq!(reconciled.current(), IngressRedirectProtectionEpoch(10));
        assert_eq!(reconciled.pending_receive(), None);

        b.activate_rotation_at(&b_token, now + Duration::from_millis(3))
            .unwrap_or_else(|error| panic!("activate B: {error}"));
        assert!(b
            .open_at(&old_frame, now + Duration::from_millis(4))
            .is_ok());
        let state = b
            .epochs
            .read()
            .unwrap_or_else(|error| panic!("read epoch state: {error}"));
        assert_eq!(state.current.epoch, IngressRedirectProtectionEpoch(10));
        assert!(state.pending.is_none());
        assert!(state.previous.is_some());
    }

    #[test]
    fn rotation_blocks_a_live_previous_epoch_then_purges_it_before_restaging() {
        let (session, _) = pair(IngressRedirectSecurityMode::HmacSha256);
        let now = Instant::now();
        let first_deadline = now
            .checked_add(Duration::from_secs(5 * 60))
            .unwrap_or_else(|| panic!("valid first deadline"));
        let first = session
            .stage_rotation_at(
                rotation_bootstrap(
                    &session,
                    10,
                    [0x33; 32],
                    [0x44; 32],
                    [9, 10, 11, 12],
                    [13, 14, 15, 16],
                    first_deadline,
                ),
                now,
            )
            .unwrap_or_else(|error| panic!("stage first rotation: {error}"));
        session
            .activate_rotation_at(&first, now + Duration::from_millis(1))
            .unwrap_or_else(|error| panic!("activate first rotation: {error}"));

        let second_deadline = now
            .checked_add(Duration::from_secs(10 * 60))
            .unwrap_or_else(|| panic!("valid second deadline"));
        assert!(matches!(
            session.stage_rotation_at(
                rotation_bootstrap(
                    &session,
                    11,
                    [0x55; 32],
                    [0x66; 32],
                    [17, 18, 19, 20],
                    [21, 22, 23, 24],
                    second_deadline,
                ),
                now + Duration::from_millis(2),
            ),
            Err(IngressRedirectError::RotationInProgress)
        ));

        let after_overlap = now
            .checked_add(session.profile().rotation_overlap())
            .and_then(|instant| instant.checked_add(Duration::from_millis(2)))
            .unwrap_or_else(|| panic!("valid post-overlap instant"));
        let second = session
            .stage_rotation_at(
                rotation_bootstrap(
                    &session,
                    11,
                    [0x55; 32],
                    [0x66; 32],
                    [17, 18, 19, 20],
                    [21, 22, 23, 24],
                    second_deadline,
                ),
                after_overlap,
            )
            .unwrap_or_else(|error| panic!("stage after previous expiry: {error}"));
        assert_eq!(second.epoch(), IngressRedirectProtectionEpoch(11));
        let state = session
            .epochs
            .read()
            .unwrap_or_else(|error| panic!("read epoch state: {error}"));
        assert!(state.previous.is_none());
        assert_eq!(
            state.pending.as_ref().map(|pending| pending.epoch.epoch),
            Some(IngressRedirectProtectionEpoch(11))
        );
    }

    #[test]
    fn expired_pending_epoch_is_purged_before_match_or_replacement_stage() {
        let (session, _) = pair(IngressRedirectSecurityMode::HmacSha256);
        let now = Instant::now();
        let deadline = now
            .checked_add(Duration::from_secs(5 * 60))
            .unwrap_or_else(|| panic!("valid deadline"));
        session
            .stage_rotation_at(
                rotation_bootstrap(
                    &session,
                    10,
                    [0x33; 32],
                    [0x44; 32],
                    [9, 10, 11, 12],
                    [13, 14, 15, 16],
                    deadline,
                ),
                now,
            )
            .unwrap_or_else(|error| panic!("stage expiring rotation: {error}"));
        let after_stage = now
            .checked_add(ROTATION_STAGING_TIMEOUT)
            .and_then(|instant| instant.checked_add(Duration::from_millis(1)))
            .unwrap_or_else(|| panic!("valid post-stage instant"));
        assert!(matches!(
            session.receive_epoch(10, after_stage),
            Err(IngressRedirectError::UnknownEpoch)
        ));
        let replacement = session
            .stage_rotation_at(
                rotation_bootstrap(
                    &session,
                    11,
                    [0x55; 32],
                    [0x66; 32],
                    [17, 18, 19, 20],
                    [21, 22, 23, 24],
                    deadline,
                ),
                after_stage,
            )
            .unwrap_or_else(|error| panic!("stage replacement: {error}"));
        assert_eq!(replacement.epoch(), IngressRedirectProtectionEpoch(11));
    }

    #[test]
    fn pending_epoch_promotes_only_after_crypto_and_sender_identity_authenticate() {
        let mode = IngressRedirectSecurityMode::HmacSha256;
        let (a, b) = pair(mode);
        let now = Instant::now();
        let hard_deadline = now
            .checked_add(Duration::from_secs(120))
            .unwrap_or_else(|| panic!("valid deadline"));
        let a_token = a
            .stage_rotation_at(
                rotation_bootstrap(
                    &a,
                    10,
                    [0x33; 32],
                    [0x44; 32],
                    [9, 10, 11, 12],
                    [13, 14, 15, 16],
                    hard_deadline,
                ),
                now,
            )
            .unwrap_or_else(|error| panic!("stage A: {error}"));
        let _b_token = b
            .stage_rotation_at(
                rotation_bootstrap(
                    &b,
                    10,
                    [0x44; 32],
                    [0x33; 32],
                    [13, 14, 15, 16],
                    [9, 10, 11, 12],
                    hard_deadline,
                ),
                now,
            )
            .unwrap_or_else(|error| panic!("stage B: {error}"));
        a.activate_rotation_at(&a_token, now + Duration::from_millis(1))
            .unwrap_or_else(|error| panic!("activate A: {error}"));
        let packet = synthetic_native_esp_packet();
        let valid = a
            .seal_data_with_generation(&packet, key().to_canonical_bytes(), 3, 1)
            .unwrap_or_else(|error| panic!("seal new frame: {error}"));

        let mut tampered = valid.clone();
        let last = tampered.len().saturating_sub(1);
        tampered[last] ^= 0x80;
        assert_eq!(
            b.open_at(&tampered, now + Duration::from_millis(2)),
            Err(IngressRedirectError::AuthenticationFailed)
        );
        assert_eq!(
            b.rotation_status()
                .unwrap_or_else(|error| panic!("status after tamper: {error}"))
                .current(),
            IngressRedirectProtectionEpoch(9)
        );

        let a_epoch = a
            .current_epoch()
            .unwrap_or_else(|error| panic!("A epoch: {error}"));
        let wrong_identity_header = IngressRedirectFrameHeader::data(
            mode,
            1,
            a.profile.hop_limit(),
            10,
            2,
            3,
            [0xff; INGRESS_REDIRECT_SENDER_DIGEST_LEN],
            key().to_canonical_bytes().len() as u16,
            packet.len() as u16,
        )
        .unwrap_or_else(|error| panic!("valid test header: {error}"));
        let wrong_identity = seal_frame(
            &a_epoch,
            mode,
            wrong_identity_header,
            &key().to_canonical_bytes(),
            &packet,
        )
        .unwrap_or_else(|error| panic!("seal wrong-identity frame: {error}"));
        assert_eq!(
            b.open_at(&wrong_identity, now + Duration::from_millis(3)),
            Err(IngressRedirectError::SenderIdentityMismatch)
        );
        assert_eq!(
            b.rotation_status()
                .unwrap_or_else(|error| panic!("status after identity mismatch: {error}"))
                .current(),
            IngressRedirectProtectionEpoch(9)
        );

        assert!(b.open_at(&valid, now + Duration::from_millis(4)).is_ok());
        assert_eq!(
            b.rotation_status()
                .unwrap_or_else(|error| panic!("status after valid frame: {error}"))
                .current(),
            IngressRedirectProtectionEpoch(10)
        );
    }

    #[test]
    fn rotation_rejects_candidate_without_full_staging_lifetime() {
        let (session, _) = pair(IngressRedirectSecurityMode::HmacSha256);
        let now = Instant::now();
        let insufficient_deadline = now
            .checked_add(ROTATION_STAGING_TIMEOUT - Duration::from_millis(1))
            .unwrap_or_else(|| panic!("valid insufficient deadline"));
        assert_eq!(
            session.stage_rotation_at(
                rotation_bootstrap(
                    &session,
                    10,
                    [0x33; 32],
                    [0x44; 32],
                    [9, 10, 11, 12],
                    [13, 14, 15, 16],
                    insufficient_deadline,
                ),
                now,
            ),
            Err(IngressRedirectError::AuthenticationExpired)
        );
        assert!(session
            .rotation_status()
            .unwrap_or_else(|error| panic!("rotation status: {error}"))
            .pending_receive()
            .is_none());
    }

    #[test]
    fn reconciliation_clears_asymmetric_non_target_pending_state() {
        let (session, _) = pair(IngressRedirectSecurityMode::HmacSha256);
        let now = Instant::now();
        let hard_deadline = now
            .checked_add(Duration::from_secs(20 * 60))
            .unwrap_or_else(|| panic!("valid deadline"));
        let token = session
            .stage_rotation_at(
                rotation_bootstrap(
                    &session,
                    10,
                    [0x33; 32],
                    [0x44; 32],
                    [9, 10, 11, 12],
                    [13, 14, 15, 16],
                    hard_deadline,
                ),
                now,
            )
            .unwrap_or_else(|error| panic!("stage rotation: {error}"));
        session
            .retain_pending_for_reconciliation(&token)
            .unwrap_or_else(|error| panic!("retain pending: {error}"));
        assert_eq!(
            session.reconcile_authenticated_epoch(IngressRedirectProtectionEpoch(9)),
            Ok(IngressRedirectProtectionEpoch(9))
        );
        assert!(session
            .rotation_status()
            .unwrap_or_else(|error| panic!("rotation status: {error}"))
            .pending_receive()
            .is_none());
    }

    #[test]
    fn reconciliation_rejects_expired_current_without_clearing_pending() {
        let (session, _) = pair(IngressRedirectSecurityMode::HmacSha256);
        let now = Instant::now();
        let hard_deadline = now
            .checked_add(Duration::from_secs(20 * 60))
            .unwrap_or_else(|| panic!("valid deadline"));
        let token = session
            .stage_rotation_at(
                rotation_bootstrap(
                    &session,
                    10,
                    [0x33; 32],
                    [0x44; 32],
                    [9, 10, 11, 12],
                    [13, 14, 15, 16],
                    hard_deadline,
                ),
                now,
            )
            .unwrap_or_else(|error| panic!("stage rotation: {error}"));
        session
            .retain_pending_for_reconciliation(&token)
            .unwrap_or_else(|error| panic!("retain pending: {error}"));
        {
            let mut state = session
                .epochs
                .write()
                .unwrap_or_else(|error| panic!("epoch state: {error}"));
            let current = Arc::get_mut(&mut state.current)
                .unwrap_or_else(|| panic!("unshared current epoch"));
            current.hard_authenticated_deadline = Instant::now();
        }

        assert_eq!(
            session.reconcile_authenticated_epoch(IngressRedirectProtectionEpoch(9)),
            Err(IngressRedirectError::AuthenticationExpired)
        );
        assert_eq!(
            session
                .rotation_status()
                .unwrap_or_else(|error| panic!("rotation status: {error}"))
                .pending_receive(),
            Some(IngressRedirectProtectionEpoch(10))
        );
    }

    #[test]
    fn outcome_unknown_pending_can_reconcile_after_stage_window() {
        let (session, _) = pair(IngressRedirectSecurityMode::HmacSha256);
        let now = Instant::now();
        let hard_deadline = now
            .checked_add(Duration::from_secs(20 * 60))
            .unwrap_or_else(|| panic!("valid deadline"));
        let token = session
            .stage_rotation_at(
                rotation_bootstrap(
                    &session,
                    10,
                    [0x33; 32],
                    [0x44; 32],
                    [9, 10, 11, 12],
                    [13, 14, 15, 16],
                    hard_deadline,
                ),
                now,
            )
            .unwrap_or_else(|error| panic!("stage rotation: {error}"));
        session
            .retain_pending_for_reconciliation(&token)
            .unwrap_or_else(|error| panic!("retain pending: {error}"));
        assert_eq!(
            session.activate_pending_from_authenticated_peer(
                10,
                now + ROTATION_STAGING_TIMEOUT + Duration::from_secs(1),
            ),
            Ok(())
        );
        assert_eq!(
            session
                .rotation_status()
                .unwrap_or_else(|error| panic!("rotation status: {error}"))
                .current(),
            IngressRedirectProtectionEpoch(10)
        );
    }

    #[test]
    fn sealing_enforces_exact_outer_mtu_inside_crypto_boundary() {
        let (sender, _) = pair(IngressRedirectSecurityMode::Aes256Gcm);
        let key = key();
        let budget = IngressRedirectMtuBudget::new(
            sender.profile,
            sender.peer_udp_endpoint.ip(),
            key.to_canonical_bytes().len(),
        )
        .unwrap_or_else(|error| panic!("valid budget: {error}"));
        let oversized = vec![0_u8; budget.maximum_original_packet() + 1];
        assert_eq!(
            sender.seal_data_with_generation(&oversized, key.to_canonical_bytes(), 3, 1),
            Err(IngressRedirectError::PacketTooLarge)
        );
    }

    #[test]
    fn replay_window_is_bounded_and_accepts_out_of_order_once() {
        let mut window = ReplayWindow::new(NonZeroU16::new(4).expect("non-zero"));
        assert_eq!(window.accept(4), Ok(()));
        assert_eq!(window.accept(2), Ok(()));
        assert_eq!(window.accept(3), Ok(()));
        assert_eq!(window.accept(2), Err(IngressRedirectError::ReplayRejected));
        assert_eq!(window.accept(8), Ok(()));
        assert_eq!(window.accept(4), Err(IngressRedirectError::ReplayRejected));
        assert!(window.accepted.len() <= 4);
    }

    #[test]
    fn aes_gcm_round_trip_preserves_packet_and_replay_fails() {
        let (sender, receiver) = pair(IngressRedirectSecurityMode::Aes256Gcm);
        let packet = synthetic_native_esp_packet();
        let sealed = sender
            .seal_data_with_generation(&packet, key().to_canonical_bytes(), 3, 1)
            .expect("seal");
        assert!(!sealed.windows(packet.len()).any(|window| window == packet));
        let opened = receiver.open(&sealed).expect("open");
        let AuthenticatedIngressRedirectFrame::Data(opened) = opened else {
            panic!("expected data")
        };
        assert_eq!(opened.packet(), packet);
        assert_eq!(opened.ownership_key(), key());
        assert_eq!(
            receiver.open(&sealed),
            Err(IngressRedirectError::ReplayRejected)
        );
        assert_eq!(receiver.metrics().replay_drops, 1);
    }

    #[test]
    fn hmac_round_trip_preserves_clear_packet_and_tamper_fails() {
        let (sender, receiver) = pair(IngressRedirectSecurityMode::HmacSha256);
        let packet = synthetic_native_esp_packet();
        let mut sealed = sender
            .seal_data_with_generation(&packet, key().to_canonical_bytes(), 3, 1)
            .expect("seal");
        assert!(sealed.windows(packet.len()).any(|window| window == packet));
        let last = sealed.len() - 1;
        sealed[last] ^= 0x80;
        assert_eq!(
            receiver.open(&sealed),
            Err(IngressRedirectError::AuthenticationFailed)
        );
    }

    #[test]
    fn authenticated_frames_with_truncated_or_trailing_body_shapes_fail_exact_length() {
        for mode in [
            IngressRedirectSecurityMode::Aes256Gcm,
            IngressRedirectSecurityMode::HmacSha256,
        ] {
            let (sender, receiver) = pair(mode);
            let packet = synthetic_native_esp_packet();
            let canonical_key = key().to_canonical_bytes();
            let epoch = sender
                .current_epoch()
                .unwrap_or_else(|error| panic!("current epoch: {error}"));
            for (sequence, claimed_packet_len) in [
                (41, packet.len().saturating_add(1)),
                (42, packet.len().saturating_sub(1)),
            ] {
                let header = IngressRedirectFrameHeader::data(
                    mode,
                    1,
                    sender.profile().hop_limit(),
                    epoch.epoch.get(),
                    sequence,
                    3,
                    sender.local_sender_digest,
                    u16::try_from(canonical_key.len())
                        .unwrap_or_else(|_| panic!("canonical key length")),
                    u16::try_from(claimed_packet_len).unwrap_or_else(|_| panic!("packet length")),
                )
                .unwrap_or_else(|error| panic!("hostile test header: {error}"));
                let sealed = seal_frame(&epoch, mode, header, &canonical_key, &packet)
                    .unwrap_or_else(|error| panic!("authenticate hostile shape: {error}"));
                assert_eq!(
                    receiver.open(&sealed),
                    Err(IngressRedirectError::MalformedFrame),
                    "mode {mode:?}, claimed length {claimed_packet_len}",
                );
            }
            assert_eq!(receiver.metrics().malformed_drops, 2);
            assert_eq!(receiver.metrics().frames_authenticated, 0);
        }
    }

    #[test]
    fn aes_gcm_new_seal_budget_is_shared_by_data_and_receipts() {
        let (sender, _receiver) = pair(IngressRedirectSecurityMode::Aes256Gcm);
        sender
            .set_current_aead_limits(2, 4, 2)
            .expect("set low AEAD limits");
        let packet = synthetic_native_esp_packet();
        sender
            .seal_data_with_generation(&packet, key().to_canonical_bytes(), 3, 1)
            .expect("first data seal");
        sender
            .seal_receipt(
                IngressRedirectProtectionEpoch(9),
                1,
                IngressRedirectReceiptCode::Delivered,
            )
            .expect("receipt shares seal budget");
        assert_eq!(
            sender.seal_data_with_generation(&packet, key().to_canonical_bytes(), 3, 1),
            Err(IngressRedirectError::AeadUsageExhausted)
        );
        let status = sender.aead_usage_status().expect("usage status");
        assert_eq!(status.newly_protected_frames_remaining(), Some(0));
        assert!(status.reauthentication_required());
        assert_eq!(sender.metrics().aead_seal_budget_exhausted, 1);
    }

    #[test]
    fn aes_gcm_successful_open_budget_retires_receive_epoch() {
        let (sender, receiver) = pair(IngressRedirectSecurityMode::Aes256Gcm);
        receiver
            .set_current_aead_limits(1, 4, 2)
            .expect("set low AEAD limits");
        let packet = synthetic_native_esp_packet();
        let first = sender
            .seal_data_with_generation(&packet, key().to_canonical_bytes(), 3, 1)
            .expect("first seal");
        let second = sender
            .seal_data_with_generation(&packet, key().to_canonical_bytes(), 3, 1)
            .expect("second seal");
        assert!(receiver.open(&first).is_ok());
        assert_eq!(
            receiver.open(&second),
            Err(IngressRedirectError::AeadUsageExhausted)
        );
        let status = receiver.aead_usage_status().expect("usage status");
        assert_eq!(status.successful_peer_opens_remaining(), Some(0));
        assert!(status.reauthentication_required());
        assert_eq!(receiver.metrics().aead_open_budget_exhausted, 1);
    }

    #[test]
    fn aes_gcm_failed_auth_budget_signals_then_retires_receive_key() {
        let (sender, receiver) = pair(IngressRedirectSecurityMode::Aes256Gcm);
        receiver
            .set_current_aead_limits(8, 2, 1)
            .expect("set low AEAD limits");
        let packet = synthetic_native_esp_packet();
        let valid = sender
            .seal_data_with_generation(&packet, key().to_canonical_bytes(), 3, 1)
            .expect("seal valid frame");
        let mut tampered = valid.clone();
        let last = tampered.len().saturating_sub(1);
        tampered[last] ^= 0x80;
        assert_eq!(
            receiver.open(&tampered),
            Err(IngressRedirectError::AuthenticationFailed)
        );
        assert_eq!(
            receiver.open(&tampered),
            Err(IngressRedirectError::AuthenticationFailed)
        );
        let status = receiver.aead_usage_status().expect("usage status");
        assert_eq!(status.failed_authentications_remaining(), Some(0));
        assert!(status.reauthentication_required());
        assert_eq!(receiver.metrics().aead_failed_auth_reauth_signals, 1);
        assert_eq!(receiver.metrics().aead_failed_auth_budget_exhausted, 1);
        assert_eq!(
            receiver.open(&valid),
            Err(IngressRedirectError::AeadUsageExhausted)
        );
    }

    #[test]
    fn hmac_mode_is_unaffected_by_aead_usage_limits() {
        let (sender, receiver) = pair(IngressRedirectSecurityMode::HmacSha256);
        sender
            .set_current_aead_limits(1, 1, 1)
            .expect("set low inert limits");
        receiver
            .set_current_aead_limits(1, 1, 1)
            .expect("set low inert limits");
        let packet = synthetic_native_esp_packet();
        for _ in 0..2 {
            let sealed = sender
                .seal_data_with_generation(&packet, key().to_canonical_bytes(), 3, 1)
                .expect("HMAC seal remains available");
            assert!(receiver.open(&sealed).is_ok());
        }
        let status = sender.aead_usage_status().expect("usage status");
        assert_eq!(status.newly_protected_frames_remaining(), None);
        assert!(!status.reauthentication_required());
    }

    #[test]
    fn unauthenticated_mode_cannot_downgrade_algorithm_or_tag_length() {
        let (sender, receiver) = pair(IngressRedirectSecurityMode::Aes256Gcm);
        let packet = synthetic_native_esp_packet();
        let mut sealed = sender
            .seal_data_with_generation(&packet, key().to_canonical_bytes(), 3, 1)
            .expect("seal");
        sealed[6] = IngressRedirectSecurityMode::HmacSha256 as u8;
        assert_eq!(
            receiver.open(&sealed),
            Err(IngressRedirectError::ProtectionModeMismatch)
        );
    }

    #[test]
    fn authenticated_but_wrong_sender_digest_is_rejected() {
        let (sender, receiver) = pair(IngressRedirectSecurityMode::HmacSha256);
        let packet = synthetic_native_esp_packet();
        let mut header = IngressRedirectFrameHeader::data(
            IngressRedirectSecurityMode::HmacSha256,
            1,
            4,
            9,
            1,
            3,
            [0xff; 32],
            key().to_canonical_bytes().len() as u16,
            packet.len() as u16,
        )
        .expect("header");
        let epoch = sender.current_epoch().expect("epoch");
        // Use a fresh sequence not consumed by the high-level sealer.
        header = IngressRedirectFrameHeader::data(
            header.security_mode(),
            header.hop_count(),
            header.hop_limit(),
            header.epoch(),
            2,
            header.ownership_generation(),
            header.sender_digest(),
            header.ownership_key_len(),
            header.packet_len(),
        )
        .expect("fresh header");
        let sealed = seal_frame(
            &epoch,
            IngressRedirectSecurityMode::HmacSha256,
            header,
            &key().to_canonical_bytes(),
            &packet,
        )
        .expect("seal with test sender digest");
        assert_eq!(
            receiver.open(&sealed),
            Err(IngressRedirectError::SenderIdentityMismatch)
        );
    }

    #[test]
    fn authenticated_hop_limit_must_equal_negotiated_profile() {
        let (sender, receiver) = pair(IngressRedirectSecurityMode::HmacSha256);
        let packet = synthetic_native_esp_packet();
        let header = IngressRedirectFrameHeader::data(
            IngressRedirectSecurityMode::HmacSha256,
            1,
            3,
            9,
            1,
            3,
            sender.local_sender_digest,
            key().to_canonical_bytes().len() as u16,
            packet.len() as u16,
        )
        .expect("structurally valid lower hop limit");
        let epoch = sender.current_epoch().expect("epoch");
        let sealed = seal_frame(
            &epoch,
            IngressRedirectSecurityMode::HmacSha256,
            header,
            &key().to_canonical_bytes(),
            &packet,
        )
        .expect("authenticated test frame");
        assert_eq!(
            receiver.open(&sealed),
            Err(IngressRedirectError::HopLimitMismatch)
        );
        assert_eq!(receiver.metrics().hop_profile_drops, 1);
    }

    #[test]
    fn routing_domain_manifest_rejects_unadmitted_domain() {
        let (sender, receiver) = pair(IngressRedirectSecurityMode::HmacSha256);
        assert_eq!(sender.routing_domains.as_ref(), &[RoutingDomainTag::new(7)]);

        let unauthorized_key = SessionOwnershipKey::Esp(EspOwnershipKey::new(
            DestinationContext::new(IpAddress::V4([192, 0, 2, 10]), RoutingDomainTag::new(8)),
            EspEncapsulationKind::Native,
            EspSpi::new(0x0102_0304).expect("valid ESP SPI"),
        ));
        let packet = synthetic_native_esp_packet();
        let sealed = sender
            .seal_data_with_generation(&packet, unauthorized_key.to_canonical_bytes(), 3, 1)
            .expect("test-only frame bypasses sender admission");
        let AuthenticatedIngressRedirectFrame::Data(data) =
            receiver.open(&sealed).expect("authenticated frame")
        else {
            panic!("expected data")
        };
        let cache = FencedOwnershipCache::new(
            FencedOwnershipNamespace::new(
                TenantId::new("redirect-tests").expect("tenant"),
                NetworkFunctionKind::new("epdg").expect("NF kind"),
            ),
            TokioVirtualClock::new(),
            FencedOwnershipCacheConfig {
                max_staleness: Duration::from_secs(1),
                max_entries: 1,
                max_retained_bytes: 1_024,
            },
        )
        .expect("cache");
        assert_eq!(
            receiver.validate_delivery(data, &cache),
            Err(IngressRedirectError::RoutingDomainNotAuthorized)
        );
        assert_eq!(receiver.metrics().routing_domain_drops, 1);
    }

    fn synthetic_native_esp_packet() -> Vec<u8> {
        let mut packet = vec![0_u8; 36];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&36_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 50;
        packet[12..16].copy_from_slice(&[198, 51, 100, 7]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 10]);
        packet[20..24].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
        packet[24..28].copy_from_slice(&1_u32.to_be_bytes());
        packet[28..].copy_from_slice(&[0x5a; 8]);
        packet
    }
}
