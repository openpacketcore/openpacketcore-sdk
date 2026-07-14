//! Bounded authentication lifetime for session transport connections.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opc_redaction::metrics::METRICS;
use sha2::{Digest, Sha256};
use tokio::sync::watch;

/// Default maximum age of one authenticated session transport connection.
pub const DEFAULT_MAX_AUTHENTICATION_AGE: Duration = Duration::from_secs(15 * 60);
/// Default transport wait and connection/task-slot ownership after retirement
/// starts; this does not prove backend completion or rollback.
pub const DEFAULT_ROTATION_DRAIN_WINDOW: Duration = Duration::from_secs(30);
/// Default first delay between reconnect attempts.
pub const DEFAULT_RECONNECT_BACKOFF_MIN: Duration = Duration::from_millis(50);
/// Default maximum delay between reconnect attempts.
pub const DEFAULT_RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(1);
/// Default per-peer spread applied when a material epoch changes.
pub const DEFAULT_ROTATION_JITTER: Duration = Duration::from_secs(30);

/// Invalid connection lifecycle configuration or exhausted control state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectionLifecycleError {
    /// A required duration was zero, values were ordered incorrectly, or a
    /// duration was not representable. Rotation jitter may be zero.
    #[error("session connection lifecycle policy is invalid")]
    InvalidPolicy,
    /// The monotonic explicit-reauthentication generation was exhausted.
    #[error("session reauthentication generation is exhausted")]
    GenerationExhausted,
}

/// One validated, finite lifecycle policy shared by clients and servers.
///
/// `maximum_authentication_age` bounds how long a completed authentication can
/// serve new operations. `rotation_drain_window` bounds how long the transport
/// waits for already-admitted work and retains its connection/task slot after
/// retirement. It does not prove backend completion or rollback: dropping a
/// backend future requests cancellation, but bounded supervised mutation work
/// may finish later. That outcome remains typed ambiguous and must never be
/// replayed automatically. Reconnect attempts use exponential backoff between
/// the inclusive minimum and maximum. Material rotation is spread by a stable
/// per-peer jitter in `[0, rotation_jitter]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionLifecyclePolicy {
    maximum_authentication_age: Duration,
    rotation_drain_window: Duration,
    reconnect_backoff_min: Duration,
    reconnect_backoff_max: Duration,
    rotation_jitter: Duration,
}

impl ConnectionLifecyclePolicy {
    /// Validate and construct a finite lifecycle policy.
    pub fn try_new(
        maximum_authentication_age: Duration,
        rotation_drain_window: Duration,
        reconnect_backoff_min: Duration,
        reconnect_backoff_max: Duration,
        rotation_jitter: Duration,
    ) -> Result<Self, ConnectionLifecycleError> {
        if maximum_authentication_age.is_zero()
            || rotation_drain_window.is_zero()
            || reconnect_backoff_min.is_zero()
            || reconnect_backoff_max.is_zero()
            || reconnect_backoff_min > reconnect_backoff_max
            || rotation_drain_window > maximum_authentication_age
            || rotation_jitter > maximum_authentication_age
        {
            return Err(ConnectionLifecycleError::InvalidPolicy);
        }
        let rotation_hard_span = rotation_jitter
            .checked_add(rotation_drain_window)
            .ok_or(ConnectionLifecycleError::InvalidPolicy)?;
        let now = tokio::time::Instant::now();
        if now.checked_add(maximum_authentication_age).is_none()
            || now.checked_add(rotation_drain_window).is_none()
            || now.checked_add(reconnect_backoff_max).is_none()
            || now.checked_add(rotation_jitter).is_none()
            || now.checked_add(rotation_hard_span).is_none()
        {
            return Err(ConnectionLifecycleError::InvalidPolicy);
        }
        Ok(Self {
            maximum_authentication_age,
            rotation_drain_window,
            reconnect_backoff_min,
            reconnect_backoff_max,
            rotation_jitter,
        })
    }

    /// Maximum age after a completed handshake before retirement.
    pub const fn maximum_authentication_age(self) -> Duration {
        self.maximum_authentication_age
    }

    /// Maximum transport wait and connection/task-slot ownership after
    /// retirement begins.
    ///
    /// This does not bound completion of already-admitted bounded supervised
    /// backend work; such late completion retains typed ambiguity and no-replay
    /// semantics.
    pub const fn rotation_drain_window(self) -> Duration {
        self.rotation_drain_window
    }

    /// First reconnect delay.
    pub const fn reconnect_backoff_min(self) -> Duration {
        self.reconnect_backoff_min
    }

    /// Maximum reconnect delay.
    pub const fn reconnect_backoff_max(self) -> Duration {
        self.reconnect_backoff_max
    }

    /// Maximum stable material-rotation spread.
    pub const fn rotation_jitter(self) -> Duration {
        self.rotation_jitter
    }

    pub(crate) fn validate_at(
        self,
        now: tokio::time::Instant,
    ) -> Result<(), ConnectionLifecycleError> {
        let rotation_hard_span = self
            .rotation_jitter
            .checked_add(self.rotation_drain_window)
            .ok_or(ConnectionLifecycleError::InvalidPolicy)?;
        if now.checked_add(self.maximum_authentication_age).is_none()
            || now.checked_add(self.rotation_drain_window).is_none()
            || now.checked_add(self.reconnect_backoff_max).is_none()
            || now.checked_add(self.rotation_jitter).is_none()
            || now.checked_add(rotation_hard_span).is_none()
        {
            return Err(ConnectionLifecycleError::InvalidPolicy);
        }
        Ok(())
    }

    pub(crate) fn deterministic_jitter(self, peer_key: &[u8]) -> Duration {
        if self.rotation_jitter.is_zero() {
            return Duration::ZERO;
        }
        let digest = Sha256::digest(peer_key);
        let mut prefix = [0_u8; 16];
        prefix.copy_from_slice(&digest[..16]);
        let sample = u128::from_be_bytes(prefix);
        let ceiling = self.rotation_jitter.as_nanos();
        let nanos = sample % ceiling.saturating_add(1);
        let seconds = u64::try_from(nanos / 1_000_000_000).unwrap_or(u64::MAX);
        let subsecond_nanos = u32::try_from(nanos % 1_000_000_000).unwrap_or(999_999_999);
        Duration::new(seconds, subsecond_nanos)
    }

    pub(crate) fn next_backoff(self, current: Duration) -> Duration {
        current
            .checked_mul(2)
            .unwrap_or(self.reconnect_backoff_max)
            .min(self.reconnect_backoff_max)
    }
}

impl Default for ConnectionLifecyclePolicy {
    fn default() -> Self {
        Self::try_new(
            DEFAULT_MAX_AUTHENTICATION_AGE,
            DEFAULT_ROTATION_DRAIN_WINDOW,
            DEFAULT_RECONNECT_BACKOFF_MIN,
            DEFAULT_RECONNECT_BACKOFF_MAX,
            DEFAULT_ROTATION_JITTER,
        )
        .unwrap_or(Self {
            maximum_authentication_age: DEFAULT_MAX_AUTHENTICATION_AGE,
            rotation_drain_window: DEFAULT_ROTATION_DRAIN_WINDOW,
            reconnect_backoff_min: DEFAULT_RECONNECT_BACKOFF_MIN,
            reconnect_backoff_max: DEFAULT_RECONNECT_BACKOFF_MAX,
            rotation_jitter: DEFAULT_ROTATION_JITTER,
        })
    }
}

/// Cooperative, plaintext-free trigger for graceful connection reauthentication.
///
/// Callers may share one control across every session client and listener in a
/// process. Advancing it retires existing connections through their ordinary
/// drain path; it never aborts tasks and never enables an insecure fallback.
#[derive(Clone)]
pub struct SessionReauthenticationControl {
    inner: Arc<Mutex<watch::Sender<u64>>>,
}

impl SessionReauthenticationControl {
    /// Create a control at generation zero.
    pub fn new() -> Self {
        let (sender, _) = watch::channel(0);
        Self {
            inner: Arc::new(Mutex::new(sender)),
        }
    }

    /// Request graceful reauthentication and return the new generation.
    pub fn request_reauthentication(&self) -> Result<u64, ConnectionLifecycleError> {
        let sender = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = *sender.borrow();
        let next = current
            .checked_add(1)
            .ok_or(ConnectionLifecycleError::GenerationExhausted)?;
        sender.send_replace(next);
        Ok(next)
    }

    /// Current process-local request generation.
    pub fn generation(&self) -> u64 {
        *self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .borrow()
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .subscribe()
    }
}

impl Default for SessionReauthenticationControl {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SessionReauthenticationControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionReauthenticationControl")
            .field("generation", &self.generation())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetirementReason {
    MaximumAge,
    LocalLeafExpiry,
    PeerLeafExpiry,
    LocalCertificateChainExpiry,
    PeerCertificateChainExpiry,
    MaterialEpoch,
    Explicit,
    IdleTimeout,
}

const LIFECYCLE_METRIC_ACTIVE: u8 = 0;
const LIFECYCLE_METRIC_DRAINING: u8 = 1;

#[derive(Debug)]
struct LifecycleConnectionMetrics {
    state: AtomicU8,
    hard_overrun_recorded: AtomicBool,
}

impl LifecycleConnectionMetrics {
    fn new() -> Self {
        METRICS
            .session_net_lifecycle_active_connections
            .fetch_add(1, Ordering::Relaxed);
        Self {
            state: AtomicU8::new(LIFECYCLE_METRIC_ACTIVE),
            hard_overrun_recorded: AtomicBool::new(false),
        }
    }

    fn begin_draining(&self) {
        if self
            .state
            .compare_exchange(
                LIFECYCLE_METRIC_ACTIVE,
                LIFECYCLE_METRIC_DRAINING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        decrement_gauge(&METRICS.session_net_lifecycle_active_connections);
        METRICS
            .session_net_lifecycle_draining_connections
            .fetch_add(1, Ordering::Relaxed);
        METRICS
            .session_net_lifecycle_drain_started
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_hard_overrun(&self) {
        self.begin_draining();
        if !self.hard_overrun_recorded.swap(true, Ordering::AcqRel) {
            METRICS
                .session_net_lifecycle_drain_overruns
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Drop for LifecycleConnectionMetrics {
    fn drop(&mut self) {
        match self.state.load(Ordering::Acquire) {
            LIFECYCLE_METRIC_DRAINING => {
                decrement_gauge(&METRICS.session_net_lifecycle_draining_connections);
                METRICS
                    .session_net_lifecycle_drain_completed
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => decrement_gauge(&METRICS.session_net_lifecycle_active_connections),
        }
    }
}

fn decrement_gauge(gauge: &AtomicI64) {
    let _ = gauge.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(1).max(0))
    });
}

impl RetirementReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::MaximumAge => "maximum_age",
            Self::LocalLeafExpiry => "local_leaf_expiry",
            Self::PeerLeafExpiry => "peer_leaf_expiry",
            Self::LocalCertificateChainExpiry => "local_certificate_chain_expiry",
            Self::PeerCertificateChainExpiry => "peer_certificate_chain_expiry",
            Self::MaterialEpoch => "material_epoch",
            Self::Explicit => "explicit",
            Self::IdleTimeout => "idle_timeout",
        }
    }

    fn retirement_counter(self) -> &'static std::sync::atomic::AtomicU64 {
        match self {
            Self::MaximumAge => &METRICS.session_net_lifecycle_retirement_maximum_age,
            Self::LocalLeafExpiry => &METRICS.session_net_lifecycle_retirement_local_leaf_expiry,
            Self::PeerLeafExpiry => &METRICS.session_net_lifecycle_retirement_peer_leaf_expiry,
            Self::LocalCertificateChainExpiry => {
                &METRICS.session_net_lifecycle_retirement_local_certificate_chain_expiry
            }
            Self::PeerCertificateChainExpiry => {
                &METRICS.session_net_lifecycle_retirement_peer_certificate_chain_expiry
            }
            Self::MaterialEpoch => &METRICS.session_net_lifecycle_retirement_material_epoch,
            Self::Explicit => &METRICS.session_net_lifecycle_retirement_explicit,
            Self::IdleTimeout => &METRICS.session_net_lifecycle_retirement_idle_timeout,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ConnectionLifecycle {
    policy: ConnectionLifecyclePolicy,
    evidence: ConnectionAuthenticationEvidence,
    retire_at: tokio::time::Instant,
    hard_deadline: tokio::time::Instant,
    reason: RetirementReason,
    generation: u64,
    rotation_retire_at: Option<(tokio::time::Instant, RetirementReason)>,
    retirement_recorded: Arc<AtomicBool>,
    metrics: Arc<LifecycleConnectionMetrics>,
}

#[derive(Clone, Copy)]
#[allow(dead_code)] // retained as exact per-connection authentication evidence
struct ConnectionAuthenticationEvidence {
    handshake_completed_at: tokio::time::Instant,
    local_certificate_expiry: Option<CertificateExpiryEvidence>,
    peer_certificate_expiry: Option<CertificateExpiryEvidence>,
    material_epoch: Option<opc_tls::TlsMaterialEpoch>,
}

impl fmt::Debug for ConnectionAuthenticationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionAuthenticationEvidence")
            .field("handshake_completed_at", &"<redacted>")
            .field(
                "local_certificate_expiry",
                &self.local_certificate_expiry.map(|_| "<redacted>"),
            )
            .field(
                "peer_certificate_expiry",
                &self.peer_certificate_expiry.map(|_| "<redacted>"),
            )
            .field("material_epoch", &self.material_epoch.map(|_| "<redacted>"))
            .finish()
    }
}

/// Exact leaf and effective presented-certificate-chain expiries plus the
/// monotonic deadline captured at TLS completion. Keeping all three values
/// prevents a later wall-clock adjustment or slow application bootstrap from
/// changing either the authenticated evidence or its fixed retirement reason.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CertificateExpiryEvidence {
    leaf_expires_at: opc_types::Timestamp,
    certificate_chain_expires_at: opc_types::Timestamp,
    deadline: tokio::time::Instant,
}

impl CertificateExpiryEvidence {
    pub(crate) fn capture(
        leaf_expires_at: opc_types::Timestamp,
        certificate_chain_expires_at: opc_types::Timestamp,
        tls_completed_at: tokio::time::Instant,
    ) -> Self {
        Self {
            leaf_expires_at,
            certificate_chain_expires_at,
            deadline: wall_expiry_deadline(
                leaf_expires_at.min(certificate_chain_expires_at),
                tls_completed_at,
            ),
        }
    }

    fn local_retirement_reason(self) -> RetirementReason {
        if self.certificate_chain_expires_at < self.leaf_expires_at {
            RetirementReason::LocalCertificateChainExpiry
        } else {
            RetirementReason::LocalLeafExpiry
        }
    }

    fn peer_retirement_reason(self) -> RetirementReason {
        if self.certificate_chain_expires_at < self.leaf_expires_at {
            RetirementReason::PeerCertificateChainExpiry
        } else {
            RetirementReason::PeerLeafExpiry
        }
    }
}

impl fmt::Debug for CertificateExpiryEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CertificateExpiryEvidence(<redacted>)")
    }
}

impl ConnectionLifecycle {
    pub(crate) fn new(
        policy: ConnectionLifecyclePolicy,
        established_at: tokio::time::Instant,
        local_certificate_expiry: Option<CertificateExpiryEvidence>,
        peer_certificate_expiry: Option<CertificateExpiryEvidence>,
        generation: u64,
        material_epoch: Option<opc_tls::TlsMaterialEpoch>,
    ) -> Result<Self, ConnectionLifecycleError> {
        policy.validate_at(established_at)?;
        let maximum_age_deadline = established_at
            .checked_add(policy.maximum_authentication_age())
            .ok_or(ConnectionLifecycleError::InvalidPolicy)?;
        // Rank ties deterministically: peer expiry, local expiry, then age.
        // This keeps diagnostics stable while the absolute hard bound remains
        // identical.
        let mut hard_deadline = maximum_age_deadline;
        let mut reason = RetirementReason::MaximumAge;
        if let Some(evidence) = local_certificate_expiry {
            let deadline = evidence.deadline.max(established_at);
            if deadline <= hard_deadline {
                hard_deadline = deadline;
                reason = evidence.local_retirement_reason();
            }
        }
        if let Some(evidence) = peer_certificate_expiry {
            let deadline = evidence.deadline.max(established_at);
            if deadline <= hard_deadline {
                hard_deadline = deadline;
                reason = evidence.peer_retirement_reason();
            }
        }
        let retire_at = hard_deadline
            .checked_sub(policy.rotation_drain_window())
            .unwrap_or(established_at)
            .max(established_at);
        Ok(Self {
            policy,
            evidence: ConnectionAuthenticationEvidence {
                handshake_completed_at: established_at,
                local_certificate_expiry,
                peer_certificate_expiry,
                material_epoch,
            },
            retire_at,
            hard_deadline,
            reason,
            generation,
            rotation_retire_at: None,
            retirement_recorded: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(LifecycleConnectionMetrics::new()),
        })
    }

    pub(crate) fn observe_rotation(
        &mut self,
        now: tokio::time::Instant,
        current_generation: u64,
        current_material_epoch: Option<opc_tls::TlsMaterialEpoch>,
        peer_key: &[u8],
    ) {
        let reason = if current_generation != self.generation {
            Some(RetirementReason::Explicit)
        } else if current_material_epoch != self.evidence.material_epoch {
            Some(RetirementReason::MaterialEpoch)
        } else {
            None
        };
        if let Some(reason) = reason {
            let deadline = now
                .checked_add(self.policy.deterministic_jitter(peer_key))
                .unwrap_or(now);
            if self
                .rotation_retire_at
                .is_none_or(|(current, _)| deadline < current)
            {
                self.rotation_retire_at = Some((deadline, reason));
            }
        }
    }

    pub(crate) const fn admitted_generation(&self) -> u64 {
        self.generation
    }

    pub(crate) const fn admitted_material_epoch(&self) -> Option<opc_tls::TlsMaterialEpoch> {
        self.evidence.material_epoch
    }

    #[cfg(feature = "legacy-session-net-compat")]
    pub(crate) const fn rotation_was_observed(&self) -> bool {
        self.rotation_retire_at.is_some()
    }

    pub(crate) fn evidence_mismatch_reason(
        &self,
        current_generation: u64,
        current_material_epoch: Option<opc_tls::TlsMaterialEpoch>,
    ) -> Option<RetirementReason> {
        if current_generation != self.generation {
            Some(RetirementReason::Explicit)
        } else if current_material_epoch != self.evidence.material_epoch {
            Some(RetirementReason::MaterialEpoch)
        } else {
            None
        }
    }

    pub(crate) fn record_forced_retirement(&self, reason: RetirementReason) {
        self.record_retirement(reason);
    }

    #[cfg(test)]
    pub(crate) fn recorded_retirement_count(&self) -> u8 {
        u8::from(self.retirement_recorded.load(Ordering::Acquire))
    }

    #[cfg(test)]
    pub(crate) fn expire_at_final_ack_boundary_for_test(&mut self) {
        self.rotation_retire_at = None;
        self.retire_at = tokio::time::Instant::now();
    }

    fn record_retirement(&self, reason: RetirementReason) {
        if self.retirement_recorded.swap(true, Ordering::Relaxed) {
            return;
        }
        self.metrics.begin_draining();
        reason.retirement_counter().fetch_add(1, Ordering::Relaxed);
        tracing::debug!(reason = reason.as_str(), "session connection retired");
    }

    pub(crate) fn retirement(&self, now: tokio::time::Instant) -> Option<RetirementReason> {
        let (deadline, reason) = self
            .rotation_retire_at
            .filter(|(deadline, _)| *deadline <= self.retire_at)
            .unwrap_or((self.retire_at, self.reason));
        if now < deadline {
            return None;
        }
        self.record_retirement(reason);
        Some(reason)
    }

    pub(crate) fn retire_at(&self) -> tokio::time::Instant {
        self.rotation_retire_at
            .map_or(self.retire_at, |(deadline, _)| deadline.min(self.retire_at))
    }

    pub(crate) fn hard_deadline(&self) -> Result<tokio::time::Instant, ConnectionLifecycleError> {
        let rotation_hard_deadline = self
            .rotation_retire_at
            .map(|(deadline, _)| {
                deadline
                    .checked_add(self.policy.rotation_drain_window())
                    .ok_or(ConnectionLifecycleError::InvalidPolicy)
            })
            .transpose()?;
        Ok(
            rotation_hard_deadline.map_or(self.hard_deadline, |deadline| {
                deadline.min(self.hard_deadline)
            }),
        )
    }

    pub(crate) fn record_hard_overrun(&self) {
        self.metrics.record_hard_overrun();
    }

    #[cfg(test)]
    fn evidence(&self) -> ConnectionAuthenticationEvidence {
        self.evidence
    }
}

pub(crate) fn wall_expiry_deadline(
    expiry: opc_types::Timestamp,
    now: tokio::time::Instant,
) -> tokio::time::Instant {
    let wall_now = opc_types::Timestamp::now_utc();
    let remaining = expiry
        .as_offset_datetime()
        .unix_timestamp_nanos()
        .saturating_sub(wall_now.as_offset_datetime().unix_timestamp_nanos());
    if remaining <= 0 {
        return now;
    }
    let seconds = remaining / 1_000_000_000;
    let nanos = remaining % 1_000_000_000;
    let Ok(seconds) = u64::try_from(seconds) else {
        return now;
    };
    let Ok(nanos) = u32::try_from(nanos) else {
        return now;
    };
    now.checked_add(Duration::new(seconds, nanos))
        .unwrap_or(now)
}

pub(crate) fn directed_connection_key(
    transport: &'static [u8],
    local_replica: &str,
    remote_replica: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"openpacketcore/session-net/lifecycle-edge/v1\0");
    for field in [
        transport,
        local_replica.as_bytes(),
        remote_replica.as_bytes(),
    ] {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

pub(crate) fn material_status_matches_admission(
    admitted_epoch: Option<opc_tls::TlsMaterialEpoch>,
    status: Option<opc_tls::TlsMaterialStatus>,
) -> bool {
    match (admitted_epoch, status) {
        (None, None) => true,
        (Some(epoch), Some(status)) => {
            status.epoch() == epoch
                && matches!(
                    status.availability(),
                    opc_tls::TlsMaterialAvailability::Ready
                        | opc_tls::TlsMaterialAvailability::RetainingLastGood
                )
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ConnectionLifecyclePolicy {
        ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            Duration::from_millis(10),
            Duration::from_millis(80),
            Duration::ZERO,
        )
        .expect("policy")
    }

    fn certificate_expiry_evidence(
        leaf_expires_at: opc_types::Timestamp,
        certificate_chain_expires_at: opc_types::Timestamp,
        deadline: tokio::time::Instant,
    ) -> CertificateExpiryEvidence {
        CertificateExpiryEvidence {
            leaf_expires_at,
            certificate_chain_expires_at,
            deadline,
        }
    }

    #[test]
    fn policy_rejects_unbounded_or_misordered_values() {
        assert_eq!(
            ConnectionLifecyclePolicy::try_new(
                Duration::ZERO,
                Duration::from_secs(1),
                Duration::from_millis(1),
                Duration::from_millis(2),
                Duration::ZERO,
            ),
            Err(ConnectionLifecycleError::InvalidPolicy)
        );
        assert_eq!(
            ConnectionLifecyclePolicy::try_new(
                Duration::MAX,
                Duration::from_secs(1),
                Duration::from_millis(1),
                Duration::from_millis(2),
                Duration::MAX,
            ),
            Err(ConnectionLifecycleError::InvalidPolicy)
        );
        assert_eq!(
            ConnectionLifecyclePolicy::try_new(
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_millis(2),
                Duration::from_millis(1),
                Duration::ZERO,
            ),
            Err(ConnectionLifecycleError::InvalidPolicy)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn earliest_age_or_leaf_expiry_retires_and_drain_is_bounded() {
        let now = tokio::time::Instant::now();
        let wall_now = opc_types::Timestamp::now_utc();
        let local_timestamp = wall_now.add_seconds(40).expect("local expiry");
        let peer_timestamp = wall_now.add_seconds(20).expect("peer expiry");
        let lifecycle = ConnectionLifecycle::new(
            policy(),
            now,
            Some(certificate_expiry_evidence(
                local_timestamp,
                local_timestamp,
                now + Duration::from_secs(40),
            )),
            Some(certificate_expiry_evidence(
                peer_timestamp,
                peer_timestamp,
                now + Duration::from_secs(20),
            )),
            0,
            None,
        )
        .expect("lifecycle");
        assert_eq!(lifecycle.retirement(now), None);
        assert_eq!(lifecycle.evidence().handshake_completed_at, now);
        assert_eq!(
            lifecycle
                .evidence()
                .peer_certificate_expiry
                .map(|value| value.leaf_expires_at),
            Some(peer_timestamp)
        );
        assert_eq!(
            lifecycle
                .evidence()
                .local_certificate_expiry
                .map(|value| value.leaf_expires_at),
            Some(local_timestamp)
        );
        assert_eq!(
            lifecycle
                .evidence()
                .peer_certificate_expiry
                .map(|value| value.deadline),
            Some(now + Duration::from_secs(20))
        );
        assert_eq!(
            lifecycle
                .evidence()
                .local_certificate_expiry
                .map(|value| value.deadline),
            Some(now + Duration::from_secs(40))
        );
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(
            lifecycle.retirement(tokio::time::Instant::now()),
            Some(RetirementReason::PeerLeafExpiry)
        );
        assert_eq!(
            lifecycle.hard_deadline().expect("hard deadline"),
            now + Duration::from_secs(20)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_shorter_than_drain_retires_immediately_and_peer_wins_ties() {
        let now = tokio::time::Instant::now();
        let expires_at = opc_types::Timestamp::now_utc()
            .add_seconds(5)
            .expect("expiry");
        let deadline = now + Duration::from_secs(5);
        let lifecycle = ConnectionLifecycle::new(
            policy(),
            now,
            Some(certificate_expiry_evidence(
                expires_at, expires_at, deadline,
            )),
            Some(certificate_expiry_evidence(
                expires_at, expires_at, deadline,
            )),
            0,
            None,
        )
        .expect("lifecycle");

        assert_eq!(lifecycle.retire_at(), now);
        assert_eq!(
            lifecycle.retirement(now),
            Some(RetirementReason::PeerLeafExpiry)
        );
        assert_eq!(lifecycle.hard_deadline().expect("hard deadline"), deadline);
    }

    #[tokio::test(start_paused = true)]
    async fn earlier_chain_expiry_uses_distinct_local_and_peer_reasons() {
        let now = tokio::time::Instant::now();
        let wall_now = opc_types::Timestamp::now_utc();
        let leaf_expires_at = wall_now.add_seconds(40).expect("leaf expiry");
        let chain_expires_at = wall_now.add_seconds(20).expect("chain expiry");
        let deadline = now + Duration::from_secs(20);
        let evidence = certificate_expiry_evidence(leaf_expires_at, chain_expires_at, deadline);

        let local = ConnectionLifecycle::new(policy(), now, Some(evidence), None, 0, None)
            .expect("local lifecycle");
        assert_eq!(
            local.retirement(now + Duration::from_secs(10)),
            Some(RetirementReason::LocalCertificateChainExpiry)
        );
        assert_eq!(
            RetirementReason::LocalCertificateChainExpiry.as_str(),
            "local_certificate_chain_expiry"
        );
        assert!(std::ptr::eq(
            RetirementReason::LocalCertificateChainExpiry.retirement_counter(),
            &METRICS.session_net_lifecycle_retirement_local_certificate_chain_expiry
        ));
        assert_eq!(
            local
                .evidence()
                .local_certificate_expiry
                .map(|value| value.certificate_chain_expires_at),
            Some(chain_expires_at)
        );

        let peer = ConnectionLifecycle::new(policy(), now, None, Some(evidence), 0, None)
            .expect("peer lifecycle");
        assert_eq!(
            peer.retirement(now + Duration::from_secs(10)),
            Some(RetirementReason::PeerCertificateChainExpiry)
        );
        assert_eq!(
            RetirementReason::PeerCertificateChainExpiry.as_str(),
            "peer_certificate_chain_expiry"
        );
        assert!(std::ptr::eq(
            RetirementReason::PeerCertificateChainExpiry.retirement_counter(),
            &METRICS.session_net_lifecycle_retirement_peer_certificate_chain_expiry
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn explicit_and_epoch_rotation_are_cooperative_and_stable() {
        let now = tokio::time::Instant::now();
        let mut lifecycle =
            ConnectionLifecycle::new(policy(), now, None, None, 3, None).expect("lifecycle");
        lifecycle.observe_rotation(now, 4, None, b"replica-a");
        assert_eq!(lifecycle.retirement(now), Some(RetirementReason::Explicit));
    }

    #[tokio::test(start_paused = true)]
    async fn lifecycle_transition_and_hard_overrun_are_shared_exactly_once() {
        let now = tokio::time::Instant::now();
        let lifecycle =
            ConnectionLifecycle::new(policy(), now, None, None, 0, None).expect("lifecycle");
        let sibling = lifecycle.clone();

        assert_eq!(
            lifecycle.metrics.state.load(Ordering::Acquire),
            LIFECYCLE_METRIC_ACTIVE
        );
        assert!(!lifecycle.retirement_recorded.load(Ordering::Acquire));
        lifecycle.record_forced_retirement(RetirementReason::Explicit);
        sibling.record_forced_retirement(RetirementReason::MaximumAge);
        assert!(lifecycle.retirement_recorded.load(Ordering::Acquire));
        assert_eq!(
            lifecycle.metrics.state.load(Ordering::Acquire),
            LIFECYCLE_METRIC_DRAINING
        );

        lifecycle.record_hard_overrun();
        sibling.record_hard_overrun();
        assert!(lifecycle
            .metrics
            .hard_overrun_recorded
            .load(Ordering::Acquire));
        assert!(Arc::ptr_eq(&lifecycle.metrics, &sibling.metrics));
    }

    #[test]
    fn jitter_is_deterministic_per_peer_and_backoff_is_bounded() {
        let jittered = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            Duration::from_millis(10),
            Duration::from_millis(40),
            Duration::from_secs(10),
        )
        .expect("policy");
        assert_eq!(
            jittered.deterministic_jitter(b"replica-a"),
            jittered.deterministic_jitter(b"replica-a")
        );
        assert_ne!(
            jittered.deterministic_jitter(b"replica-a"),
            jittered.deterministic_jitter(b"replica-b")
        );
        assert_eq!(
            jittered.next_backoff(Duration::from_millis(10)),
            Duration::from_millis(20)
        );
        assert_eq!(
            jittered.next_backoff(Duration::from_millis(40)),
            Duration::from_millis(40)
        );
    }

    #[test]
    fn explicit_control_is_monotonic_and_redacted() {
        let control = SessionReauthenticationControl::new();
        assert_eq!(control.generation(), 0);
        assert_eq!(control.request_reauthentication(), Ok(1));
        assert_eq!(control.generation(), 1);
        assert_eq!(
            format!("{control:?}"),
            "SessionReauthenticationControl { generation: 1 }"
        );
    }

    #[test]
    fn explicit_control_concurrent_requests_do_not_collapse_generations() {
        let control = SessionReauthenticationControl::new();
        let threads: Vec<_> = (0..32)
            .map(|_| {
                let control = control.clone();
                std::thread::spawn(move || control.request_reauthentication())
            })
            .collect();
        for thread in threads {
            assert!(thread.join().expect("join").is_ok());
        }
        assert_eq!(control.generation(), 32);
    }

    #[test]
    fn long_rotation_jitter_keeps_full_duration_range() {
        let jittered = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(u32::MAX.into()),
            Duration::from_secs(10),
            Duration::from_millis(10),
            Duration::from_millis(40),
            Duration::from_secs(u32::MAX.into()),
        )
        .expect("long policy");
        let jitter = jittered.deterministic_jitter(b"long-duration-peer");
        assert!(jitter <= jittered.rotation_jitter());
        assert_eq!(jitter, jittered.deterministic_jitter(b"long-duration-peer"));
    }

    #[test]
    fn directed_edges_are_stable_and_distributed() {
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            Duration::from_millis(10),
            Duration::from_millis(40),
            Duration::from_secs(10),
        )
        .expect("policy");
        let mut jitters = std::collections::BTreeSet::new();
        for local in 0..5 {
            for remote in 0..5 {
                if local == remote {
                    continue;
                }
                let key = directed_connection_key(
                    b"consensus",
                    &format!("replica-{local}"),
                    &format!("replica-{remote}"),
                );
                assert_eq!(
                    policy.deterministic_jitter(&key),
                    policy.deterministic_jitter(&key)
                );
                jitters.insert(policy.deterministic_jitter(&key));
            }
        }
        assert!(jitters.len() > 10, "directed edges must not collapse");
    }
}
