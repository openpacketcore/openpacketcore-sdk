//! Bounded authentication lifetime for session transport connections.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::sync::watch;

/// Default maximum age of one authenticated session transport connection.
pub const DEFAULT_MAX_AUTHENTICATION_AGE: Duration = Duration::from_secs(15 * 60);
/// Default time allowed for an operation already in flight when retirement starts.
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
/// serve new operations. `rotation_drain_window` bounds an operation that was
/// already in flight at retirement. Reconnect attempts use exponential backoff
/// between the inclusive minimum and maximum. Material rotation is spread by
/// a stable per-peer jitter in `[0, rotation_jitter]`.
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
        let now = tokio::time::Instant::now();
        if now.checked_add(maximum_authentication_age).is_none()
            || now.checked_add(rotation_drain_window).is_none()
            || now.checked_add(reconnect_backoff_max).is_none()
            || now.checked_add(rotation_jitter).is_none()
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

    /// Maximum drain allowed after retirement begins.
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
        if now.checked_add(self.maximum_authentication_age).is_none()
            || now.checked_add(self.rotation_drain_window).is_none()
            || now.checked_add(self.reconnect_backoff_max).is_none()
            || now.checked_add(self.rotation_jitter).is_none()
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
    MaterialEpoch,
    Explicit,
}

impl RetirementReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::MaximumAge => "maximum_age",
            Self::LocalLeafExpiry => "local_leaf_expiry",
            Self::PeerLeafExpiry => "peer_leaf_expiry",
            Self::MaterialEpoch => "material_epoch",
            Self::Explicit => "explicit",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ConnectionLifecycle {
    policy: ConnectionLifecyclePolicy,
    evidence: ConnectionAuthenticationEvidence,
    retire_at: tokio::time::Instant,
    hard_deadline: tokio::time::Instant,
    reason: RetirementReason,
    generation: u64,
    rotation_retire_at: Option<(tokio::time::Instant, RetirementReason)>,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // retained as exact per-connection authentication evidence
struct ConnectionAuthenticationEvidence {
    handshake_completed_at: tokio::time::Instant,
    local_leaf_expiry: Option<tokio::time::Instant>,
    peer_leaf_expiry: Option<tokio::time::Instant>,
    material_epoch: Option<opc_tls::TlsMaterialEpoch>,
}

impl ConnectionLifecycle {
    pub(crate) fn new(
        policy: ConnectionLifecyclePolicy,
        established_at: tokio::time::Instant,
        local_leaf_expiry: Option<tokio::time::Instant>,
        peer_leaf_expiry: Option<tokio::time::Instant>,
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
        if let Some(deadline) = local_leaf_expiry.map(|deadline| deadline.max(established_at)) {
            if deadline <= hard_deadline {
                hard_deadline = deadline;
                reason = RetirementReason::LocalLeafExpiry;
            }
        }
        if let Some(deadline) = peer_leaf_expiry.map(|deadline| deadline.max(established_at)) {
            if deadline <= hard_deadline {
                hard_deadline = deadline;
                reason = RetirementReason::PeerLeafExpiry;
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
                local_leaf_expiry,
                peer_leaf_expiry,
                material_epoch,
            },
            retire_at,
            hard_deadline,
            reason,
            generation,
            rotation_retire_at: None,
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

    pub(crate) fn retirement(self, now: tokio::time::Instant) -> Option<RetirementReason> {
        let (deadline, reason) = self
            .rotation_retire_at
            .filter(|(deadline, _)| *deadline <= self.retire_at)
            .unwrap_or((self.retire_at, self.reason));
        (now >= deadline).then_some(reason)
    }

    pub(crate) fn retire_at(self) -> tokio::time::Instant {
        self.rotation_retire_at
            .map_or(self.retire_at, |(deadline, _)| deadline.min(self.retire_at))
    }

    pub(crate) fn hard_deadline(self) -> Result<tokio::time::Instant, ConnectionLifecycleError> {
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

    #[cfg(test)]
    fn evidence(self) -> ConnectionAuthenticationEvidence {
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
        let lifecycle = ConnectionLifecycle::new(
            policy(),
            now,
            Some(now + Duration::from_secs(40)),
            Some(now + Duration::from_secs(20)),
            0,
            None,
        )
        .expect("lifecycle");
        assert_eq!(lifecycle.retirement(now), None);
        assert_eq!(lifecycle.evidence().handshake_completed_at, now);
        assert_eq!(
            lifecycle.evidence().peer_leaf_expiry,
            Some(now + Duration::from_secs(20))
        );
        assert_eq!(
            lifecycle.evidence().local_leaf_expiry,
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
    async fn explicit_and_epoch_rotation_are_cooperative_and_stable() {
        let now = tokio::time::Instant::now();
        let mut lifecycle =
            ConnectionLifecycle::new(policy(), now, None, None, 3, None).expect("lifecycle");
        lifecycle.observe_rotation(now, 4, None, b"replica-a");
        assert_eq!(lifecycle.retirement(now), Some(RetirementReason::Explicit));
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
