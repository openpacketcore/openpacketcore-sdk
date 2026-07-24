//! Origin-scoped Diameter End-to-End Identifier allocation.
//!
//! RFC 6733 section 3 combines an Origin-Host with an End-to-End Identifier
//! to detect duplicate requests. [`DiameterEndToEndIdentifierAuthority`]
//! provides the process-local half of that contract: one shared authority is
//! owned by exactly one Origin-Host and every new request receives one affine
//! [`DiameterEndToEndRequestIdentity`]. The identity is retained for every
//! retry and failover attempt of that request.
//!
//! The authority uses the RFC time-derived layout: the high 12 bits contain
//! the low 12 bits of the current UNIX second and the low 20 bits are a
//! collision-checked deterministic sequence. A bounded recent-use fence
//! prevents in-process reuse for four minutes under concurrency, sequence
//! wrap, and wall-clock jumps while the trusted monotonic fence remains valid.
//! The cross-process restart claim is conditional on the clock contract below.
//! Identifier generation uses no random fallback.
//!
//! # Restart contract
//!
//! Every constructor refuses allocation until the wall clock enters the next
//! second after initialization. Construction consumes an affine caller
//! attestation asserting exactly one live authority for the Origin-Host. The
//! clock's returned whole `unix_seconds` observations must be globally
//! nondecreasing across process incarnations and, for any two real instants
//! less than 240 seconds apart, differ by at most 4095 seconds.
//! The monotonic expiry clock must not report 240 seconds of advance before at
//! least 240 real seconds have elapsed; lag is conservative and permitted.
//! Deployments unable to trust the restart-time assumptions need durable
//! non-reuse state/range reservation or an independently trusted full
//! 240-second startup quarantine. A shared Origin-Host separately requires an
//! external singleton lease/fence or distinct Origin-Host values. This API
//! provides none of those distributed or durable mechanisms.
//!
//! This module does not allocate Hop-by-Hop Identifiers, select peers, retain
//! request bytes, or own application retry policy.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// RFC 6733's minimum local End-to-End Identifier uniqueness interval.
pub const DIAMETER_END_TO_END_IDENTIFIER_FENCE: Duration = Duration::from_secs(4 * 60);

/// Default maximum identifiers retained inside one origin scope.
pub const DEFAULT_DIAMETER_END_TO_END_IDENTIFIER_CAPACITY: usize = 65_536;

/// Hard upper bound for one authority's retained identifier table.
pub const MAX_DIAMETER_END_TO_END_IDENTIFIER_CAPACITY: usize = 1 << 20;

/// Maximum accepted byte length for an authority's Diameter Origin-Host.
///
/// This authority-specific resource bound supplements, but does not change,
/// the crate's shared nonempty-ASCII DiameterIdentity validation contract.
pub const MAX_DIAMETER_END_TO_END_ORIGIN_HOST_LEN: usize = 1_024;

const TIME_BITS: u32 = 12;
const SEQUENCE_BITS: u32 = 20;
const TIME_MASK: u32 = (1 << TIME_BITS) - 1;
const SEQUENCE_MASK: u32 = (1 << SEQUENCE_BITS) - 1;
const ORIGIN_SCOPE_FINGERPRINT_DOMAIN: &[u8] =
    b"openpacketcore-diameter-end-to-end-origin-scope-v1\0";

/// One coherent observation from an injectable identifier clock.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DiameterEndToEndIdentifierTime {
    unix_seconds: u64,
    monotonic: Duration,
}

impl DiameterEndToEndIdentifierTime {
    /// Construct a wall-time and monotonic-time observation.
    #[must_use]
    pub const fn new(unix_seconds: u64, monotonic: Duration) -> Self {
        Self {
            unix_seconds,
            monotonic,
        }
    }

    /// Return complete seconds since the UNIX epoch.
    #[must_use]
    pub const fn unix_seconds(self) -> u64 {
        self.unix_seconds
    }

    /// Return the process-monotonic elapsed time.
    #[must_use]
    pub const fn monotonic(self) -> Duration {
        self.monotonic
    }
}

impl fmt::Debug for DiameterEndToEndIdentifierTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterEndToEndIdentifierTime")
            .finish_non_exhaustive()
    }
}

/// Redaction-safe failure reported by an identifier clock.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiameterEndToEndIdentifierClockError {
    /// The time source could not produce a trustworthy observation.
    Unavailable,
}

impl DiameterEndToEndIdentifierClockError {
    /// Return the stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "diameter_end_to_end_identifier_clock_unavailable",
        }
    }
}

impl fmt::Display for DiameterEndToEndIdentifierClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for DiameterEndToEndIdentifierClockError {}

/// Injectable fallible wall and monotonic clock for identifier allocation.
///
/// Implementations are trusted process-local components. [`Self::now`] must
/// be nonblocking and panic-free. The authority independently rejects either
/// clock moving backward. Returned whole `unix_seconds` observations must be
/// nondecreasing and, for calls at real instants less than 240 seconds apart,
/// differ by at most 4095. The monotonic value is also trusted not to advance
/// by the four-minute fence duration before at least four real minutes have
/// elapsed; a lagging clock is conservative and permitted. The authority
/// attestation extends the wall-observation contract across process
/// incarnations.
pub trait DiameterEndToEndIdentifierClock: Send + Sync {
    /// Return one coherent wall-time and monotonic-time observation.
    fn now(&self) -> Result<DiameterEndToEndIdentifierTime, DiameterEndToEndIdentifierClockError>;
}

/// Production clock backed by [`SystemTime`] and a process-local [`Instant`].
#[derive(Debug, Clone)]
pub struct DiameterEndToEndIdentifierSystemClock {
    monotonic_anchor: Instant,
}

impl DiameterEndToEndIdentifierSystemClock {
    /// Create a production clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            monotonic_anchor: Instant::now(),
        }
    }
}

impl Default for DiameterEndToEndIdentifierSystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl DiameterEndToEndIdentifierClock for DiameterEndToEndIdentifierSystemClock {
    fn now(&self) -> Result<DiameterEndToEndIdentifierTime, DiameterEndToEndIdentifierClockError> {
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DiameterEndToEndIdentifierClockError::Unavailable)?
            .as_secs();
        Ok(DiameterEndToEndIdentifierTime::new(
            unix_seconds,
            self.monotonic_anchor.elapsed(),
        ))
    }
}

/// Bounded configuration for one origin-scoped authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiameterEndToEndIdentifierConfig {
    max_recent_identifiers: usize,
}

impl DiameterEndToEndIdentifierConfig {
    /// Construct a bounded authority configuration.
    ///
    /// # Errors
    ///
    /// Returns [`DiameterEndToEndIdentifierError::InvalidCapacity`] when the
    /// capacity is zero or exceeds
    /// [`MAX_DIAMETER_END_TO_END_IDENTIFIER_CAPACITY`].
    pub const fn new(
        max_recent_identifiers: usize,
    ) -> Result<Self, DiameterEndToEndIdentifierError> {
        if max_recent_identifiers == 0
            || max_recent_identifiers > MAX_DIAMETER_END_TO_END_IDENTIFIER_CAPACITY
        {
            return Err(DiameterEndToEndIdentifierError::InvalidCapacity);
        }
        Ok(Self {
            max_recent_identifiers,
        })
    }

    /// Return the maximum number of retained identifiers.
    #[must_use]
    pub const fn max_recent_identifiers(self) -> usize {
        self.max_recent_identifiers
    }
}

impl Default for DiameterEndToEndIdentifierConfig {
    fn default() -> Self {
        Self {
            max_recent_identifiers: DEFAULT_DIAMETER_END_TO_END_IDENTIFIER_CAPACITY,
        }
    }
}

/// Affine caller attestation required by one origin-scoped authority.
///
/// The private field prevents construction without calling the explicit
/// factory, and the value is consumed by one authority constructor. It is a
/// caller assertion, not an SDK-enforced distributed lease.
///
/// ```compile_fail
/// use opc_proto_diameter::end_to_end::DiameterEndToEndIdentifierAuthorityAttestation;
///
/// fn duplicate_attestation() -> Result<(), Box<dyn std::error::Error>> {
///     let attestation =
///         DiameterEndToEndIdentifierAuthorityAttestation::
///             attest_single_origin_owner_with_faithful_clocks(
///                 "origin.example.invalid",
///             )?;
///     let _duplicate = attestation.clone();
///     Ok(())
/// }
/// ```
pub struct DiameterEndToEndIdentifierAuthorityAttestation {
    origin_scope_fingerprint: OriginScopeFingerprint,
}

impl DiameterEndToEndIdentifierAuthorityAttestation {
    /// Attest the assumptions required for one Origin-Host authority.
    ///
    /// The caller attests all of the following:
    ///
    /// - the previous owner is gone before exactly one live authority takes
    ///   ownership of this Origin-Host;
    /// - returned whole `unix_seconds` observations are globally nondecreasing
    ///   across process incarnations and, for any two real instants less than
    ///   240 seconds apart, differ by at most 4095, so the low-12-bit prefix
    ///   cannot wrap inside the RFC duplicate interval; and
    /// - the monotonic expiry clock cannot advance by 240 seconds before at
    ///   least 240 real seconds have elapsed. It may lag conservatively.
    ///
    /// The Origin-Host is validated using the crate's nonempty-ASCII
    /// DiameterIdentity contract plus this authority's explicit 1024-byte
    /// resource bound. Only a case-insensitive, domain-separated SHA-256 scope
    /// fingerprint is retained.
    ///
    /// # Errors
    ///
    /// Returns [`DiameterEndToEndIdentifierError::InvalidOriginHost`] when
    /// `origin_host` is empty, non-ASCII, or exceeds
    /// [`MAX_DIAMETER_END_TO_END_ORIGIN_HOST_LEN`].
    #[must_use = "this affine attestation must be consumed by one authority constructor"]
    pub fn attest_single_origin_owner_with_faithful_clocks(
        origin_host: &str,
    ) -> Result<Self, DiameterEndToEndIdentifierError> {
        Ok(Self {
            origin_scope_fingerprint: origin_scope_fingerprint(origin_host)?,
        })
    }
}

impl fmt::Debug for DiameterEndToEndIdentifierAuthorityAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiameterEndToEndIdentifierAuthorityAttestation(<redacted>)")
    }
}

/// Stable, redaction-safe allocation failure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiameterEndToEndIdentifierError {
    /// The configured recent-identifier capacity is outside supported bounds.
    InvalidCapacity,
    /// The claimed Origin-Host violates the bounded DiameterIdentity contract.
    InvalidOriginHost,
    /// The request Origin-Host does not match the allocating authority.
    OriginHostMismatch,
    /// The injected clock could not provide a trustworthy observation.
    ClockUnavailable,
    /// The injected monotonic clock moved backward.
    MonotonicClockMovedBackward,
    /// The injected wall clock moved backward.
    WallClockMovedBackward,
    /// Restart quarantine has not reached a new wall-clock second.
    RestartFenceActive,
    /// The bounded recent-use table is full inside the protected interval.
    RecentWindowExhausted,
    /// Internal synchronized state is unavailable, invalid, or could not be reserved.
    StateUnavailable,
}

impl DiameterEndToEndIdentifierError {
    /// Return the stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCapacity => "diameter_end_to_end_identifier_invalid_capacity",
            Self::InvalidOriginHost => "diameter_end_to_end_identifier_invalid_origin_host",
            Self::OriginHostMismatch => "diameter_end_to_end_identifier_origin_host_mismatch",
            Self::ClockUnavailable => "diameter_end_to_end_identifier_clock_unavailable",
            Self::MonotonicClockMovedBackward => {
                "diameter_end_to_end_identifier_monotonic_clock_moved_backward"
            }
            Self::WallClockMovedBackward => {
                "diameter_end_to_end_identifier_wall_clock_moved_backward"
            }
            Self::RestartFenceActive => "diameter_end_to_end_identifier_restart_fence_active",
            Self::RecentWindowExhausted => "diameter_end_to_end_identifier_recent_window_exhausted",
            Self::StateUnavailable => "diameter_end_to_end_identifier_state_unavailable",
        }
    }
}

impl fmt::Display for DiameterEndToEndIdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for DiameterEndToEndIdentifierError {}

impl From<DiameterEndToEndIdentifierClockError> for DiameterEndToEndIdentifierError {
    fn from(_: DiameterEndToEndIdentifierClockError) -> Self {
        Self::ClockUnavailable
    }
}

/// Affine End-to-End duplicate identity assigned to exactly one new request.
///
/// This type is intentionally neither `Clone`, `Copy`, nor [`std::hash::Hash`].
/// Retain it, or the request envelope constructed from it, for every
/// retransmission instead of allocating again. Omitting `Hash` is part of the
/// authority boundary: a caller-controlled hasher must not observe the hidden
/// raw identifier or origin-scope fingerprint.
///
/// ```compile_fail
/// use opc_proto_diameter::end_to_end::DiameterEndToEndRequestIdentity;
///
/// fn accidentally_duplicate(identity: DiameterEndToEndRequestIdentity) {
///     let _second_identity = identity.clone();
/// }
/// ```
///
/// ```compile_fail
/// use std::hash::Hash;
/// use opc_proto_diameter::end_to_end::DiameterEndToEndRequestIdentity;
///
/// fn requires_hash<T: Hash>() {}
///
/// requires_hash::<DiameterEndToEndRequestIdentity>();
/// ```
#[must_use = "retain this identity for every retry and failover attempt of the request"]
#[derive(PartialEq, Eq)]
pub struct DiameterEndToEndRequestIdentity {
    identifier: u32,
    origin_scope_fingerprint: OriginScopeFingerprint,
}

impl DiameterEndToEndRequestIdentity {
    /// Consume this identity after matching the request's Origin-Host.
    ///
    /// DiameterIdentity matching is ASCII case-insensitive. The raw identifier
    /// is never exposed until this origin-scope check succeeds.
    ///
    /// # Errors
    ///
    /// Returns a typed, value-free error when `origin_host` is invalid or does
    /// not match the authority that allocated this identity.
    pub fn into_u32_for_origin_host(
        self,
        origin_host: &str,
    ) -> Result<u32, DiameterEndToEndIdentifierError> {
        let claimed_scope = origin_scope_fingerprint(origin_host)?;
        if !bool::from(self.origin_scope_fingerprint.0.ct_eq(&claimed_scope.0)) {
            return Err(DiameterEndToEndIdentifierError::OriginHostMismatch);
        }
        Ok(self.identifier)
    }
}

impl fmt::Debug for DiameterEndToEndRequestIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiameterEndToEndRequestIdentity(<redacted>)")
    }
}

#[derive(Clone, Copy)]
struct RecentIdentifier {
    identifier: u32,
    allocated_at: Duration,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct OriginScopeFingerprint([u8; 32]);

fn origin_scope_fingerprint(
    origin_host: &str,
) -> Result<OriginScopeFingerprint, DiameterEndToEndIdentifierError> {
    if origin_host.is_empty()
        || origin_host.len() > MAX_DIAMETER_END_TO_END_ORIGIN_HOST_LEN
        || !origin_host.is_ascii()
    {
        return Err(DiameterEndToEndIdentifierError::InvalidOriginHost);
    }
    let mut hasher = Sha256::new();
    hasher.update(ORIGIN_SCOPE_FINGERPRINT_DOMAIN);
    hasher.update((origin_host.len() as u64).to_be_bytes());
    for octet in origin_host.bytes() {
        hasher.update([octet.to_ascii_lowercase()]);
    }
    Ok(OriginScopeFingerprint(hasher.finalize().into()))
}

struct AuthorityState {
    last_unix_seconds: u64,
    last_monotonic: Duration,
    sequence_second: u64,
    next_sequence: u32,
    restart_after_second: Option<u64>,
    recent_order: VecDeque<RecentIdentifier>,
    recent: HashMap<u32, Duration>,
}

impl AuthorityState {
    fn new(
        config: DiameterEndToEndIdentifierConfig,
        now: DiameterEndToEndIdentifierTime,
    ) -> Result<Self, DiameterEndToEndIdentifierError> {
        let mut recent_order = VecDeque::new();
        recent_order
            .try_reserve(config.max_recent_identifiers)
            .map_err(|_| DiameterEndToEndIdentifierError::StateUnavailable)?;
        let mut recent = HashMap::new();
        recent
            .try_reserve(config.max_recent_identifiers)
            .map_err(|_| DiameterEndToEndIdentifierError::StateUnavailable)?;
        Ok(Self {
            last_unix_seconds: now.unix_seconds,
            last_monotonic: now.monotonic,
            sequence_second: now.unix_seconds,
            next_sequence: 0,
            restart_after_second: Some(now.unix_seconds),
            recent_order,
            recent,
        })
    }

    /// Validate and retain every coherent observation before later allocation
    /// checks. This high-water advances even when restart or capacity checks
    /// subsequently fail.
    fn observe_time(
        &mut self,
        now: DiameterEndToEndIdentifierTime,
    ) -> Result<(), DiameterEndToEndIdentifierError> {
        if now.monotonic < self.last_monotonic {
            return Err(DiameterEndToEndIdentifierError::MonotonicClockMovedBackward);
        }
        if now.unix_seconds < self.last_unix_seconds {
            return Err(DiameterEndToEndIdentifierError::WallClockMovedBackward);
        }
        self.last_unix_seconds = now.unix_seconds;
        self.last_monotonic = now.monotonic;
        Ok(())
    }

    fn validate_restart_fence(
        &self,
        now: DiameterEndToEndIdentifierTime,
    ) -> Result<(), DiameterEndToEndIdentifierError> {
        if self
            .restart_after_second
            .is_some_and(|restart_after_second| now.unix_seconds <= restart_after_second)
        {
            return Err(DiameterEndToEndIdentifierError::RestartFenceActive);
        }
        Ok(())
    }

    fn expired_count(&self, now: Duration) -> usize {
        self.recent_order
            .iter()
            .take_while(|entry| {
                now.saturating_sub(entry.allocated_at) >= DIAMETER_END_TO_END_IDENTIFIER_FENCE
            })
            .count()
    }

    fn is_protected(&self, identifier: u32, now: Duration) -> bool {
        self.recent.get(&identifier).is_some_and(|allocated_at| {
            now.saturating_sub(*allocated_at) < DIAMETER_END_TO_END_IDENTIFIER_FENCE
        })
    }

    fn expire_recent(&mut self, now: Duration) {
        while self.recent_order.front().is_some_and(|entry| {
            now.saturating_sub(entry.allocated_at) >= DIAMETER_END_TO_END_IDENTIFIER_FENCE
        }) {
            let Some(expired) = self.recent_order.pop_front() else {
                break;
            };
            self.recent.remove(&expired.identifier);
        }
    }
}

fn next_candidate(unix_seconds: u64, next_sequence: &mut u32) -> u32 {
    let time = (unix_seconds as u32) & TIME_MASK;
    let candidate = (time << SEQUENCE_BITS) | *next_sequence;
    *next_sequence = next_sequence.wrapping_add(1) & SEQUENCE_MASK;
    candidate
}

struct AuthorityInner {
    config: DiameterEndToEndIdentifierConfig,
    origin_scope_fingerprint: OriginScopeFingerprint,
    clock: Arc<dyn DiameterEndToEndIdentifierClock>,
    state: Mutex<AuthorityState>,
}

/// Bounded, concurrency-safe authority for one Diameter Origin-Host.
///
/// Clones share one allocation state. Independently constructed authorities
/// must never be live concurrently for the same Origin-Host.
#[derive(Clone)]
pub struct DiameterEndToEndIdentifierAuthority {
    inner: Arc<AuthorityInner>,
}

impl DiameterEndToEndIdentifierAuthority {
    /// Construct an authority using the production clock and default capacity.
    ///
    /// The first allocation may return
    /// [`DiameterEndToEndIdentifierError::RestartFenceActive`] until the wall
    /// clock enters the next second.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the initial clock observation fails or
    /// bounded state storage cannot be reserved.
    pub fn new(
        authority_attestation: DiameterEndToEndIdentifierAuthorityAttestation,
    ) -> Result<Self, DiameterEndToEndIdentifierError> {
        Self::with_clock(
            DiameterEndToEndIdentifierConfig::default(),
            Arc::new(DiameterEndToEndIdentifierSystemClock::new()),
            authority_attestation,
        )
    }

    /// Construct an authority from bounded configuration and injected clock.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the initial clock observation fails or
    /// bounded state storage cannot be reserved.
    pub fn with_clock(
        config: DiameterEndToEndIdentifierConfig,
        clock: Arc<dyn DiameterEndToEndIdentifierClock>,
        authority_attestation: DiameterEndToEndIdentifierAuthorityAttestation,
    ) -> Result<Self, DiameterEndToEndIdentifierError> {
        let now = clock.now()?;
        let state = AuthorityState::new(config, now)?;
        Ok(Self {
            inner: Arc::new(AuthorityInner {
                config,
                origin_scope_fingerprint: authority_attestation.origin_scope_fingerprint,
                clock,
                state: Mutex::new(state),
            }),
        })
    }

    /// Allocate one affine identity for a new Diameter request.
    ///
    /// Call this exactly once when creating a request. Timer retransmission and
    /// failover code must retain the returned identity or request envelope and
    /// never call `allocate` again for the same logical request.
    ///
    /// Every coherent clock observation advances the rollback high-water even
    /// if restart, capacity, or candidate checks subsequently fail. Those
    /// failures do not change the identifier cursor or recent-use fence.
    ///
    /// # Errors
    ///
    /// Returns a stable error for clock failure or rollback, active restart
    /// quarantine, synchronized-state failure, or bounded-window exhaustion.
    pub fn allocate(
        &self,
    ) -> Result<DiameterEndToEndRequestIdentity, DiameterEndToEndIdentifierError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| DiameterEndToEndIdentifierError::StateUnavailable)?;
        let now = self.inner.clock.now()?;
        state.observe_time(now)?;
        state.validate_restart_fence(now)?;

        let expired_count = state.expired_count(now.monotonic);
        let effective_recent_count = state.recent_order.len().saturating_sub(expired_count);
        if effective_recent_count >= self.inner.config.max_recent_identifiers {
            return Err(DiameterEndToEndIdentifierError::RecentWindowExhausted);
        }

        let mut candidate_sequence = if state.sequence_second == now.unix_seconds {
            state.next_sequence
        } else {
            0
        };
        let attempts = effective_recent_count.saturating_add(1);
        let mut selected = None;
        for _ in 0..attempts {
            let candidate = next_candidate(now.unix_seconds, &mut candidate_sequence);
            if !state.is_protected(candidate, now.monotonic) {
                selected = Some(candidate);
                break;
            }
        }
        // With at most 2^20 retained identifiers, pigeonhole guarantees that
        // one of `effective_recent_count + 1` candidates is free. Keep a
        // defensive value-free error instead of panicking if state is ever
        // corrupted in a future implementation.
        let identifier = selected.ok_or(DiameterEndToEndIdentifierError::StateUnavailable)?;

        state.expire_recent(now.monotonic);
        state.restart_after_second = None;
        state.sequence_second = now.unix_seconds;
        state.next_sequence = candidate_sequence;
        state.recent.insert(identifier, now.monotonic);
        state.recent_order.push_back(RecentIdentifier {
            identifier,
            allocated_at: now.monotonic,
        });
        Ok(DiameterEndToEndRequestIdentity {
            identifier,
            origin_scope_fingerprint: self.inner.origin_scope_fingerprint,
        })
    }

    /// Return the number of identifiers currently retained in the bounded
    /// recent-use fence without exposing identifier values.
    ///
    /// This snapshot does not observe the clock or expire entries.
    pub fn recent_identifier_count(&self) -> Result<usize, DiameterEndToEndIdentifierError> {
        self.inner
            .state
            .lock()
            .map(|state| state.recent_order.len())
            .map_err(|_| DiameterEndToEndIdentifierError::StateUnavailable)
    }

    /// Return the configured retention capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.config.max_recent_identifiers
    }
}

impl fmt::Debug for DiameterEndToEndIdentifierAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterEndToEndIdentifierAuthority")
            .field("capacity", &self.capacity())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::thread;

    const TEST_ORIGIN_HOST: &str = "origin.identifier.private.invalid";

    #[derive(Debug)]
    struct FakeClock {
        unix_seconds: AtomicU64,
        monotonic_nanos: AtomicU64,
        unavailable: AtomicBool,
    }

    impl FakeClock {
        fn new(unix_seconds: u64, monotonic: Duration) -> Self {
            Self {
                unix_seconds: AtomicU64::new(unix_seconds),
                monotonic_nanos: AtomicU64::new(duration_nanos(monotonic)),
                unavailable: AtomicBool::new(false),
            }
        }

        fn set(&self, unix_seconds: u64, monotonic: Duration) {
            self.unix_seconds.store(unix_seconds, Ordering::SeqCst);
            self.monotonic_nanos
                .store(duration_nanos(monotonic), Ordering::SeqCst);
        }

        fn advance_one_second(&self) {
            self.unix_seconds.fetch_add(1, Ordering::SeqCst);
            self.monotonic_nanos
                .fetch_add(1_000_000_000, Ordering::SeqCst);
        }

        fn fail(&self) {
            self.unavailable.store(true, Ordering::SeqCst);
        }

        fn recover(&self) {
            self.unavailable.store(false, Ordering::SeqCst);
        }
    }

    impl DiameterEndToEndIdentifierClock for FakeClock {
        fn now(
            &self,
        ) -> Result<DiameterEndToEndIdentifierTime, DiameterEndToEndIdentifierClockError> {
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(DiameterEndToEndIdentifierClockError::Unavailable);
            }
            Ok(DiameterEndToEndIdentifierTime::new(
                self.unix_seconds.load(Ordering::SeqCst),
                Duration::from_nanos(self.monotonic_nanos.load(Ordering::SeqCst)),
            ))
        }
    }

    fn duration_nanos(duration: Duration) -> u64 {
        u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
    }

    fn config(capacity: usize) -> DiameterEndToEndIdentifierConfig {
        match DiameterEndToEndIdentifierConfig::new(capacity) {
            Ok(config) => config,
            Err(error) => panic!("test capacity must be valid: {error}"),
        }
    }

    fn authority_attestation() -> DiameterEndToEndIdentifierAuthorityAttestation {
        match DiameterEndToEndIdentifierAuthorityAttestation::
            attest_single_origin_owner_with_faithful_clocks(TEST_ORIGIN_HOST)
        {
            Ok(attestation) => attestation,
            Err(error) => panic!("test Origin-Host must be valid: {error}"),
        }
    }

    fn authority(capacity: usize, clock: Arc<FakeClock>) -> DiameterEndToEndIdentifierAuthority {
        let clock_for_authority = Arc::clone(&clock) as Arc<dyn DiameterEndToEndIdentifierClock>;
        match DiameterEndToEndIdentifierAuthority::with_clock(
            config(capacity),
            clock_for_authority,
            authority_attestation(),
        ) {
            Ok(authority) => {
                clock.advance_one_second();
                authority
            }
            Err(error) => panic!("test authority must initialize: {error}"),
        }
    }

    fn allocated_value(authority: &DiameterEndToEndIdentifierAuthority) -> u32 {
        match authority.allocate() {
            Ok(identity) => identity.identifier,
            Err(error) => panic!("test allocation must succeed: {error}"),
        }
    }

    #[derive(Clone, PartialEq, Eq)]
    struct AllocationSnapshot {
        sequence_second: u64,
        next_sequence: u32,
        restart_after_second: Option<u64>,
        recent_order: Vec<(u32, Duration)>,
        recent: Vec<(u32, Duration)>,
    }

    fn allocation_snapshot(authority: &DiameterEndToEndIdentifierAuthority) -> AllocationSnapshot {
        let state = match authority.inner.state.lock() {
            Ok(state) => state,
            Err(_) => panic!("test state lock must be available"),
        };
        let recent_order = state
            .recent_order
            .iter()
            .map(|entry| (entry.identifier, entry.allocated_at))
            .collect();
        let mut recent: Vec<_> = state
            .recent
            .iter()
            .map(|(identifier, allocated_at)| (*identifier, *allocated_at))
            .collect();
        recent.sort_unstable();
        AllocationSnapshot {
            sequence_second: state.sequence_second,
            next_sequence: state.next_sequence,
            restart_after_second: state.restart_after_second,
            recent_order,
            recent,
        }
    }

    fn high_water(authority: &DiameterEndToEndIdentifierAuthority) -> (u64, Duration) {
        let state = match authority.inner.state.lock() {
            Ok(state) => state,
            Err(_) => panic!("test state lock must be available"),
        };
        (state.last_unix_seconds, state.last_monotonic)
    }

    #[test]
    fn concurrent_default_capacity_has_no_duplicates() {
        const THREADS: usize = 64;
        const ALLOCATIONS_PER_THREAD: usize = 1_024;
        let clock = Arc::new(FakeClock::new(10_000, Duration::ZERO));
        let authority = match DiameterEndToEndIdentifierAuthority::with_clock(
            DiameterEndToEndIdentifierConfig::default(),
            Arc::clone(&clock) as Arc<dyn DiameterEndToEndIdentifierClock>,
            authority_attestation(),
        ) {
            Ok(authority) => authority,
            Err(error) => panic!("default authority must initialize: {error}"),
        };
        clock.advance_one_second();
        let mut workers = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let authority = authority.clone();
            workers.push(thread::spawn(move || {
                let mut values = Vec::with_capacity(ALLOCATIONS_PER_THREAD);
                for _ in 0..ALLOCATIONS_PER_THREAD {
                    values.push(allocated_value(&authority));
                }
                values
            }));
        }

        let mut values = Vec::with_capacity(THREADS * ALLOCATIONS_PER_THREAD);
        for worker in workers {
            match worker.join() {
                Ok(mut allocated) => values.append(&mut allocated),
                Err(_) => panic!("allocation worker must not panic"),
            }
        }
        let unique: HashSet<_> = values.iter().copied().collect();
        assert_eq!(values.len(), 65_536);
        assert_eq!(unique.len(), values.len());
        assert_eq!(
            authority.allocate(),
            Err(DiameterEndToEndIdentifierError::RecentWindowExhausted)
        );
    }

    #[test]
    fn bounded_recent_window_exhausts_and_recovers_at_four_minutes() {
        let clock = Arc::new(FakeClock::new(20_000, Duration::ZERO));
        let authority = authority(2, Arc::clone(&clock));
        let first = allocated_value(&authority);
        let second = allocated_value(&authority);
        assert_ne!(first, second);
        let before = allocation_snapshot(&authority);

        clock.set(20_010, Duration::from_secs(10));
        assert_eq!(
            authority.allocate(),
            Err(DiameterEndToEndIdentifierError::RecentWindowExhausted)
        );
        assert!(before == allocation_snapshot(&authority));
        assert_eq!(high_water(&authority), (20_010, Duration::from_secs(10)));

        clock.set(
            20_241,
            DIAMETER_END_TO_END_IDENTIFIER_FENCE + Duration::from_secs(1),
        );
        assert!(authority.allocate().is_ok());
        assert_eq!(authority.recent_identifier_count(), Ok(1));
    }

    #[test]
    fn recent_window_expires_at_exactly_four_minutes() {
        let clock = Arc::new(FakeClock::new(22_000, Duration::ZERO));
        let authority = authority(1, Arc::clone(&clock));
        assert!(authority.allocate().is_ok());

        clock.set(
            22_240,
            Duration::from_secs(240) + Duration::from_nanos(999_999_999),
        );
        assert_eq!(
            authority.allocate(),
            Err(DiameterEndToEndIdentifierError::RecentWindowExhausted)
        );

        clock.set(22_241, Duration::from_secs(241));
        assert!(authority.allocate().is_ok());
        assert_eq!(authority.recent_identifier_count(), Ok(1));
    }

    #[test]
    fn rollback_after_capacity_failure_is_detected_without_mutating_allocation_state() {
        let clock = Arc::new(FakeClock::new(25_000, Duration::ZERO));
        let authority = authority(1, Arc::clone(&clock));
        assert!(authority.allocate().is_ok());
        let before = allocation_snapshot(&authority);

        clock.set(25_100, Duration::from_secs(100));
        assert_eq!(
            authority.allocate(),
            Err(DiameterEndToEndIdentifierError::RecentWindowExhausted)
        );
        assert!(before == allocation_snapshot(&authority));
        assert_eq!(high_water(&authority), (25_100, Duration::from_secs(100)));

        clock.set(25_099, Duration::from_secs(99));
        assert_eq!(
            authority.allocate(),
            Err(DiameterEndToEndIdentifierError::MonotonicClockMovedBackward)
        );
        assert!(before == allocation_snapshot(&authority));

        clock.set(25_099, Duration::from_secs(101));
        assert_eq!(
            authority.allocate(),
            Err(DiameterEndToEndIdentifierError::WallClockMovedBackward)
        );
        assert!(before == allocation_snapshot(&authority));
    }

    #[test]
    fn restart_fence_observations_advance_high_water() {
        let clock = Arc::new(FakeClock::new(27_000, Duration::from_secs(10)));
        let authority = match DiameterEndToEndIdentifierAuthority::with_clock(
            config(1),
            Arc::clone(&clock) as Arc<dyn DiameterEndToEndIdentifierClock>,
            authority_attestation(),
        ) {
            Ok(authority) => authority,
            Err(error) => panic!("authority must initialize: {error}"),
        };
        let before = allocation_snapshot(&authority);

        clock.set(27_000, Duration::from_secs(20));
        assert_eq!(
            authority.allocate(),
            Err(DiameterEndToEndIdentifierError::RestartFenceActive)
        );
        assert!(before == allocation_snapshot(&authority));
        assert_eq!(high_water(&authority), (27_000, Duration::from_secs(20)));

        clock.set(27_001, Duration::from_secs(19));
        assert_eq!(
            authority.allocate(),
            Err(DiameterEndToEndIdentifierError::MonotonicClockMovedBackward)
        );
        assert!(before == allocation_snapshot(&authority));
    }

    #[test]
    fn sequence_wrap_skips_still_protected_candidates() {
        let clock = Arc::new(FakeClock::new(0x0abc, Duration::ZERO));
        let authority = authority(4, Arc::clone(&clock));
        let protected_zero = allocated_value(&authority);
        assert_eq!(protected_zero & SEQUENCE_MASK, 0);
        {
            let mut state = match authority.inner.state.lock() {
                Ok(state) => state,
                Err(_) => panic!("test state lock must be available"),
            };
            state.sequence_second = 0x0abd;
            state.next_sequence = SEQUENCE_MASK;
        }
        let last = allocated_value(&authority);
        let wrapped = allocated_value(&authority);
        assert_eq!(last & SEQUENCE_MASK, SEQUENCE_MASK);
        assert_eq!(wrapped & SEQUENCE_MASK, 1);
        assert_ne!(last, wrapped);
    }

    #[test]
    fn out_of_contract_in_process_prefix_wrap_still_skips_the_retained_identifier() {
        let clock = Arc::new(FakeClock::new(28_000, Duration::ZERO));
        let authority = authority(4, Arc::clone(&clock));
        let first = allocated_value(&authority);
        assert_eq!(first & SEQUENCE_MASK, 0);

        // A +4096 whole-second observation inside one real four-minute window
        // violates the authority attestation. The retained fence still avoids
        // reuse as defense in depth while this process remains alive.
        clock.set(28_001 + (1 << TIME_BITS), Duration::from_secs(2));
        let after_prefix_wrap = allocated_value(&authority);

        assert_eq!(first >> SEQUENCE_BITS, after_prefix_wrap >> SEQUENCE_BITS);
        assert_eq!(after_prefix_wrap & SEQUENCE_MASK, 1);
        assert_ne!(first, after_prefix_wrap);
        assert_eq!(authority.recent_identifier_count(), Ok(2));
    }

    #[test]
    fn unavailable_and_backward_clocks_fail_closed() {
        let unavailable_at_start = Arc::new(FakeClock::new(29_000, Duration::ZERO));
        unavailable_at_start.fail();
        let initialization = DiameterEndToEndIdentifierAuthority::with_clock(
            config(4),
            Arc::clone(&unavailable_at_start) as Arc<dyn DiameterEndToEndIdentifierClock>,
            authority_attestation(),
        );
        assert!(matches!(
            initialization,
            Err(DiameterEndToEndIdentifierError::ClockUnavailable)
        ));

        let clock = Arc::new(FakeClock::new(30_000, Duration::from_secs(10)));
        let authority = authority(4, Arc::clone(&clock));
        assert!(authority.allocate().is_ok());
        let before = allocation_snapshot(&authority);

        clock.fail();
        assert_eq!(
            authority.allocate(),
            Err(DiameterEndToEndIdentifierError::ClockUnavailable)
        );
        assert!(before == allocation_snapshot(&authority));
        clock.recover();

        clock.set(30_000, Duration::from_secs(9));
        assert_eq!(
            authority.allocate(),
            Err(DiameterEndToEndIdentifierError::MonotonicClockMovedBackward)
        );
        assert!(before == allocation_snapshot(&authority));

        clock.set(29_999, Duration::from_secs(11));
        assert_eq!(
            authority.allocate(),
            Err(DiameterEndToEndIdentifierError::WallClockMovedBackward)
        );
        assert!(before == allocation_snapshot(&authority));
    }

    #[test]
    fn restart_within_window_uses_a_distinct_time_prefix() {
        let prior_clock = Arc::new(FakeClock::new(50_000, Duration::ZERO));
        let prior = authority(4, Arc::clone(&prior_clock));
        let prior_value = allocated_value(&prior);
        drop(prior);

        let restart_clock = Arc::new(FakeClock::new(50_001, Duration::ZERO));
        let restarted = match DiameterEndToEndIdentifierAuthority::with_clock(
            config(4),
            Arc::clone(&restart_clock) as Arc<dyn DiameterEndToEndIdentifierClock>,
            authority_attestation(),
        ) {
            Ok(authority) => authority,
            Err(error) => panic!("restart authority must initialize: {error}"),
        };
        let before = allocation_snapshot(&restarted);
        assert_eq!(
            restarted.allocate(),
            Err(DiameterEndToEndIdentifierError::RestartFenceActive)
        );
        assert!(before == allocation_snapshot(&restarted));

        restart_clock.set(50_002, Duration::from_secs(1));
        let restarted_value = allocated_value(&restarted);
        assert_ne!(prior_value, restarted_value);
        assert_ne!(
            prior_value >> SEQUENCE_BITS,
            restarted_value >> SEQUENCE_BITS
        );
    }

    #[test]
    fn restart_maximum_conforming_wall_observation_uses_a_distinct_prefix() {
        let prior_clock = Arc::new(FakeClock::new(55_000, Duration::ZERO));
        let prior = authority(4, Arc::clone(&prior_clock));
        let prior_value = allocated_value(&prior);
        drop(prior);

        // These synthetic observations model real instants less than 240
        // seconds apart. +4095 whole observed seconds is the maximum
        // conforming advance and cannot wrap the 12-bit time prefix.
        let restart_clock = Arc::new(FakeClock::new(55_001 + 4094, Duration::ZERO));
        let restarted = match DiameterEndToEndIdentifierAuthority::with_clock(
            config(4),
            Arc::clone(&restart_clock) as Arc<dyn DiameterEndToEndIdentifierClock>,
            authority_attestation(),
        ) {
            Ok(authority) => authority,
            Err(error) => panic!("restart authority must initialize: {error}"),
        };
        restart_clock.set(55_001 + 4095, Duration::from_secs(1));
        let restarted_value = allocated_value(&restarted);

        assert_ne!(prior_value, restarted_value);
        assert_ne!(
            prior_value >> SEQUENCE_BITS,
            restarted_value >> SEQUENCE_BITS
        );
        assert_eq!(restarted_value & SEQUENCE_MASK, 0);
    }

    #[test]
    fn restart_beyond_window_can_reuse_an_expired_identifier() {
        let prior_clock = Arc::new(FakeClock::new(60_000, Duration::ZERO));
        let prior = authority(1, Arc::clone(&prior_clock));
        let prior_value = allocated_value(&prior);
        drop(prior);

        let restart_clock = Arc::new(FakeClock::new(60_000 + (1 << TIME_BITS), Duration::ZERO));
        let restarted = match DiameterEndToEndIdentifierAuthority::with_clock(
            config(1),
            Arc::clone(&restart_clock) as Arc<dyn DiameterEndToEndIdentifierClock>,
            authority_attestation(),
        ) {
            Ok(authority) => authority,
            Err(error) => panic!("restart authority must initialize: {error}"),
        };
        assert_eq!(
            restarted.allocate(),
            Err(DiameterEndToEndIdentifierError::RestartFenceActive)
        );
        restart_clock.set(60_001 + (1 << TIME_BITS), Duration::from_secs(1));
        let restarted_value = allocated_value(&restarted);
        assert_eq!(prior_value, restarted_value);
    }

    #[test]
    fn affine_identity_is_origin_bound_case_insensitive_and_redacted() {
        let clock = Arc::new(FakeClock::new(70_000, Duration::ZERO));
        let authority = authority(4, clock);
        let identity = match authority.allocate() {
            Ok(identity) => identity,
            Err(error) => panic!("identity allocation must succeed: {error}"),
        };
        let diagnostic = format!("{identity:?}");
        assert_eq!(diagnostic, "DiameterEndToEndRequestIdentity(<redacted>)");
        assert!(!diagnostic.contains(&identity.identifier.to_string()));
        assert!(identity
            .into_u32_for_origin_host("ORIGIN.IDENTIFIER.PRIVATE.INVALID")
            .is_ok());
    }

    #[test]
    fn affine_identity_rejects_a_different_origin_without_disclosure() {
        let clock = Arc::new(FakeClock::new(71_000, Duration::ZERO));
        let authority = authority(4, clock);
        let identity = match authority.allocate() {
            Ok(identity) => identity,
            Err(error) => panic!("identity allocation must succeed: {error}"),
        };
        assert_eq!(
            identity.into_u32_for_origin_host("other.identifier.private.invalid"),
            Err(DiameterEndToEndIdentifierError::OriginHostMismatch)
        );
        assert_eq!(
            DiameterEndToEndIdentifierError::OriginHostMismatch.to_string(),
            "diameter_end_to_end_identifier_origin_host_mismatch"
        );
    }

    #[test]
    fn public_errors_are_value_free_and_capacity_is_bounded() {
        let attestation = authority_attestation();
        assert_eq!(
            format!("{attestation:?}"),
            "DiameterEndToEndIdentifierAuthorityAttestation(<redacted>)"
        );
        assert_eq!(
            DiameterEndToEndIdentifierConfig::new(0),
            Err(DiameterEndToEndIdentifierError::InvalidCapacity)
        );
        assert_eq!(
            DiameterEndToEndIdentifierConfig::new(MAX_DIAMETER_END_TO_END_IDENTIFIER_CAPACITY + 1),
            Err(DiameterEndToEndIdentifierError::InvalidCapacity)
        );
        assert!(matches!(
            DiameterEndToEndIdentifierAuthorityAttestation::
                attest_single_origin_owner_with_faithful_clocks(""),
            Err(DiameterEndToEndIdentifierError::InvalidOriginHost)
        ));
        assert!(matches!(
            DiameterEndToEndIdentifierAuthorityAttestation::
                attest_single_origin_owner_with_faithful_clocks("origin.\u{00e9}xample"),
            Err(DiameterEndToEndIdentifierError::InvalidOriginHost)
        ));
        let maximum = "a".repeat(MAX_DIAMETER_END_TO_END_ORIGIN_HOST_LEN);
        assert!(
            DiameterEndToEndIdentifierAuthorityAttestation::
                attest_single_origin_owner_with_faithful_clocks(&maximum)
                .is_ok()
        );
        let oversized = "a".repeat(MAX_DIAMETER_END_TO_END_ORIGIN_HOST_LEN + 1);
        assert!(matches!(
            DiameterEndToEndIdentifierAuthorityAttestation::
                attest_single_origin_owner_with_faithful_clocks(&oversized),
            Err(DiameterEndToEndIdentifierError::InvalidOriginHost)
        ));
        assert_eq!(
            DiameterEndToEndIdentifierError::ClockUnavailable.to_string(),
            "diameter_end_to_end_identifier_clock_unavailable"
        );
    }
}
