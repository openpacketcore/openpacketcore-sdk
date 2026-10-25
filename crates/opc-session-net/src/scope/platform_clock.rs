//! Supported platform authentication-time source (RFC 026).
//!
//! [`PlatformAuthenticationTimeSource`] is the production
//! [`AuthenticationTimeSource`] for the scope transport. It reads the Linux
//! kernel's clock-adjustment state through
//! `opc_linux_clock_sys::read_kernel_clock_adjustment` and reports the
//! kernel's maximum realtime error as the symmetric uncertainty of one fresh
//! realtime observation. The installed
//! [`IntervalClock`](super::IntervalClock) turns those observations into the
//! earliest/latest authentication interval and enforces the fixed uncertainty
//! budget.
//!
//! # Platform requirements
//!
//! - **Linux only.** Other platforms compile, but every read fails with the
//!   typed retryable [`AuthenticationTimeError`]: there is no wall-clock
//!   fallback that silently weakens authentication.
//! - **Unprivileged read.** The adapter performs one read-only
//!   `clock_adjtime(CLOCK_REALTIME)` query (`modes == 0`). It does not change
//!   the clock and does not require `CAP_SYS_TIME`. A seccomp filter, LSM
//!   policy or hardened container runtime that refuses the syscall makes
//!   authentication time unavailable; the failure is retryable and grants no
//!   authority.
//! - **A synchronization daemon that maintains the kernel estimate.** The
//!   kernel's `timex.maxerror` is only meaningful while a time daemon
//!   (for example chrony or ntpd) keeps it current. A node without one usually
//!   reports `STA_UNSYNC` or the boot-default multi-second bound; both fail
//!   closed here.
//! - **Containers.** The kernel clock and synchronization state are
//!   host-global, not namespaced per container. Every container observes the
//!   same synchronization state, so a clock fault affects the whole host.
//!
//! # Operator signal
//!
//! Every refusal logs one fixed, value-free `tracing` warning on target
//! `opc_session_net::scope::auth_time` with a closed `reason` field:
//! `unsupported_platform`, `io_unavailable`, `permission_denied`,
//! `not_synchronized`, `zero_error_bound`, `invalid_error_bound`,
//! `uncertainty_exceeded` or `generation_exhausted`. The caller of the
//! authentication path sees the existing typed retryable
//! `AuthTimeUnavailable` refusal; the operator should alarm on the warnings
//! and on the node's `STA_UNSYNC`/time-daemon health rather than widen the
//! uncertainty budget.
//!
//! # Synchronization generation
//!
//! A [`RealtimeReading`] carries a positive synchronization generation. This
//! adapter starts at generation 1 on the first accepted synchronized
//! observation and increments the generation each time synchronization is
//! re-established after a refused (unsynchronized) observation. Wall-clock
//! steps without a synchronization transition remain
//! [`IntervalClock`](super::IntervalClock)'s consistency checks: three
//! consistent observations at least one second apart over at least three
//! seconds restore authentication, and the fixed budget never moves.

use super::clock::{AuthenticationTimeError, AuthenticationTimeSource, RealtimeReading};
use opc_types::Timestamp;
use std::{sync::Mutex, time::Duration};

/// Default maximum kernel-declared realtime uncertainty accepted by
/// [`PlatformAuthenticationTimeSource`].
///
/// The kernel's maximum error is the symmetric authentication-time bound. The
/// default is deliberately small (one second) so a node with an unmaintained
/// or clearly inaccurate clock refuses authentication instead of widening its
/// interval; deploy the fixed [`IntervalClock`](super::IntervalClock) budget
/// at or below this value.
pub const PLATFORM_AUTHENTICATION_TIME_MAX_UNCERTAINTY: Duration = Duration::from_secs(1);

const LOG_TARGET: &str = "opc_session_net::scope::auth_time";

/// One value-free kernel synchronization snapshot used by the adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PlatformTimeSyncObservation {
    synchronized: bool,
    maximum_error_microseconds: i64,
}

fn warn_reason(reason: &'static str) {
    tracing::warn!(
        target: LOG_TARGET,
        reason,
        "platform authentication time unavailable"
    );
}

#[cfg(target_os = "linux")]
fn platform_io_reason(kind: std::io::ErrorKind) -> &'static str {
    match kind {
        std::io::ErrorKind::Unsupported => "unsupported_platform",
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        _ => "io_unavailable",
    }
}

#[cfg(target_os = "linux")]
fn read_platform_time_sync_observation(
) -> Result<PlatformTimeSyncObservation, AuthenticationTimeError> {
    match opc_linux_clock_sys::read_kernel_clock_adjustment() {
        Ok(adjustment) => Ok(PlatformTimeSyncObservation {
            synchronized: adjustment.is_synchronized(),
            maximum_error_microseconds: adjustment.max_error_microseconds(),
        }),
        Err(error) => {
            warn_reason(platform_io_reason(error.kind()));
            Err(AuthenticationTimeError)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn read_platform_time_sync_observation(
) -> Result<PlatformTimeSyncObservation, AuthenticationTimeError> {
    warn_reason("unsupported_platform");
    Err(AuthenticationTimeError)
}

#[derive(Default)]
struct SynchronizationState {
    synchronized: bool,
    generation: u64,
}

/// Supported platform [`AuthenticationTimeSource`] for RFC 026 scope
/// authentication.
///
/// Install it once per process and keep it for the process lifetime:
///
/// ```
/// # use opc_session_net::scope::{
/// #     IntervalClock, PlatformAuthenticationTimeSource,
/// #     PLATFORM_AUTHENTICATION_TIME_MAX_UNCERTAINTY,
/// # };
/// # use std::sync::Arc;
/// # use std::time::Duration;
/// let source = Arc::new(PlatformAuthenticationTimeSource::new());
/// // The deployment fixes this budget; it is never widened on retry.
/// let clock = IntervalClock::new(source, Duration::from_millis(100)).expect("fixed budget");
/// # let _ = &clock;
/// # assert!(!PLATFORM_AUTHENTICATION_TIME_MAX_UNCERTAINTY.is_zero());
/// ```
///
/// A read never grants authority, never changes ownership or effect state and
/// never substitutes a wall clock. An unavailable, unsynchronized, zero-bound
/// or over-bound kernel state is the typed retryable
/// [`AuthenticationTimeError`].
pub struct PlatformAuthenticationTimeSource {
    state: Mutex<SynchronizationState>,
    maximum_uncertainty: Duration,
}

impl PlatformAuthenticationTimeSource {
    /// Create a source with the default
    /// [`PLATFORM_AUTHENTICATION_TIME_MAX_UNCERTAINTY`] acceptance bound.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(SynchronizationState {
                synchronized: false,
                generation: 0,
            }),
            maximum_uncertainty: PLATFORM_AUTHENTICATION_TIME_MAX_UNCERTAINTY,
        }
    }

    /// Create a source with an explicit fixed maximum accepted kernel error.
    ///
    /// The bound is a deployment decision and stays fixed for the process
    /// lifetime: callers must not raise it on a retry. It must be non-zero.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationTimeError`] when the bound is zero, because a
    /// zero-bound source would invent certainty it cannot establish.
    pub fn with_maximum_uncertainty(
        maximum_uncertainty: Duration,
    ) -> Result<Self, AuthenticationTimeError> {
        if maximum_uncertainty.is_zero() {
            return Err(AuthenticationTimeError);
        }
        Ok(Self {
            state: Mutex::new(SynchronizationState::default()),
            maximum_uncertainty,
        })
    }

    fn read_observation(&self, now: Timestamp) -> Result<RealtimeReading, AuthenticationTimeError> {
        let observation = read_platform_time_sync_observation()?;
        self.observe(observation, now)
    }

    fn observe(
        &self,
        observation: PlatformTimeSyncObservation,
        now: Timestamp,
    ) -> Result<RealtimeReading, AuthenticationTimeError> {
        let mut state = self.state.lock().map_err(|_| {
            warn_reason("state_poisoned");
            AuthenticationTimeError
        })?;
        if !observation.synchronized {
            state.synchronized = false;
            warn_reason("not_synchronized");
            return Err(AuthenticationTimeError);
        }
        let uncertainty_microseconds = u64::try_from(observation.maximum_error_microseconds)
            .map_err(|_| {
                warn_reason("invalid_error_bound");
                AuthenticationTimeError
            })?;
        if uncertainty_microseconds == 0 {
            // A zero kernel bound cannot be a trustworthy authentication
            // bound; never invent certainty.
            warn_reason("zero_error_bound");
            return Err(AuthenticationTimeError);
        }
        let uncertainty = Duration::from_micros(uncertainty_microseconds);
        if uncertainty > self.maximum_uncertainty {
            warn_reason("uncertainty_exceeded");
            return Err(AuthenticationTimeError);
        }
        if !state.synchronized {
            state.generation = state.generation.checked_add(1).ok_or_else(|| {
                warn_reason("generation_exhausted");
                AuthenticationTimeError
            })?;
            state.synchronized = true;
        }
        Ok(RealtimeReading {
            now,
            uncertainty,
            synchronization_generation: state.generation,
        })
    }
}

impl Default for PlatformAuthenticationTimeSource {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthenticationTimeSource for PlatformAuthenticationTimeSource {
    fn read(&self) -> Result<RealtimeReading, AuthenticationTimeError> {
        self.read_observation(Timestamp::now_utc())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn synchronized(microseconds: i64) -> PlatformTimeSyncObservation {
        PlatformTimeSyncObservation {
            synchronized: true,
            maximum_error_microseconds: microseconds,
        }
    }

    const UNSYNCHRONIZED: PlatformTimeSyncObservation = PlatformTimeSyncObservation {
        synchronized: false,
        maximum_error_microseconds: 16_000_000,
    };

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(1_800_000_000 + seconds).expect("timestamp"),
        )
    }

    #[test]
    fn synchronized_kernel_bound_is_accepted_with_the_kernel_uncertainty() {
        let source = PlatformAuthenticationTimeSource::new();
        let reading = source
            .observe(synchronized(2_500), at(0))
            .expect("synchronized");
        assert_eq!(reading.uncertainty, Duration::from_micros(2_500));
        assert_eq!(reading.synchronization_generation, 1);
        assert_eq!(reading.now, at(0));
        // A stable synchronized source does not advance the generation.
        let second = source
            .observe(synchronized(3_500), at(1))
            .expect("synchronized");
        assert_eq!(second.uncertainty, Duration::from_micros(3_500));
        assert_eq!(second.synchronization_generation, 1);
    }

    #[test]
    fn unsynchronized_or_unknown_synchronization_stays_unavailable() {
        let source = PlatformAuthenticationTimeSource::new();
        assert_eq!(
            source.observe(UNSYNCHRONIZED, at(0)).unwrap_err(),
            AuthenticationTimeError
        );
        assert_eq!(
            source.observe(UNSYNCHRONIZED, at(1)).unwrap_err(),
            AuthenticationTimeError
        );
        // A refused observation never establishes a positive generation.
        assert_eq!(
            source.observe(UNSYNCHRONIZED, at(2)).unwrap_err(),
            AuthenticationTimeError
        );
        let reading = source
            .observe(synchronized(1_000), at(3))
            .expect("synchronized");
        assert_eq!(reading.synchronization_generation, 1);
    }

    #[test]
    fn lost_and_restored_synchronization_increments_the_generation() {
        let source = PlatformAuthenticationTimeSource::new();
        assert_eq!(
            source
                .observe(synchronized(1_000), at(0))
                .expect("first synchronization")
                .synchronization_generation,
            1
        );
        assert_eq!(
            source.observe(UNSYNCHRONIZED, at(1)).unwrap_err(),
            AuthenticationTimeError
        );
        let restored = source
            .observe(synchronized(1_000), at(2))
            .expect("resynchronized");
        assert_eq!(restored.synchronization_generation, 2);
        let stable = source
            .observe(synchronized(1_000), at(3))
            .expect("synchronized");
        assert_eq!(stable.synchronization_generation, 2);
    }

    #[test]
    fn zero_negative_and_excessive_kernel_bounds_are_rejected() {
        let source = PlatformAuthenticationTimeSource::new();
        assert_eq!(
            source.observe(synchronized(0), at(0)).unwrap_err(),
            AuthenticationTimeError
        );
        assert_eq!(
            source.observe(synchronized(-1), at(1)).unwrap_err(),
            AuthenticationTimeError
        );
        assert_eq!(
            source.observe(synchronized(i64::MAX), at(2)).unwrap_err(),
            AuthenticationTimeError
        );
        // The kernel's boot-default maximum is far outside the default bound.
        assert_eq!(
            source.observe(synchronized(16_000_000), at(3)).unwrap_err(),
            AuthenticationTimeError
        );
        // The failed observations above never established a generation.
        let reading = source
            .observe(synchronized(1_000), at(4))
            .expect("synchronized");
        assert_eq!(reading.synchronization_generation, 1);
    }

    #[test]
    fn explicit_uncertainty_bound_is_fixed_and_never_widened() {
        let source =
            PlatformAuthenticationTimeSource::with_maximum_uncertainty(Duration::from_millis(5))
                .expect("non-zero bound");
        assert_eq!(
            source.observe(synchronized(5_001), at(0)).unwrap_err(),
            AuthenticationTimeError
        );
        let reading = source
            .observe(synchronized(5_000), at(1))
            .expect("within bound");
        assert_eq!(reading.uncertainty, Duration::from_millis(5));
        assert!(
            PlatformAuthenticationTimeSource::with_maximum_uncertainty(Duration::ZERO).is_err()
        );
    }

    #[test]
    fn default_bound_is_documented_and_nonzero() {
        assert_eq!(
            PLATFORM_AUTHENTICATION_TIME_MAX_UNCERTAINTY,
            Duration::from_secs(1)
        );
        assert!(!PLATFORM_AUTHENTICATION_TIME_MAX_UNCERTAINTY.is_zero());
    }

    /// A production code path never falls back to the wall clock: an
    /// unavailable platform read yields no reading at all.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform_never_serves_a_wall_clock_reading() {
        let source = PlatformAuthenticationTimeSource::new();
        assert_eq!(source.read().unwrap_err(), AuthenticationTimeError);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_platform_read_is_typed_and_part_of_the_same_contract() {
        let source = PlatformAuthenticationTimeSource::new();
        match source.read() {
            Ok(reading) => {
                assert!(reading.synchronization_generation > 0);
                assert!(!reading.uncertainty.is_zero());
                assert!(reading.uncertainty <= PLATFORM_AUTHENTICATION_TIME_MAX_UNCERTAINTY);
            }
            Err(error) => assert_eq!(error, AuthenticationTimeError),
        }
    }

    struct ScriptedKernelSource {
        source: PlatformAuthenticationTimeSource,
        script: Mutex<VecDeque<(PlatformTimeSyncObservation, Timestamp)>>,
    }

    impl ScriptedKernelSource {
        fn new(
            maximum_uncertainty: Duration,
            script: impl IntoIterator<Item = (PlatformTimeSyncObservation, Timestamp)>,
        ) -> Self {
            Self {
                source: PlatformAuthenticationTimeSource::with_maximum_uncertainty(
                    maximum_uncertainty,
                )
                .expect("non-zero bound"),
                script: Mutex::new(script.into_iter().collect()),
            }
        }
    }

    impl AuthenticationTimeSource for ScriptedKernelSource {
        fn read(&self) -> Result<RealtimeReading, AuthenticationTimeError> {
            let (observation, now) = self
                .script
                .lock()
                .expect("script")
                .pop_front()
                .expect("scripted kernel observation");
            self.source.observe(observation, now)
        }
    }

    /// Backward and forward wall steps are refused by the installed clock even
    /// when the kernel stays synchronized; the production source changes only
    /// the authentication interval, never ownership or effect state.
    #[tokio::test(start_paused = true)]
    async fn installed_clock_refuses_backward_and_forward_wall_steps() {
        use super::super::{AuthenticationClock, IntervalClock};
        use std::sync::Arc;

        for offset_seconds in [-10_i64, 10] {
            let source = Arc::new(ScriptedKernelSource::new(
                Duration::from_millis(10),
                [
                    (synchronized(5_000), at(0)),
                    (synchronized(5_000), at(offset_seconds)),
                ],
            ));
            let clock = IntervalClock::new(source, Duration::from_millis(10)).expect("clock");
            assert!(clock.interval().is_ok(), "the initial reading is accepted");
            // The step happens one real second later; the wall clock moved by
            // ten seconds while the monotonic clock moved by one.
            tokio::time::advance(Duration::from_secs(1)).await;
            assert_eq!(
                clock.interval().unwrap_err(),
                AuthenticationTimeError,
                "a wall step outside the fixed budget is refused"
            );
        }
    }

    /// A clock failure constructs no authentication interval at all, so no
    /// authentication or ownership consumer can act on an unavailable read.
    /// The clock port is read-only and has no store/ownership handle.
    #[tokio::test]
    async fn clock_failure_never_constructs_an_authentication_interval() {
        use super::super::{AuthenticationClock, IntervalClock};
        use std::sync::Arc;

        let source = Arc::new(ScriptedKernelSource::new(
            Duration::from_millis(10),
            [(UNSYNCHRONIZED, at(0))],
        ));
        let clock = IntervalClock::new(source, Duration::from_millis(10)).expect("clock");
        assert_eq!(clock.interval().unwrap_err(), AuthenticationTimeError);
    }

    /// A synchronization transition makes the clock accept the new baseline
    /// immediately, without widening its fixed uncertainty budget.
    #[tokio::test(start_paused = true)]
    async fn resynchronization_restores_authentication_without_widening_the_budget() {
        use super::super::{AuthenticationClock, IntervalClock};
        use std::sync::Arc;

        let source = Arc::new(ScriptedKernelSource::new(
            Duration::from_millis(10),
            [
                (synchronized(5_000), at(0)),
                (UNSYNCHRONIZED, at(10)),
                (synchronized(5_000), at(20)),
            ],
        ));
        let clock = IntervalClock::new(source, Duration::from_millis(10)).expect("clock");
        clock.interval().expect("synchronized baseline");
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            clock.interval().unwrap_err(),
            AuthenticationTimeError,
            "unsynchronized kernel state refuses authentication"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        // The wall clock stepped forward while synchronization was lost. The
        // newer generation is the trusted resynchronization baseline; the
        // installed uncertainty stays exactly the fixed budget or smaller.
        let after = clock.interval().expect("resynchronized baseline");
        assert!(after.is_within(
            at(20).add_seconds(-1).unwrap(),
            at(20).add_seconds(1).unwrap()
        ));
        assert!(
            !after.is_within(at(20), at(20).add_seconds(1).unwrap()),
            "the fixed bound is not widened after resynchronization"
        );
    }
}
