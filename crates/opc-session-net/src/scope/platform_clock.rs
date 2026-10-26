//! Supported platform authentication-time source for RFC 026.
//!
//! Linux uses two read-only `clock_adjtime(CLOCK_REALTIME)` snapshots bracketed
//! by monotonic time. The second snapshot supplies the realtime instant; the
//! symmetric bound includes both snapshots' maximum/estimated error, precision,
//! error-field quantization, oscillator tolerance and the whole sampling span.
//! Unknown, malformed or changing synchronization data grants no authority.
//!
//! Other platforms fail with the typed retryable `AuthenticationTimeError`.
//! A node synchronization daemon must maintain the kernel estimate (chrony
//! requires `rtcsync`). Containers use the host clock and must permit this
//! read-only syscall, which needs no `CAP_SYS_TIME`. Authentication resumes
//! automatically after healthy observations; ownership and closure evidence do
//! not change. Keep the deployment's uncertainty budget fixed on every retry.
//!
//! Refusal warnings contain a closed, value-free reason and occur only when
//! the refusal changes. One recovery event follows the first accepted pair.
//! Clock steps without observed synchronization loss remain subject to
//! `IntervalClock`'s three-second consistent-progress recovery contract.

use super::clock::{AuthenticationTimeError, AuthenticationTimeSource, RealtimeReading};
use opc_linux_clock_sys::{status::*, RealtimeSnapshot};
use opc_types::Timestamp;
use std::{
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Default maximum complete symmetric error accepted by the platform source.
/// The fixed `IntervalClock` budget must be at or below this one-second ceiling.
pub const PLATFORM_AUTHENTICATION_TIME_MAX_UNCERTAINTY: Duration = Duration::from_secs(1);

const LOG_TARGET: &str = "opc_session_net::scope::auth_time";

#[derive(Clone, Copy, Debug)]
struct KernelSample {
    observations: [Result<RealtimeSnapshot, io::ErrorKind>; 2],
    elapsed: Duration,
}

trait KernelReader: Send + Sync {
    fn sample(&self) -> KernelSample;
}

struct LinuxKernel;
impl KernelReader for LinuxKernel {
    fn sample(&self) -> KernelSample {
        let started = Instant::now();
        let observations = std::array::from_fn(|_| {
            opc_linux_clock_sys::read_kernel_clock_adjustment()
                .map(|raw| raw.realtime_snapshot())
                .map_err(|error| error.kind())
        });
        KernelSample {
            observations,
            elapsed: started.elapsed(),
        }
    }
}

#[derive(Default)]
struct SourceState {
    generation: u64,
    lost_synchronization: bool,
    refusal: Option<Refusal>,
}

/// Linux realtime synchronization source for a fixed-budget [`super::IntervalClock`].
/// Install one long-lived instance and retain it across authentication retries.
///
/// Queries `clock_adjtime(CLOCK_REALTIME, modes=0)` without adjusting the clock.
/// The node time service must publish trusted synchronization and conservative
/// error bounds; chrony installations require `rtcsync`. Containers use the node
/// clock and must allow this read-only syscall, which needs no `CAP_SYS_TIME`.
///
/// A generation identifies an observed synchronization episode in this instance,
/// not a persistent kernel epoch. Observed loss followed by a healthy pair
/// increments it once. Loss entirely between observations cannot be detected.
/// Unknown data and syscall errors never manufacture a recovered generation.
/// Refusal and recovery change no ownership, accepted work or closure evidence.
/// Linux adds 0.5 ms to the maximum error each second between daemon updates.
/// At installation, allow at least root distance + 0.5 ms per second of the
/// longest actual update interval + about 1 ms for sampling/precision (more if
/// required by measured sampling spans). Chrony's default `maxpoll 10` permits
/// 1,024 seconds between polls, adding 512 ms; successful updates may be farther
/// apart during packet loss. The example assumes root distance at most 50 ms,
/// actual updates within 1,024 seconds and sampling overhead at most 1 ms, so
/// 563 ms fits a fixed 600 ms budget. A 100 ms budget instead needs shorter
/// updates, for example `maxpoll 6` with successful updates within 64 seconds
/// under the same root-distance and sampling limits.
/// Periodic budget refusal with a healthy daemon calls for correcting these
/// install-time assumptions; neither source nor adapter widens its budget.
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
/// // Fixed at installation for the root-distance and update bounds above.
/// let clock = IntervalClock::new(source, Duration::from_millis(600)).expect("fixed budget");
/// # let _ = &clock;
/// # assert!(!PLATFORM_AUTHENTICATION_TIME_MAX_UNCERTAINTY.is_zero());
/// ```
///
pub struct PlatformAuthenticationTimeSource {
    reader: Option<Arc<dyn KernelReader>>,
    state: Mutex<SourceState>,
    maximum_uncertainty: Duration,
}

impl PlatformAuthenticationTimeSource {
    /// Install the read-only source with its fixed default acceptance bound.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reader: None,
            state: Mutex::new(SourceState {
                generation: 0,
                lost_synchronization: false,
                refusal: None,
            }),
            maximum_uncertainty: PLATFORM_AUTHENTICATION_TIME_MAX_UNCERTAINTY,
        }
    }

    /// Install an explicit fixed maximum accepted symmetric uncertainty.
    /// The bound remains fixed for the process lifetime and must not be widened
    /// on retry. The complete conservative bound is compared with this value.
    ///
    /// # Errors
    /// Returns `AuthenticationTimeError` when the bound is zero.
    pub fn with_maximum_uncertainty(
        maximum_uncertainty: Duration,
    ) -> Result<Self, AuthenticationTimeError> {
        if maximum_uncertainty.is_zero() {
            return Err(AuthenticationTimeError);
        }
        Ok(Self {
            maximum_uncertainty,
            ..Self::new()
        })
    }

    #[cfg(test)]
    fn with_reader(reader: Arc<dyn KernelReader>) -> Self {
        Self {
            reader: Some(reader),
            ..Self::new()
        }
    }

    fn accept_sample(
        &self,
        state: &mut SourceState,
        sample: KernelSample,
    ) -> Result<RealtimeReading, AuthenticationTimeError> {
        if sample
            .observations
            .iter()
            .any(|observed| observed.as_ref().is_ok_and(lost_synchronization))
        {
            // Keep this evidence even when the other query failed. A transient
            // query error must not erase an observed synchronization boundary.
            state.lost_synchronization = true;
            return state.refuse(Refusal::Synchronization);
        }
        let (now, uncertainty) = match validate_sample(sample) {
            Ok(reading) => reading,
            Err(reason) => return state.refuse(reason),
        };
        if uncertainty > self.maximum_uncertainty {
            return state.refuse(Refusal::UncertaintyExceeded);
        }
        let generation = if state.generation == 0 {
            1
        } else if state.lost_synchronization {
            match state.generation.checked_add(1) {
                Some(generation) => generation,
                None => return state.refuse(Refusal::GenerationExhausted),
            }
        } else {
            state.generation
        };
        state.generation = generation;
        state.lost_synchronization = false;
        if state.refusal.take().is_some() {
            tracing::info!(target: LOG_TARGET, "platform authentication time observations recovered");
        }
        Ok(RealtimeReading {
            now,
            uncertainty,
            synchronization_generation: generation,
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
        // Serialize observations as well as generation changes. Two concurrent
        // callers must not reorder a healthy pair around an observed loss.
        let mut state = self.state.lock().map_err(|_| AuthenticationTimeError)?;
        let sample = self
            .reader
            .as_ref()
            .map_or_else(|| LinuxKernel.sample(), |reader| reader.sample());
        self.accept_sample(&mut state, sample)
    }
}

const KNOWN_STATUS: i32 = STA_PLL
    | STA_PPSFREQ
    | STA_PPSTIME
    | STA_FLL
    | STA_INS
    | STA_DEL
    | STA_UNSYNC
    | STA_FREQHOLD
    | STA_PPSSIGNAL
    | STA_PPSJITTER
    | STA_PPSWANDER
    | STA_PPSERROR
    | STA_CLOCKERR
    | STA_NANO
    | STA_MODE
    | STA_CLK;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Query,
    UnsupportedPlatform,
    PermissionDenied,
    UncertaintyExceeded,
    Synchronization,
    InvalidObservation,
    SamplingChanged,
    Overflow,
    GenerationExhausted,
}

impl Refusal {
    fn query(kind: io::ErrorKind) -> Self {
        match kind {
            io::ErrorKind::Unsupported => Self::UnsupportedPlatform,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => Self::Query,
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::Query => "io_unavailable",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::PermissionDenied => "permission_denied",
            Self::UncertaintyExceeded => "uncertainty_exceeded",
            Self::Synchronization => "not_synchronized",
            Self::InvalidObservation => "invalid_observation",
            Self::SamplingChanged => "sampling_changed",
            Self::Overflow => "invalid_error_bound",
            Self::GenerationExhausted => "generation_exhausted",
        }
    }
}

impl SourceState {
    fn refuse(&mut self, reason: Refusal) -> Result<RealtimeReading, AuthenticationTimeError> {
        if self.refusal != Some(reason) {
            tracing::warn!(target: LOG_TARGET, reason = reason.code(), "platform authentication time unavailable");
            self.refusal = Some(reason);
        }
        Err(AuthenticationTimeError)
    }
}

fn lost_synchronization(raw: &RealtimeSnapshot) -> bool {
    if raw.state == TIME_ERROR {
        return true;
    }
    if !matches!(
        raw.state,
        TIME_OK | TIME_INS | TIME_DEL | TIME_OOP | TIME_WAIT
    ) || raw.status & !KNOWN_STATUS != 0
    {
        return false;
    }
    raw.status & (STA_UNSYNC | STA_CLOCKERR) != 0
        || (raw.status & (STA_PPSFREQ | STA_PPSTIME) != 0 && raw.status & STA_PPSSIGNAL == 0)
        || (raw.status & STA_PPSTIME != 0 && raw.status & STA_PPSJITTER != 0)
        || (raw.status & STA_PPSFREQ != 0 && raw.status & (STA_PPSWANDER | STA_PPSERROR) != 0)
}

fn observation_time(raw: RealtimeSnapshot) -> Result<Timestamp, Refusal> {
    if !matches!(raw.state, TIME_OK | TIME_INS | TIME_DEL | TIME_WAIT)
        || raw.status & !KNOWN_STATUS != 0
        || raw.status & (STA_INS | STA_DEL) == (STA_INS | STA_DEL)
        || raw.maximum_error_micros <= 0
        || raw.estimated_error_micros < 0
        || raw.precision_micros <= 0
        || raw.tolerance_scaled_ppm <= 0
    {
        return Err(Refusal::InvalidObservation);
    }
    let unit = if raw.status & STA_NANO != 0 { 1 } else { 1_000 };
    if !(0..1_000_000_000 / unit).contains(&raw.subsecond) {
        return Err(Refusal::InvalidObservation);
    }
    let nanos = raw
        .seconds
        .checked_mul(1_000_000_000)
        .and_then(|seconds| {
            raw.subsecond
                .checked_mul(unit)
                .and_then(|fraction| seconds.checked_add(fraction))
        })
        .ok_or(Refusal::Overflow)?;
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map(Timestamp::from_offset_datetime)
        .map_err(|_| Refusal::Overflow)
}

fn micros(value: i128) -> Result<Duration, Refusal> {
    u64::try_from(value)
        .map(Duration::from_micros)
        .map_err(|_| Refusal::Overflow)
}

fn validate_sample(sample: KernelSample) -> Result<(Timestamp, Duration), Refusal> {
    let [first, last] = sample.observations;
    let first = first.map_err(Refusal::query)?;
    let last = last.map_err(Refusal::query)?;
    let before = observation_time(first)?;
    let now = observation_time(last)?;
    if first.state != last.state || first.status != last.status {
        return Err(Refusal::SamplingChanged);
    }
    let error = micros(
        first
            .maximum_error_micros
            .max(last.maximum_error_micros)
            .max(first.estimated_error_micros)
            .max(last.estimated_error_micros),
    )?;
    // maxerror/esterror/precision stay in microseconds even with STA_NANO.
    // Include a full microsecond for that interface's error-field rounding.
    let quantization = micros(first.precision_micros.max(last.precision_micros))?
        .checked_add(Duration::from_micros(1))
        .ok_or(Refusal::Overflow)?;
    // Linux tolerance is scaled ppm (65536 per ppm). Reserve one second of
    // reported drift, rounding upward, in addition to the whole sampling span.
    let drift_nanos = first
        .tolerance_scaled_ppm
        .max(last.tolerance_scaled_ppm)
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(65_535))
        .ok_or(Refusal::Overflow)?
        / 65_536;
    let drift = Duration::from_nanos(u64::try_from(drift_nanos).map_err(|_| Refusal::Overflow)?);
    let allowed_progress = sample
        .elapsed
        .checked_add(quantization.checked_mul(2).ok_or(Refusal::Overflow)?)
        .ok_or(Refusal::Overflow)?;
    let progress = now
        .as_offset_datetime()
        .unix_timestamp_nanos()
        .checked_sub(before.as_offset_datetime().unix_timestamp_nanos())
        .ok_or(Refusal::Overflow)?;
    if progress < 0
        || u128::try_from(progress).map_err(|_| Refusal::Overflow)? > allowed_progress.as_nanos()
    {
        return Err(Refusal::SamplingChanged);
    }
    let uncertainty = error
        .checked_add(quantization)
        .and_then(|value| value.checked_add(drift))
        .and_then(|value| value.checked_add(sample.elapsed))
        .ok_or(Refusal::Overflow)?;
    Ok((now, uncertainty))
}

#[cfg(test)]
#[path = "platform_clock_snapshot_tests.rs"]
mod snapshot_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "platform_clock_test_support.rs"]
pub(crate) mod test_support;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Clone, Copy)]
    struct PlatformTimeSyncObservation {
        synchronized: bool,
        maximum_error_microseconds: i64,
    }

    impl PlatformAuthenticationTimeSource {
        fn observe(
            &self,
            observation: PlatformTimeSyncObservation,
            now: Timestamp,
        ) -> Result<RealtimeReading, AuthenticationTimeError> {
            let nanos = now.as_offset_datetime().unix_timestamp_nanos();
            let raw = RealtimeSnapshot {
                state: if observation.synchronized {
                    TIME_OK
                } else {
                    TIME_ERROR
                },
                status: STA_PLL | STA_NANO,
                seconds: nanos.div_euclid(1_000_000_000),
                subsecond: nanos.rem_euclid(1_000_000_000),
                maximum_error_micros: i128::from(observation.maximum_error_microseconds),
                estimated_error_micros: 0,
                precision_micros: 1,
                tolerance_scaled_ppm: 32_768_000,
            };
            let sample = KernelSample {
                observations: [Ok(raw); 2],
                elapsed: Duration::ZERO,
            };
            self.accept_sample(&mut self.state.lock().unwrap(), sample)
        }
    }

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
        assert_eq!(reading.uncertainty, Duration::from_micros(3_002));
        assert_eq!(reading.synchronization_generation, 1);
        assert_eq!(reading.now, at(0));
        // A stable synchronized source does not advance the generation.
        let second = source
            .observe(synchronized(3_500), at(1))
            .expect("synchronized");
        assert_eq!(second.uncertainty, Duration::from_micros(4_002));
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
            .observe(synchronized(4_498), at(1))
            .expect("within bound, including 502 microseconds of quantization and drift");
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
