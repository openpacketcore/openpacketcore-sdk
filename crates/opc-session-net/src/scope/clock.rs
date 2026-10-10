//! Authentication freshness, independent of untimed ownership and effect state.
use opc_tls::AuthenticationTimeInterval;
use opc_types::Timestamp;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

/// No trustworthy complete authentication interval is currently available.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("authentication time unavailable")]
pub struct AuthenticationTimeError;

/// Trusted platform time observation, never accepted from protocol input.
#[derive(Clone, Copy, Debug)]
pub struct RealtimeReading {
    /// Platform realtime observation.
    pub now: Timestamp,
    /// Actual symmetric uncertainty of this observation.
    pub uncertainty: Duration,
    /// Positive platform synchronization generation; changes after resynchronization.
    pub synchronization_generation: u64,
}

/// Installed trusted platform adapter. Report unknown synchronization or known
/// excessive skew as an error, rather than claiming a larger uncertainty.
pub trait AuthenticationTimeSource: Send + Sync {
    /// Read a fresh observation and its actual error bound.
    fn read(&self) -> Result<RealtimeReading, AuthenticationTimeError>;
}

/// Authentication-time port used on every proof and response admission.
pub trait AuthenticationClock: Send + Sync {
    /// Obtain the entire interval; failure changes no ownership or accepted work.
    fn interval(&self) -> Result<AuthenticationTimeInterval, AuthenticationTimeError>;
}

/// Fixed-budget clock adapter with monotonic progress/regression checks.
pub struct IntervalClock {
    source: Arc<dyn AuthenticationTimeSource>,
    budget: Duration,
    state: Mutex<ClockState>,
}
#[derive(Default)]
struct ClockState {
    previous: Option<(RealtimeReading, tokio::time::Instant)>,
    recovering: Option<(tokio::time::Instant, u8)>,
}
impl IntervalClock {
    /// Install a trusted source and freeze the maximum allowed uncertainty.
    /// The adapter never widens this budget to make authentication succeed.
    pub fn new(
        source: Arc<dyn AuthenticationTimeSource>,
        budget: Duration,
    ) -> Result<Self, AuthenticationTimeError> {
        time::Duration::try_from(budget).map_err(|_| AuthenticationTimeError)?;
        Ok(Self {
            source,
            budget,
            state: Mutex::new(ClockState::default()),
        })
    }
}
impl AuthenticationClock for IntervalClock {
    fn interval(&self) -> Result<AuthenticationTimeInterval, AuthenticationTimeError> {
        let mut state = self.state.lock().map_err(|_| AuthenticationTimeError)?;
        let current = self.source.read()?;
        let monotonic = tokio::time::Instant::now();
        if current.uncertainty > self.budget || current.synchronization_generation == 0 {
            return Err(AuthenticationTimeError);
        }
        if let Some((old, old_monotonic)) = state.previous {
            if current.synchronization_generation < old.synchronization_generation {
                return Err(AuthenticationTimeError);
            }
            if current.synchronization_generation == old.synchronization_generation {
                let wall_step = current.now.as_offset_datetime().unix_timestamp_nanos()
                    - old.now.as_offset_datetime().unix_timestamp_nanos();
                let monotonic_step = i128::try_from(
                    monotonic
                        .saturating_duration_since(old_monotonic)
                        .as_nanos(),
                )
                .map_err(|_| AuthenticationTimeError)?;
                let tolerance =
                    i128::try_from(current.uncertainty.as_nanos() + old.uncertainty.as_nanos())
                        .map_err(|_| AuthenticationTimeError)?;
                if wall_step < 0 || (wall_step - monotonic_step).abs() > tolerance {
                    // Retain the refused observation only as a recovery baseline.
                    // It cannot authorize authentication until fresh observations
                    // demonstrate consistent progress against monotonic time.
                    state.previous = Some((current, monotonic));
                    state.recovering = Some((monotonic, 0));
                    tracing::warn!(
                        "authentication clock step detected; awaiting consistent readings"
                    );
                    return Err(AuthenticationTimeError);
                }
                if let Some((since, mut samples)) = state.recovering {
                    if monotonic.saturating_duration_since(old_monotonic) >= Duration::from_secs(1)
                    {
                        samples = samples.saturating_add(1);
                        state.previous = Some((current, monotonic));
                    }
                    state.recovering = Some((since, samples));
                    if samples < 3
                        || monotonic.saturating_duration_since(since) < Duration::from_secs(3)
                    {
                        return Err(AuthenticationTimeError);
                    }
                    state.recovering = None;
                    tracing::warn!("authentication clock recovered after consistent readings");
                }
            } else {
                // An explicitly newer trusted synchronization generation remains
                // sufficient; adapters need not supply one after every step.
                state.recovering = None;
            }
        }
        let error =
            time::Duration::try_from(current.uncertainty).map_err(|_| AuthenticationTimeError)?;
        let earliest = current
            .now
            .as_offset_datetime()
            .checked_sub(error)
            .ok_or(AuthenticationTimeError)?;
        let latest = current
            .now
            .as_offset_datetime()
            .checked_add(error)
            .ok_or(AuthenticationTimeError)?;
        let interval = AuthenticationTimeInterval::new(
            Timestamp::from_offset_datetime(earliest),
            Timestamp::from_offset_datetime(latest),
        )
        .map_err(|_| AuthenticationTimeError)?;
        state.previous = Some((current, monotonic));
        Ok(interval)
    }
}
