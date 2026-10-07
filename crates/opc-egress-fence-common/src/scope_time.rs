//! Conservative deadline arithmetic for a namespace-owned scope packet gate.
//!
//! These values describe time bounds, not authenticated lease authority. They
//! neither sample a clock nor install or update a kernel gate.
//!
//! A trusted provider must guarantee a common-time upper envelope through an
//! absolute BOOTTIME horizon, including when userspace cannot run. A sample of
//! wall time alone is insufficient. See `docs/lease-timed-packet-gate.md` in the
//! repository for the assumptions, timing proof and remaining kernel work.

use core::fmt;

const RATE_SCALE: u128 = 1_000_000_000;
const MAX_SAMPLE_UNCERTAINTY_NS: i128 = 1_000_000_000;

/// A trusted common-time sample bracketed by kernel-domain BOOTTIME readings.
///
/// This is a checked description of the provider's promise, not evidence that
/// the promise is true. No system clock or synchronization service is selected
/// automatically. The future bound must hold despite pause, suspend and loss
/// of synchronization, until its fixed horizon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeClockCorrelation {
    boot_before_ns: u64,
    boot_after_ns: u64,
    latest_common_ns: i128,
    max_rate_error_ppb: u32,
    max_forward_error_ns: u64,
    valid_until_boot_ns: u64,
}

/// A half-open interval in the kernel's suspend-aware BOOTTIME domain.
///
/// Equality at the stop deadline is expired. This value carries no execution,
/// fence or grant identity and cannot authorize an update to a packet gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopePacketDeadline {
    not_before_boot_ns: u64,
    stop_boot_ns: u64,
}

/// Stable, value-free refusal of a scope clock conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeClockError {
    /// The sample or its future validity interval is invalid.
    InvalidCorrelation,
    /// The common-time interval exceeds the scope clock guard.
    ClockUncertain,
    /// A later BOOTTIME reading precedes the completed sample.
    ClockRegressed,
    /// The prospective clock guarantee no longer holds.
    BoundExpired,
    /// No positive packet lifetime remains.
    Expired,
    /// A clock conversion cannot be represented without overflow.
    Overflow,
}

impl ScopeClockCorrelation {
    /// Validate the bracket, common-time interval and prospective clock bound.
    ///
    /// `earliest_common_ns..=latest_common_ns` must contain the actual common
    /// time at a sample taken between `boot_before_ns` and `boot_after_ns`.
    /// Its width may not exceed the one-second clock guard in the scope-lease
    /// profile specified by [#1134](https://github.com/openpacketcore/openpacketcore-sdk/issues/1134).
    /// Common time is signed nanoseconds in the same domain as the lease's
    /// absolute deadlines, independent of the local boot origin.
    ///
    /// From sample completion up to, but not including, the validity horizon
    /// (`boot_after_ns <= b < valid_until_boot_ns`), actual common time at boot
    /// reading `b` must be no greater than:
    ///
    /// ```text
    /// latest_common_ns + max_forward_error_ns
    ///     + (b - boot_before_ns) * (1 + max_rate_error_ppb / 1_000_000_000)
    /// ```
    ///
    /// The ratio is a real-number upper bound, not integer division.
    /// `max_forward_error_ns` budgets total forward discontinuity, including
    /// suspend-accounting error and hypervisor pause or migration that can
    /// freeze guest BOOTTIME. Unbounded pauses make the platform unsupported.
    /// The rate bound covers relative clock drift and time-daemon slew (Linux
    /// permits adjustments of about 10%), unless the total correction through
    /// the horizon is instead covered by the forward-error allowance. Express
    /// this as common-time growth per boot tick: a 10% slower boot clock needs
    /// a rate factor of at least `1 / 0.9`, not `1.1`.
    /// The promise must hold for the entire horizon without a userspace
    /// callback. Providers unable to make it must not construct a correlation.
    ///
    /// If the sample comes from a store reply, `boot_before_ns` is the first
    /// send of that logical request and `boot_after_ns` is receipt. Exact
    /// retries return the original stamp, so they must retain the first-send
    /// reading, never replace it with a retry-send reading. A lost first-send
    /// reading cannot be reconstructed from the reply; refuse that correlation.
    ///
    /// All boot readings must use the same domain as `bpf_ktime_get_boot_ns`.
    /// An offset time-namespace clock, `Instant`, or `CLOCK_MONOTONIC` is not
    /// interchangeable with it. This function does not verify clock identity.
    pub fn new(
        boot_before_ns: u64,
        boot_after_ns: u64,
        earliest_common_ns: i128,
        latest_common_ns: i128,
        max_rate_error_ppb: u32,
        max_forward_error_ns: u64,
        valid_until_boot_ns: u64,
    ) -> Result<Self, ScopeClockError> {
        if boot_before_ns > boot_after_ns || valid_until_boot_ns <= boot_after_ns {
            return Err(ScopeClockError::InvalidCorrelation);
        }
        let uncertainty = latest_common_ns
            .checked_sub(earliest_common_ns)
            .ok_or(ScopeClockError::Overflow)?;
        if uncertainty < 0 {
            return Err(ScopeClockError::InvalidCorrelation);
        }
        if uncertainty > MAX_SAMPLE_UNCERTAINTY_NS {
            return Err(ScopeClockError::ClockUncertain);
        }
        Ok(Self {
            boot_before_ns,
            boot_after_ns,
            latest_common_ns,
            max_rate_error_ppb,
            max_forward_error_ns,
            valid_until_boot_ns,
        })
    }

    /// Translate an immutable common-domain stop deadline without rebasing it.
    ///
    /// The result stops no later than the prospective clock horizon. Sampling
    /// and response delays consume the remaining lifetime: the calculation
    /// starts at the *first* bracket reading, never at `observed_boot_ns`.
    /// A repeated call with the same correlation and stop returns the same
    /// deadline while it remains live. An expired or unrepresentable result is
    /// refused, never saturated into a later authorization.
    ///
    /// A controller must bind and cache this result once per committed grant
    /// revision. Re-sampling an old grant must not extend its installed deadline.
    /// Authenticating grants and rejecting stale execution/fence/revision
    /// updates remain the controller's responsibility.
    pub fn deadline_for(
        self,
        stop_common_ns: i128,
        observed_boot_ns: u64,
    ) -> Result<ScopePacketDeadline, ScopeClockError> {
        if observed_boot_ns < self.boot_after_ns {
            return Err(ScopeClockError::ClockRegressed);
        }
        if observed_boot_ns >= self.valid_until_boot_ns {
            return Err(ScopeClockError::BoundExpired);
        }
        let upper = self
            .latest_common_ns
            .checked_add(i128::from(self.max_forward_error_ns))
            .ok_or(ScopeClockError::Overflow)?;
        let remaining = stop_common_ns
            .checked_sub(upper)
            .ok_or(ScopeClockError::Overflow)?;
        if remaining <= 0 {
            return Err(ScopeClockError::Expired);
        }
        let scaled = (remaining as u128)
            .checked_mul(RATE_SCALE)
            .ok_or(ScopeClockError::Overflow)?;
        let boot_lifetime =
            u64::try_from(scaled / (RATE_SCALE + u128::from(self.max_rate_error_ppb)))
                .map_err(|_| ScopeClockError::Overflow)?;
        let stop_boot_ns = self
            .boot_before_ns
            .checked_add(boot_lifetime)
            .ok_or(ScopeClockError::Overflow)?
            .min(self.valid_until_boot_ns);
        if observed_boot_ns >= stop_boot_ns {
            return Err(ScopeClockError::Expired);
        }
        Ok(ScopePacketDeadline {
            not_before_boot_ns: self.boot_after_ns,
            stop_boot_ns,
        })
    }
}

impl ScopePacketDeadline {
    /// First BOOTTIME nanosecond at which traffic must be closed.
    #[must_use]
    pub const fn stop_boot_ns(self) -> u64 {
        self.stop_boot_ns
    }

    /// Check only the time interval; this grants no packet authority.
    ///
    /// Read the kernel clock for every packet, including queued retransmissions.
    /// A caller-supplied or cached timestamp is not enforcement. Observations
    /// preceding the completed sample also fail closed.
    #[must_use]
    pub const fn is_live_at(self, observed_boot_ns: u64) -> bool {
        observed_boot_ns >= self.not_before_boot_ns && observed_boot_ns < self.stop_boot_ns
    }
}

impl fmt::Display for ScopeClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCorrelation => "scope_clock_invalid_correlation",
            Self::ClockUncertain => "scope_clock_uncertain",
            Self::ClockRegressed => "scope_clock_regressed",
            Self::BoundExpired => "scope_clock_bound_expired",
            Self::Expired => "scope_clock_deadline_expired",
            Self::Overflow => "scope_clock_overflow",
        })
    }
}

impl core::error::Error for ScopeClockError {}
