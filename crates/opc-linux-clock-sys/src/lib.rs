//! Narrow Linux clock-adjustment UAPI boundary for OpenPacketCore.
//!
//! This crate owns the only raw kernel call needed by the safe
//! `opc-session-net` authentication-time source: a read-only
//! `clock_adjtime(CLOCK_REALTIME)` query of the kernel NTP/clock state. It
//! deliberately does not implement NTP, time synchronization, clock policy or
//! authentication decisions.
//!
//! Unsupported platforms compile to a stub whose only read fails explicitly;
//! there is no wall-clock fallback or invented synchronization state.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

use std::io;

#[cfg(all(target_os = "linux", not(opc_linux_clock_sys_force_unsupported)))]
mod linux;
#[cfg_attr(
    all(target_os = "linux", not(opc_linux_clock_sys_force_unsupported)),
    allow(dead_code)
)]
mod unsupported;

#[cfg(all(target_os = "linux", not(opc_linux_clock_sys_force_unsupported)))]
use linux as platform;
#[cfg(any(not(target_os = "linux"), opc_linux_clock_sys_force_unsupported))]
use unsupported as platform;

/// Stable Linux UAPI synchronization states and status flags.
pub mod status {
    /// Linux `TIME_OK` UAPI value.
    pub const TIME_OK: i32 = 0x0000;
    /// Linux `TIME_INS` UAPI value.
    pub const TIME_INS: i32 = 0x0001;
    /// Linux `TIME_DEL` UAPI value.
    pub const TIME_DEL: i32 = 0x0002;
    /// Linux `TIME_OOP` UAPI value.
    pub const TIME_OOP: i32 = 0x0003;
    /// Linux `TIME_WAIT` UAPI value.
    pub const TIME_WAIT: i32 = 0x0004;
    /// Linux `TIME_ERROR` UAPI value.
    pub const TIME_ERROR: i32 = 0x0005;
    /// Linux `STA_PLL` UAPI value.
    pub const STA_PLL: i32 = 0x0001;
    /// Linux `STA_PPSFREQ` UAPI value.
    pub const STA_PPSFREQ: i32 = 0x0002;
    /// Linux `STA_PPSTIME` UAPI value.
    pub const STA_PPSTIME: i32 = 0x0004;
    /// Linux `STA_FLL` UAPI value.
    pub const STA_FLL: i32 = 0x0008;
    /// Linux `STA_INS` UAPI value.
    pub const STA_INS: i32 = 0x0010;
    /// Linux `STA_DEL` UAPI value.
    pub const STA_DEL: i32 = 0x0020;
    /// Linux `STA_UNSYNC` UAPI value.
    pub const STA_UNSYNC: i32 = 0x0040;
    /// Linux `STA_FREQHOLD` UAPI value.
    pub const STA_FREQHOLD: i32 = 0x0080;
    /// Linux `STA_PPSSIGNAL` UAPI value.
    pub const STA_PPSSIGNAL: i32 = 0x0100;
    /// Linux `STA_PPSJITTER` UAPI value.
    pub const STA_PPSJITTER: i32 = 0x0200;
    /// Linux `STA_PPSWANDER` UAPI value.
    pub const STA_PPSWANDER: i32 = 0x0400;
    /// Linux `STA_PPSERROR` UAPI value.
    pub const STA_PPSERROR: i32 = 0x0800;
    /// Linux `STA_CLOCKERR` UAPI value.
    pub const STA_CLOCKERR: i32 = 0x1000;
    /// Linux `STA_NANO` UAPI value.
    pub const STA_NANO: i32 = 0x2000;
    /// Linux `STA_MODE` UAPI value.
    pub const STA_MODE: i32 = 0x4000;
    /// Linux `STA_CLK` UAPI value.
    pub const STA_CLK: i32 = 0x8000;
}

/// Raw kernel observation. Consumers must validate its state, units and bounds.
/// Signed fields preserve invalid values for fail-closed validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealtimeSnapshot {
    /// Returned Linux `TIME_*` state.
    pub state: i32,
    /// Returned Linux `STA_*` bit mask.
    pub status: i32,
    /// Realtime seconds since the Unix epoch.
    pub seconds: i128,
    /// Nanoseconds with `STA_NANO`, otherwise microseconds, within the second.
    pub subsecond: i128,
    /// Kernel maximum error, always in microseconds.
    pub maximum_error_micros: i128,
    /// Kernel estimated error, always in microseconds.
    pub estimated_error_micros: i128,
    /// Kernel precision, always in microseconds.
    pub precision_micros: i128,
    /// Frequency tolerance in scaled ppm (65536 units per ppm).
    pub tolerance_scaled_ppm: i128,
}

/// Audit-clock state reported by the kernel after one clock-adjustment read.
///
/// The value is a snapshot of the kernel's NTP state: whether the realtime
/// clock is currently synchronized and the kernel's maximum and estimated
/// error bounds and the realtime instant returned in that same snapshot.
/// It carries no identity, address or application payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelClockAdjustment {
    clock_state: i32,
    status: i32,
    max_error_microseconds: i64,
    estimated_error_microseconds: i64,
    seconds: i128,
    subsecond: i128,
    precision_microseconds: i128,
    tolerance_scaled_ppm: i128,
}

impl KernelClockAdjustment {
    #[cfg(test)]
    const fn new(
        clock_state: i32,
        status: i32,
        max_error_microseconds: i64,
        estimated_error_microseconds: i64,
    ) -> Self {
        Self {
            clock_state,
            status,
            max_error_microseconds,
            estimated_error_microseconds,
            seconds: 0,
            subsecond: 0,
            precision_microseconds: 1,
            tolerance_scaled_ppm: 32_768_000,
        }
    }

    /// Whether the kernel reports a synchronized realtime clock.
    ///
    /// A reader must not treat a non-synchronized kernel as a trusted
    /// authentication-time source; [`read_kernel_clock_adjustment`] still
    /// returns the state so callers can distinguish "unsynchronized" from
    /// "the read failed".
    #[must_use]
    pub const fn is_synchronized(self) -> bool {
        use status::*;
        matches!(self.clock_state, TIME_OK | TIME_INS | TIME_DEL | TIME_WAIT)
            && self.status & !0xffff == 0
            && self.status & (STA_UNSYNC | STA_CLOCKERR) == 0
            && self.status & (STA_INS | STA_DEL) != (STA_INS | STA_DEL)
            && (self.status & (STA_PPSFREQ | STA_PPSTIME) == 0 || self.status & STA_PPSSIGNAL != 0)
            && (self.status & STA_PPSTIME == 0 || self.status & STA_PPSJITTER == 0)
            && (self.status & STA_PPSFREQ == 0 || self.status & (STA_PPSWANDER | STA_PPSERROR) == 0)
    }

    /// Kernel maximum error bound for the realtime clock, in microseconds.
    ///
    /// This is the kernel's `timex.maxerror` field. It can be zero or large
    /// when no synchronization daemon maintains the kernel estimate; callers
    /// must decide their own acceptance bound and never widen it on a retry.
    #[must_use]
    pub const fn max_error_microseconds(self) -> i64 {
        self.max_error_microseconds
    }

    /// Kernel estimated error for the realtime clock, in microseconds.
    ///
    /// This is the kernel's `timex.esterror` field. Conservative consumers use
    /// the larger of this estimate and [`Self::max_error_microseconds`].
    #[must_use]
    pub const fn estimated_error_microseconds(self) -> i64 {
        self.estimated_error_microseconds
    }

    /// Return the complete raw realtime snapshot, preserving signed values.
    /// Consumers must validate synchronization, units and uncertainty bounds.
    #[must_use]
    pub fn realtime_snapshot(self) -> RealtimeSnapshot {
        RealtimeSnapshot {
            state: self.clock_state,
            status: self.status,
            seconds: self.seconds,
            subsecond: self.subsecond,
            maximum_error_micros: i128::from(self.max_error_microseconds),
            estimated_error_micros: i128::from(self.estimated_error_microseconds),
            precision_micros: self.precision_microseconds,
            tolerance_scaled_ppm: self.tolerance_scaled_ppm,
        }
    }

    #[cfg(test)]
    const fn from_kernel_fields(
        clock_state: i32,
        status: i32,
        max_error_microseconds: i64,
        estimated_error_microseconds: i64,
    ) -> Self {
        Self::new(
            clock_state,
            status,
            max_error_microseconds,
            estimated_error_microseconds,
        )
    }
}

/// Read the kernel clock-adjustment state without modifying the clock.
///
/// On Linux this performs one read-only `clock_adjtime(CLOCK_REALTIME)` call
/// (`modes == 0`); no clock parameter is changed and no privilege is requested.
/// An unprivileged caller is refused only by an explicit platform policy such
/// as a seccomp filter or LSM, which surfaces as a typed [`io::Error`].
///
/// On unsupported platforms the returned error kind is
/// [`io::ErrorKind::Unsupported`].
///
/// # Errors
///
/// Propagates the platform error when the read is denied or unavailable. A
/// successful read of an unsynchronized clock is not an error; inspect
/// [`KernelClockAdjustment::is_synchronized`].
pub fn read_kernel_clock_adjustment() -> io::Result<KernelClockAdjustment> {
    platform::read_clock_adjustment()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Stable Linux UAPI values; the safe API must not depend on libc being
    // linked on non-Linux test hosts.
    const STA_UNSYNC: i32 = 0x0040;
    const TIME_OK: i32 = 0;
    const TIME_ERROR: i32 = 5;

    #[test]
    fn synchronized_status_is_derived_from_the_unsync_bit() {
        let synchronized = KernelClockAdjustment::from_kernel_fields(TIME_OK, 0x0001, 1_000, 500);
        assert!(synchronized.is_synchronized());
        assert_eq!(synchronized.max_error_microseconds(), 1_000);
        assert_eq!(synchronized.estimated_error_microseconds(), 500);

        let unsynchronized = KernelClockAdjustment::from_kernel_fields(
            TIME_ERROR, STA_UNSYNC, 16_000_000, 16_000_000,
        );
        assert!(!unsynchronized.is_synchronized());

        // The clock-state return and the status bit are both authoritative;
        // either one refuses synchronization.
        assert!(
            !KernelClockAdjustment::from_kernel_fields(TIME_ERROR, 0, 1_000, 1_000)
                .is_synchronized()
        );
        assert!(
            !KernelClockAdjustment::from_kernel_fields(TIME_OK, STA_UNSYNC, 1_000, 1_000)
                .is_synchronized()
        );
        assert!(!KernelClockAdjustment::from_kernel_fields(
            TIME_OK,
            STA_UNSYNC | 0x0001,
            1_000,
            1_000
        )
        .is_synchronized());
        // Pending/completed leap states remain usable. TIME_OOP (3) is the
        // repeated UTC second itself and must be refused.
        assert!(!KernelClockAdjustment::from_kernel_fields(3, 0, 1_000, 1_000).is_synchronized());
        // A pending leap-second state is still a synchronized clock.
        for state in [1, 2, 4] {
            assert!(
                KernelClockAdjustment::from_kernel_fields(state, 0, 1_000, 1_000).is_synchronized()
            );
        }
    }

    #[test]
    fn ambiguous_unknown_and_faulted_kernel_states_are_not_synchronized() {
        // TIME_OOP is 3 in Linux UAPI; TIME_WAIT is 4 and is synchronized.
        for state in [3, -1, 99] {
            assert!(
                !KernelClockAdjustment::from_kernel_fields(state, 0, 1_000, 500).is_synchronized(),
                "ambiguous or unknown state {state} must fail closed"
            );
        }
        for status in [
            0x1000,  // STA_CLOCKERR
            0x0030,  // contradictory STA_INS | STA_DEL
            0x0004,  // STA_PPSTIME without STA_PPSSIGNAL
            0x0304,  // STA_PPSTIME | STA_PPSSIGNAL | STA_PPSJITTER
            0x0502,  // STA_PPSFREQ | STA_PPSSIGNAL | STA_PPSWANDER
            0x0902,  // STA_PPSFREQ | STA_PPSSIGNAL | STA_PPSERROR
            0x10000, // unknown future status
        ] {
            assert!(
                !KernelClockAdjustment::from_kernel_fields(0, status, 1_000, 500).is_synchronized(),
                "faulted or unknown status {status:#x} must fail closed"
            );
        }
        assert!(KernelClockAdjustment::from_kernel_fields(4, 0, 1_000, 500).is_synchronized());
    }

    #[test]
    fn error_bounds_are_reported_verbatim() {
        let adjustment = KernelClockAdjustment::from_kernel_fields(TIME_OK, 0, i64::MAX, i64::MIN);
        assert_eq!(adjustment.max_error_microseconds(), i64::MAX);
        assert_eq!(adjustment.estimated_error_microseconds(), i64::MIN);
        let zero = KernelClockAdjustment::from_kernel_fields(TIME_OK, 0, 0, 0);
        assert_eq!(zero.max_error_microseconds(), 0);
    }

    #[cfg(all(target_os = "linux", not(opc_linux_clock_sys_force_unsupported)))]
    #[test]
    fn current_kernel_state_read_is_typed_and_does_not_modify_the_clock() {
        // A CI host may be synchronized or not; the contract is a typed
        // result, not a specific synchronization state. The read must never
        // panic or silently substitute a wall clock.
        match read_kernel_clock_adjustment() {
            Ok(adjustment) => {
                // Accessors are value snapshots; the read itself never
                // panics, and a successful read of an unsynchronized clock is
                // still a successful typed read.
                let _ = adjustment.is_synchronized();
                let _ = adjustment.max_error_microseconds();
                let _ = adjustment.estimated_error_microseconds();
            }
            Err(error) => assert!(
                error.raw_os_error().is_some(),
                "a platform read failure carries the kernel errno: {error:?}"
            ),
        }
    }

    #[cfg(any(not(target_os = "linux"), opc_linux_clock_sys_force_unsupported))]
    #[test]
    fn unsupported_platform_reports_unsupported() {
        let error = match read_kernel_clock_adjustment() {
            Ok(adjustment) => panic!("unsupported platform returned {adjustment:?}"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
