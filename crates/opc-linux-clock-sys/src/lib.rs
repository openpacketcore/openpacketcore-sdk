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

/// Audit-clock state reported by the kernel after one clock-adjustment read.
///
/// The value is a snapshot of the kernel's NTP state: whether the realtime
/// clock is currently synchronized and the kernel's maximum and estimated
/// error bounds. It carries no clock reading, identity, address or payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelClockAdjustment {
    clock_state: i32,
    status: i32,
    max_error_microseconds: i64,
    estimated_error_microseconds: i64,
}

impl KernelClockAdjustment {
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
        self.clock_state != platform::TIME_ERROR && self.status & platform::STA_UNSYNC == 0
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
    /// This is the kernel's `timex.esterror` field. It is reported for
    /// diagnostics only; a bounded maximum error uses
    /// [`Self::max_error_microseconds`].
    #[must_use]
    pub const fn estimated_error_microseconds(self) -> i64 {
        self.estimated_error_microseconds
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
    let (clock_state, status, max_error_microseconds, estimated_error_microseconds) =
        platform::read_clock_adjustment()?;
    Ok(KernelClockAdjustment::new(
        clock_state,
        status,
        max_error_microseconds,
        estimated_error_microseconds,
    ))
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
        // A pending leap-second state is still a synchronized clock.
        for state in [1, 2, 3, 4] {
            assert!(
                KernelClockAdjustment::from_kernel_fields(state, 0, 1_000, 1_000).is_synchronized()
            );
        }
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
