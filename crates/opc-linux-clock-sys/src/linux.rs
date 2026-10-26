//! Linux `clock_adjtime(CLOCK_REALTIME)` read-only query.

use std::io;

pub(super) fn read_clock_adjustment() -> io::Result<super::KernelClockAdjustment> {
    read_with(|clock, raw| {
        // SAFETY: read_with supplies a live initialized timex, fixes realtime
        // and leaves modes at zero. The syscall only reads clock state and
        // writes the observation into this owned value.
        unsafe { libc::clock_adjtime(clock, raw) }
    })
}

#[allow(
    clippy::useless_conversion,
    reason = "libc's c_long timex fields are i32 on 32-bit targets and i64 on 64-bit"
)]
fn read_with(
    query: impl FnOnce(libc::clockid_t, &mut libc::timex) -> libc::c_int,
) -> io::Result<super::KernelClockAdjustment> {
    // SAFETY: timex is a C integer aggregate. Zero initializes every field
    // and padding byte; modes=0 selects the documented read-only operation.
    let mut adjustment: libc::timex = unsafe { std::mem::zeroed() };
    let clock_state = query(libc::CLOCK_REALTIME, &mut adjustment);
    if clock_state < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(super::KernelClockAdjustment {
        clock_state,
        status: adjustment.status,
        max_error_microseconds: i64::from(adjustment.maxerror),
        estimated_error_microseconds: i64::from(adjustment.esterror),
        seconds: i128::from(adjustment.time.tv_sec),
        subsecond: i128::from(adjustment.time.tv_usec),
        precision_microseconds: i128::from(adjustment.precision),
        tolerance_scaled_ppm: i128::from(adjustment.tolerance),
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::RealtimeSnapshot;

    #[test]
    fn realtime_query_fixes_read_only_mode_and_preserves_raw_fields() {
        let observed = read_with(|clock, raw| {
            assert_eq!(clock, libc::CLOCK_REALTIME);
            assert_eq!(raw.modes, 0);
            assert_eq!(raw.offset, 0);
            assert_eq!(raw.freq, 0);
            raw.status = libc::STA_NANO;
            raw.time.tv_sec = 123;
            raw.time.tv_usec = 456;
            raw.maxerror = 789;
            raw.esterror = -1;
            raw.precision = 2;
            raw.tolerance = 32768000;
            libc::TIME_OK
        });
        assert_eq!(
            observed.unwrap().realtime_snapshot(),
            RealtimeSnapshot {
                state: libc::TIME_OK,
                status: libc::STA_NANO,
                seconds: 123,
                subsecond: 456,
                maximum_error_micros: 789,
                estimated_error_micros: -1,
                precision_micros: 2,
                tolerance_scaled_ppm: 32768000,
            }
        );
    }

    #[test]
    fn realtime_query_preserves_synchronization_failure_as_observation() {
        let observed = read_with(|clock, raw| {
            assert_eq!(clock, libc::CLOCK_REALTIME);
            assert_eq!(raw.modes, 0);
            raw.status = libc::STA_UNSYNC;
            libc::TIME_ERROR
        })
        .unwrap();
        assert_eq!(observed.realtime_snapshot().state, libc::TIME_ERROR);
        assert_eq!(observed.realtime_snapshot().status, libc::STA_UNSYNC);
    }
}
