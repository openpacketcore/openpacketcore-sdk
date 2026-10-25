//! Linux `clock_adjtime(CLOCK_REALTIME)` read-only query.

use std::io;

/// The kernel reports that the clock was not synchronized.
pub(super) const TIME_ERROR: i32 = libc::TIME_ERROR;

/// Kernel status bit: the clock is not synchronized.
pub(super) const STA_UNSYNC: i32 = libc::STA_UNSYNC;

#[allow(
    clippy::useless_conversion,
    reason = "libc's c_long timex fields are i32 on 32-bit targets and i64 on 64-bit"
)]
pub(super) fn read_clock_adjustment() -> io::Result<(i32, i32, i64, i64)> {
    // `modes == 0` makes the query read-only: the kernel fills the complete
    // `timex` snapshot and returns the clock state (TIME_OK .. TIME_ERROR).
    let mut adjustment = std::mem::MaybeUninit::<libc::timex>::zeroed();
    // SAFETY: `adjustment` is a valid zeroed `timex`; a zeroed `modes` field is
    // the documented read-only request and no clock parameter is modified. On
    // success the kernel initializes the whole structure through the pointer.
    let clock_state = unsafe { libc::clock_adjtime(libc::CLOCK_REALTIME, adjustment.as_mut_ptr()) };
    if clock_state < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `clock_adjtime` returned a non-negative clock state, so the
    // kernel wrote the complete `timex` structure before returning.
    let adjustment = unsafe { adjustment.assume_init() };
    Ok((
        clock_state,
        adjustment.status,
        i64::from(adjustment.maxerror),
        i64::from(adjustment.esterror),
    ))
}
