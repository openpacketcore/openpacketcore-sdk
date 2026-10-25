//! Unsupported-platform stub: every kernel clock read fails explicitly.

use std::io;

// The Linux UAPI values are reproduced here so the safe API compiles and
// reports "not synchronized" without libc on non-Linux targets. They are only
// reachable on a platform whose read always fails first.
pub(super) const TIME_ERROR: i32 = 5;
pub(super) const STA_UNSYNC: i32 = 0x0040;

pub(super) fn read_clock_adjustment() -> io::Result<(i32, i32, i64, i64)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "kernel clock adjustment is supported only on Linux",
    ))
}
