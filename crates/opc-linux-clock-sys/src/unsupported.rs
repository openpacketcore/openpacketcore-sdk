//! Unsupported-platform stub: every kernel clock read fails explicitly.

use std::io;

pub(super) fn read_clock_adjustment() -> io::Result<super::KernelClockAdjustment> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "kernel clock adjustment is supported only on Linux",
    ))
}
