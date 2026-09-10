//! Schedule large log decoder temporaries within the existing process budget.
//!
//! Several voters can each validate a public 256-request row while background
//! append verification and snapshot reads validate other rows. Their bounded
//! scratch peaks can overlap beyond the process cap even though retained data
//! fits. Serialize those large CPU sections before reserving their scratch.
//! Small decoders keep direct admission. Callers must release State and finish
//! input I/O first; a permit never spans a disk read, append, sync or selection.

use crate::consensus::verified_snapshot::{VerificationMemory, PROCESS_VERIFICATION_BYTES};
use std::io;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

const LARGE_LOG_BYTES: usize = PROCESS_VERIFICATION_BYTES / 8;
static LARGE_LOG: LargeLogGate = LargeLogGate::new();

struct LargeLogGate {
    busy: Mutex<bool>,
    available: Condvar,
}

impl LargeLogGate {
    const fn new() -> Self {
        Self {
            busy: Mutex::new(false),
            available: Condvar::new(),
        }
    }

    fn acquire(
        &'static self,
        bytes: usize,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Option<LargeLogPermit>> {
        if bytes < LARGE_LOG_BYTES {
            return Ok(None);
        }
        loop {
            // The existing owner/cancellation check also bounds this wait.
            // Run it without the scheduling mutex: it may inspect State.
            check()?;
            let mut busy = self
                .busy
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if !*busy {
                *busy = true;
                return Ok(Some(LargeLogPermit(self)));
            }
            drop(
                self.available
                    .wait_timeout(busy, Duration::from_millis(1))
                    .unwrap_or_else(|poison| poison.into_inner()),
            );
        }
    }
}

struct LargeLogPermit(&'static LargeLogGate);

impl Drop for LargeLogPermit {
    fn drop(&mut self) {
        // This mutex protects scheduling only. Decoder errors and unwinding
        // retain the caller's original integrity fencing and cannot poison it.
        let mut busy = self
            .0
            .busy
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *busy = false;
        self.0.available.notify_one();
    }
}

pub(in crate::consensus::native) struct LogMemory {
    // Fields drop in declaration order: refund scratch before admitting the
    // next large decoder. All decoded temporaries must be destroyed first.
    memory: VerificationMemory,
    _permit: Option<LargeLogPermit>,
}

impl LogMemory {
    pub(in crate::consensus::native) fn reserve(
        bytes: usize,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        Self::reserve_with(&LARGE_LOG, bytes, check, VerificationMemory::reserve)
    }

    fn reserve_with(
        gate: &'static LargeLogGate,
        bytes: usize,
        check: &impl Fn() -> io::Result<()>,
        reserve: impl FnOnce(usize) -> io::Result<VerificationMemory>,
    ) -> io::Result<Self> {
        check()?;
        let permit = gate.acquire(bytes, check)?;
        check()?;
        // The original shared counter still refuses exhausted retained data
        // or other verification work. No cap, allocation bound or validation
        // changes, and no memory is reserved while waiting for this permit.
        let memory = reserve(bytes)?;
        Ok(Self {
            memory,
            _permit: permit,
        })
    }

    pub(in crate::consensus::native) fn shrink_to(&mut self, bytes: usize) -> io::Result<()> {
        self.memory.shrink_to(bytes)
    }

    /// After decoder destruction and shrink, return the retained copy's
    /// reservation while releasing CPU admission. The result may outlive any
    /// number of subsequent decoders without keeping their permit occupied.
    pub(in crate::consensus::native) fn into_memory(self) -> VerificationMemory {
        self.memory
    }
}

#[cfg(test)]
#[path = "scratch_admission_tests.rs"]
mod tests;
