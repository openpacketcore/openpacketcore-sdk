//! Application captures keep immutable row roots and the exact semantic
//! predecessor. Decoding, evaluation and after-image preparation occur after
//! the WAL owner releases State. Only checked publication takes that mutex.

use super::*;
use crate::consensus::verified_snapshot::VerificationMemory;
use std::mem::size_of;

pub(crate) struct ApplicationCapture {
    state: NativeState,
    // Covers the bounded frontiers/membership copy and persistent map roots.
    // Historical row bodies remain shared with their original reservations.
    _memory: VerificationMemory,
}

pub(crate) struct ApplicationPublication(changes::Publication);

impl NativeState {
    pub(crate) fn capture_application(&self) -> io::Result<ApplicationCapture> {
        let memory =
            VerificationMemory::reserve(64 * 1024 + size_of::<ApplicationCapture>() + 16 * 1024)?;
        let state = self.clone_for_application()?;
        Ok(ApplicationCapture {
            state,
            _memory: memory,
        })
    }
}

impl ApplicationCapture {
    pub(crate) fn prepare(
        self,
        entries: &[Entry<SessionRaftTypeConfig>],
        check: &impl Fn() -> io::Result<()>,
        before_receipt_read: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<ApplicationPublication> {
        check()?;
        let reads = self.state.capture_apply_reads(entries)?;
        let copies = if reads.is_empty() {
            None
        } else {
            before_receipt_read()?;
            Some(reads.resolve(check)?.copy_current(&self.state)?)
        };
        let delta = self
            .state
            .prepare_using_checked(entries, copies.as_ref(), check)?;
        let publication = changes::Publication::prepare_checked(delta, check)?;
        check()?;
        Ok(ApplicationPublication(publication))
    }
}

impl ApplicationPublication {
    pub(crate) fn is_current(&self, state: &NativeState) -> io::Result<bool> {
        self.0.is_current(state)
    }

    pub(crate) fn publish(self, state: &mut NativeState) -> io::Result<NativeApplied> {
        self.0.publish(state)
    }
}

#[cfg(test)]
#[path = "application_tests.rs"]
mod tests;
