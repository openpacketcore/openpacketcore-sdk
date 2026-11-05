//! Test-only access to the real resource waits and terminal notifications.
use super::*;
use crate::test_process::witness::CondvarExt;

impl Wal {
    pub(in crate::sqlite::consensus) fn native_hold_ceiling_checkpoint_for_test(&self, held: bool) {
        let mut state = lock_state(&self.shared).unwrap();
        if held {
            assert!(state.snapshot.is_none() && !state.native_live_capacity);
        }
        state.native_ceiling_wait = held;
        state.native_basis_active = held;
        self.shared.ready.notify_all();
    }

    pub(in crate::sqlite::consensus) fn native_unarmed_install_claim_for_test(
        &self,
        claimed: bool,
    ) {
        let mut state = lock_state(&self.shared).unwrap();
        assert!(state.snapshot.is_none());
        state.native_install_pending = claimed;
        self.shared.ready.notify_all();
    }

    pub(in crate::sqlite::consensus) fn native_wait_at_guard_for_test(
        &self,
        resource: bool,
    ) -> io::Result<Duration> {
        if resource {
            self.wait_for_native_resource_guard()
        } else {
            self.wait_for_native_file_guard()
        }
    }

    pub(in crate::sqlite::consensus) fn native_live_capacity_guard_for_test(&self, active: bool) {
        let mut state = lock_state(&self.shared).unwrap();
        state.native_ceiling_wait = active;
        state.native_live_capacity = active;
        // Hold the simulated capacity owner's checkpoint slot: an unrelated
        // ordinary checkpoint must not clear this protocol fixture's guard.
        state.native_basis_active = active;
        self.shared.ready.notify_all();
    }

    pub(in crate::sqlite::consensus) fn native_retry_journal_reservation_for_test(
        &self,
        bytes: usize,
    ) -> io::Result<()> {
        use crate::consensus::verified_snapshot::VerificationMemory;
        let mut progress = None;
        loop {
            match VerificationMemory::reserve_journal(bytes) {
                Ok(memory) => {
                    drop(memory);
                    return Ok(());
                }
                Err(error) if VerificationMemory::journal_pressure(&error).is_some() => {
                    self.wait_for_journal_memory(&mut progress, bytes)?
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(in crate::sqlite::consensus) fn native_request_pending_journal_drain_for_test(&self) {
        let mut state = lock_state(&self.shared).unwrap();
        assert!(state.native_pending_base && state.native_live_capacity);
        state.native_pending_journal_pressure = true;
        self.shared.ready.notify_all();
    }

    pub(in crate::sqlite::consensus) fn native_wait_for_background_failure_for_test(&self) -> bool {
        let mut state = lock_state(&self.shared).unwrap();
        while state.status == Status::Running {
            state = self.shared.ready.test_wait(state).unwrap();
        }
        state.status == Status::Failed
    }
}

impl Wal {
    pub(in crate::sqlite::consensus) fn native_wait_for_checkpoint_ready_for_test(
        &self,
        pending: bool,
    ) {
        let mut state = lock_state(&self.shared).unwrap();
        while if pending {
            !state.native_pending_ready
        } else {
            !state.native_basis_ready
        } {
            assert!(state.status == Status::Running);
            state = self.shared.ready.test_wait(state).unwrap();
        }
    }
}
