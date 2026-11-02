//! Candidate capacity is scheduling, never an integrity failure. Only this
//! live attempt's preparing name is discarded; the old selected cut survives.

use super::*;

pub(in crate::sqlite::consensus::wal::native_basis) struct Capacity {
    pub after: PrefixIdentity,
    pub live_context: Option<[u8; 32]>,
    pub required: u64,
    pub maximum: u64,
}

impl Built {
    pub fn discard(self, control: &IoControl) -> io::Result<()> {
        self.append.confirm_named(&self.preparing)?;
        (control.hook)(Point::BeforeNativeCandidateDiscard)?;
        self.append.retire();
        fs::remove_file(&self.preparing)?;
        File::open(
            self.preparing
                .parent()
                .ok_or_else(|| invalid_data("native candidate directory missing"))?,
        )?
        .sync_all()?;
        (control.hook)(Point::AfterNativeCandidateDiscard)?;
        Ok(())
    }
}

impl Coordinator {
    pub fn record_pending_attempt(&self, shared: &Arc<Shared>, file_epoch: u64) -> io::Result<()> {
        let mut work = self
            .work
            .lock()
            .map_err(|_| invalid_data("native attempt accounting poisoned"))?;
        if work.attempt_file != file_epoch {
            work.attempt_file = file_epoch;
            work.attempts = 0;
        }
        work.attempts += 1;
        drop(work);
        let mut state = lock_state(shared)?;
        state.checkpoint_costs.compactor_attempts += 1;
        state.checkpoint_costs.pending_base_attempts += 1;
        Ok(())
    }
    pub fn finish_pending(&self) {
        let mut work = self.work.lock().unwrap();
        work.restart_after = None;
        work.live_context = None;
        work.error = None;
        work.queue.clear();
        work.built = None;
        work.active = false;
        work.finished = true;
        work.stop = true;
        // begin_pending already joined the cancelled old compactor. Its cancel
        // bit cannot leak into a later file epoch while a guard awaits the
        // next Job::start; only that live job's cancellation may stop its wait.
        self.cancel.store(false, Ordering::Release);
    }
    pub fn restarting(&self) -> bool {
        self.work.lock().unwrap().restart_after.is_some()
    }
    pub fn restart_finished(&self) -> bool {
        // A poisoned queue is terminal work for the owner to join and reject.
        // Readiness predicates can run under State; they must not panic there
        // and poison that separate mutex before the owner publishes failure.
        let Ok(work) = self.work.lock() else {
            return true;
        };
        work.restart_after.is_some() && work.finished
    }
    pub fn eligible(&self, head: PrefixIdentity) -> bool {
        let work = self.work.lock().unwrap();
        work.restart_after.is_none_or(|after| {
            head.file_epoch == after.file_epoch
                && head.checkpoint_epoch > after.checkpoint_epoch
                && head.operation_sequence >= after.operation_sequence
        }) && work
            .live_context
            .is_none_or(|context| head.frontiers != context)
    }

    pub(in crate::sqlite::consensus::wal::native_basis) fn capacity_abort(
        &self,
        capacity: Capacity,
        shared: &Arc<Shared>,
        control: &IoControl,
    ) -> io::Result<()> {
        let finished = {
            let mut work = self
                .work
                .lock()
                .map_err(|_| invalid_data("native capacity owner poisoned"))?;
            work.queue.clear();
            work.built = None;
            work.active = false;
            work.restart_after = Some(capacity.after);
            work.live_context = capacity.live_context;
            work.finished
        };
        let mut state = lock_state(shared)?;
        state.checkpoint_costs.compactor_restarts += 1;
        state.native_rollover_ready |= finished;
        if capacity.live_context.is_some() {
            state.native_live_capacity = true;
            state.native_ceiling_wait = true;
            state.checkpoint_costs.live_capacity_events += 1;
            tracing::warn!(
                file_epoch = capacity.after.file_epoch,
                checkpoint = capacity.after.checkpoint_epoch,
                required_bytes = capacity.required,
                maximum_bytes = capacity.maximum,
                "native live-data capacity: admission waits for retirement or install"
            );
        }
        shared.ready.notify_all();
        drop(state);
        if capacity.live_context.is_some() {
            (control.hook)(Point::NativeLiveDataCapacity)?;
        }
        (control.hook)(Point::NativeCandidateCapacityRestart)?;
        self.changed.notify_all();
        Ok(())
    }

    pub fn record_switch(&self, shared: &Arc<Shared>, control: &IoControl) -> io::Result<()> {
        let attempts = self
            .work
            .lock()
            .map_err(|_| invalid_data("native switch accounting poisoned"))?
            .attempts;
        let mut state = lock_state(shared)?;
        state.checkpoint_costs.compactor_switches += 1;
        state.checkpoint_costs.last_rollover_attempts = attempts;
        state.checkpoint_costs.maximum_rollover_attempts = state
            .checkpoint_costs
            .maximum_rollover_attempts
            .max(attempts);
        state.native_live_capacity = false;
        shared.ready.notify_all();
        drop(state);
        (control.hook)(Point::AfterNativeSwitchSelection)
    }
}
