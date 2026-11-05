//! Independent post-switch relocation. A parked read/codec unit owns no WAL
//! checkpoint slot. Publication retains the existing revision comparison.

use super::*;
use crate::consensus::native::generation::Relocations;
use crate::consensus::native::prefix::VerifiedPrefix;

pub(super) struct Background {
    source: Arc<VerifiedPrefix>,
    rows: Relocations,
}

impl Background {
    pub(super) fn new(source: Arc<VerifiedPrefix>, rows: Relocations) -> Self {
        Self { source, rows }
    }
}

impl Owner {
    /// Retained work resumes on the install owner's withdrawal notification,
    /// including an empty writer queue. A finished paused unit remains owned.
    pub(in crate::sqlite::consensus::wal) fn background_actionable(&self, state: &State) -> bool {
        !state.native_install_pending
            && state.snapshot.is_none()
            && (state.native_background_ready
                || (self.background_worker.is_none() && !self.background.is_empty()))
    }

    fn record_background_pending(&self, shared: &Arc<Shared>) -> io::Result<()> {
        let pending = self.background_worker.is_some() || !self.background.is_empty();
        let mut state = lock_state(shared)?;
        if state.native_background_pending != pending {
            state.native_background_pending = pending;
            shared.ready.notify_all();
        }
        Ok(())
    }

    /// Poll a ready unit and start at most one detached unit. Neither joining
    /// nor preparing ever happens while holding State. The completion flag and
    /// notification share State with the writer's idle predicate.
    pub(in crate::sqlite::consensus::wal) fn poll_background(
        &mut self,
        shared: &Arc<Shared>,
        disk: &Disk,
        control: &IoControl,
    ) -> io::Result<()> {
        self.record_background_pending(shared)?;
        let (armed, claimed) = {
            let state = lock_state(shared)?;
            (state.snapshot.is_some(), state.native_install_pending)
        };
        if armed {
            self.stop_background()?;
            {
                let mut state = lock_state(shared)?;
                state.native_background_ready = false;
                state.native_background_pending = false;
                shared.ready.notify_all();
            }
            #[cfg(test)]
            (control.hook)(Point::AfterNativeBackgroundPoll)?;
            return Ok(());
        }
        if claimed {
            // An unarmed claim can be withdrawn. Preserve both queued work and
            // a completed unit; only an armed handoff may discard this owner.
            #[cfg(test)]
            (control.hook)(Point::AfterNativeBackgroundPoll)?;
            return Ok(());
        }
        if lock_state(shared)?.native_background_ready {
            let worker = self
                .background_worker
                .take()
                .ok_or_else(|| invalid_data("native background relocation owner missing"))?;
            let mut work = worker
                .join()
                .map_err(|_| io::Error::other("native background relocation panicked"))??;
            let mut state = lock_state(shared)?;
            let held = Instant::now();
            ensure_readable(&state)?;
            let prefix = work.source.identity();
            let selected = disk
                .anchor
                .as_ref()
                .and_then(|a| a.native_prefix().ok())
                .flatten()
                .ok_or_else(|| invalid_data("native background selected prefix missing"))?;
            if selected.file_epoch != prefix.file_epoch
                || selected.binding != prefix.binding
                || selected.checkpoint_epoch < prefix.checkpoint_epoch
                || selected.length < prefix.length
                || state.snapshot.is_some()
                || self
                    .selected
                    .as_ref()
                    .is_some_and(|s| !s.append.current().same_source(&work.source))
            {
                return Err(invalid_data("native background relocation source changed"));
            }
            let retired = work.rows.publish_step_mirrored(
                state
                    .native
                    .as_mut()
                    .ok_or_else(|| invalid_data("native background resident owner missing"))?,
                self.cut.as_mut().map(|cut| &mut cut.capture.storage),
            )?;
            state.native_background_ready = false;
            let elapsed = held.elapsed();
            state.checkpoint_costs.native_owner_publish += elapsed;
            state.checkpoint_costs.native_owner_maximum =
                state.checkpoint_costs.native_owner_maximum.max(elapsed);
            shared.ready.notify_all();
            drop(state);
            drop(retired);
            if !work.rows.is_empty() {
                self.background.push_front(work);
            }
            (control.hook)(Point::AfterNativeBackgroundRelocationPublish)?;
        }
        if self.background_worker.is_none() {
            if let Some(mut work) = self.background.pop_front() {
                let shared = Arc::clone(shared);
                let control = control.clone();
                self.background_worker = Some(
                    std::thread::Builder::new()
                        .name("session-native-relocate".into())
                        .spawn(move || {
                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    work.rows.prepare_step(&|| {
                                        let state = lock_state(&shared)?;
                                        ensure_readable(&state)
                                    })?;
                                    (control.hook)(Point::AfterNativeRelocationStep)?;
                                    Ok(work)
                                }))
                                .unwrap_or_else(|_| {
                                    Err(io::Error::other("native background relocation panicked"))
                                });
                            // Completion must be published even after panic or
                            // poison, so the sole owner always wakes and reaps
                            // the handle before releasing directory ownership.
                            let mut state = match shared.state.lock() {
                                Ok(state) => state,
                                Err(poison) => {
                                    let mut state = poison.into_inner();
                                    application::fence(&mut state);
                                    state.native_background_ready = true;
                                    shared.ready.notify_all();
                                    return Err(io::Error::other(
                                        "native background completion poisoned",
                                    ));
                                }
                            };
                            if result.is_err() {
                                application::fence(&mut state);
                            }
                            state.native_background_ready = true;
                            shared.ready.notify_all();
                            result
                        })?,
                );
            }
        }
        self.record_background_pending(shared)?;
        #[cfg(test)]
        {
            (control.hook)(Point::AfterNativeBackgroundPoll)?;
            if self.background.is_empty() && self.background_worker.is_none() {
                (control.hook)(Point::NativeBackgroundRelocationIdle)?;
            }
        }
        Ok(())
    }

    /// Install and final shutdown relinquish optional relocation before
    /// replacing authority or releasing the directory lock.
    pub(super) fn stop_background(&mut self) -> io::Result<()> {
        if let Some(worker) = self.background_worker.take() {
            drop(
                worker
                    .join()
                    .map_err(|_| io::Error::other("native background relocation panicked"))??,
            );
        }
        self.background.clear();
        Ok(())
    }
}
