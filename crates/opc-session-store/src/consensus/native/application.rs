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
        #[cfg(feature = "test-control")]
        let started = std::time::Instant::now();
        // An ordinary lease/business update can revalidate a retained roster
        // reservation too. Schedule detached evaluation before any hydration,
        // retaining the shared allocation cap and every owner/cancellation
        // check. Empty non-roster work bypasses it.
        let roster_work = !self.state.roster.rows.is_empty()
            || entries.iter().any(|entry| {
                let EntryPayload::Normal(command) = &entry.payload else {
                    return false;
                };
                let intent = match &command.intent {
                    SessionMutationIntent::Authorized { mutation, .. } => mutation.as_ref(),
                    intent => intent,
                };
                matches!(
                    intent,
                    SessionMutationIntent::RosterAdmission(_)
                        | SessionMutationIntent::RosterAdmissionV2(_)
                        | SessionMutationIntent::RosterTerminal(_)
                        | SessionMutationIntent::RosterTerminalV2(_)
                )
            });
        let roster_preparation = roster_work
            .then(|| scratch::RosterPreparation::acquire(check))
            .transpose()?;
        #[cfg(feature = "test-control")]
        let admitted = std::time::Instant::now();
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
        #[cfg(feature = "test-control")]
        let evaluated = std::time::Instant::now();
        // Store::finish_with_changes has destroyed evaluator hydrations.
        // No admission permit is held while waiting for the next phase.
        drop(roster_preparation);
        let _roster_publication = roster_work
            .then(|| scratch::RosterPreparation::publication(check))
            .transpose()?;
        let publication = changes::Publication::prepare_checked(delta, check)?;
        check()?;
        #[cfg(feature = "test-control")]
        if roster_work {
            eprintln!(
                "native_roster_preparation entries={} wait_ms={} evaluation_ms={} publication_ms={}",
                entries.len(), admitted.duration_since(started).as_millis(),
                evaluated.duration_since(admitted).as_millis(), evaluated.elapsed().as_millis(),
            );
        }
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
