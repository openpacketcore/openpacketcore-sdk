//! Atomic, bounded owner-to-worker transfer. This primitive does not select a
//! checkpoint or discard its reconstructing WAL suffix. Worker verification
//! must succeed before a later persistence path can select the captured cut.

use super::*;
use std::sync::Arc;

pub(crate) struct NativeChanges {
    pub(super) business: changes::BusinessChanges,
    pub(super) log: log::CapturedLog,
}

pub(crate) struct SnapshotCapture {
    pub(crate) storage: NativeStorage,
    // Small frontiers and the bounded inline vector root are the only copied
    // values. Every map/tree payload is an immutable shared node or row.
    _memory: crate::consensus::verified_snapshot::VerificationMemory,
}

impl SnapshotCapture {
    /// Application may advance during export. The immutable snapshot keeps
    /// its captured cut, but a different live authority cannot authorize its
    /// return. The WAL adapter separately checks its current running owner.
    pub(crate) fn require_current_authority(&self, current: &NativeStorage) -> io::Result<()> {
        let (identity, members, _) = self.storage.business.require_business_proof()?.context();
        let (current_identity, current_members, _) =
            current.business.require_business_proof()?.context();
        current.log.generation_version(&current.business)?;
        if identity != current_identity
            || members != current_members
            || self.storage.business.roster_root != current.business.roster_root
        {
            return Err(invalid("native snapshot export authority changed"));
        }
        Ok(())
    }
}

impl NativeChanges {
    /// Verification owns its complete target context and never consults the
    /// current NativeStorage. Cancellation leaves this capture reusable; an
    /// integrating worker must retain it or fence, never silently drop a cut.
    pub(crate) fn validate(&self, check: &impl Fn() -> io::Result<()>) -> io::Result<()> {
        check()?;
        if !Arc::ptr_eq(self.business.target_proof(), self.log.business_proof()) {
            return Err(invalid("native captured log and business revisions differ"));
        }
        self.business.validate_captured(check)?;
        self.log.validate_captured(check)?;
        check()
    }
}

impl NativeStorage {
    #[cfg(test)]
    pub(crate) fn cold_counts_for_test(&self) -> [usize; 3] {
        [
            self.business
                .receipts
                .values()
                .filter(|row| row.cold.is_some())
                .count(),
            self.business
                .notifications
                .iter()
                .filter(|row| row.resident().is_err())
                .count(),
            self.log
                .entries
                .values()
                .filter(|row| row.is_cold())
                .count(),
        ]
    }

    pub(crate) fn capture_snapshot(&self) -> io::Result<SnapshotCapture> {
        self.business.require_business_proof()?;
        self.log.generation_version(&self.business)?;
        let memory = crate::consensus::verified_snapshot::VerificationMemory::reserve(
            128 * 1024 + std::mem::size_of::<SnapshotCapture>(),
        )?;
        Ok(SnapshotCapture {
            storage: self.clone(),
            _memory: memory,
        })
    }

    pub(crate) fn begin_changes(&mut self) -> io::Result<()> {
        let business = self.business.prepare_tracking()?;
        self.log.begin_changes(&self.business)?;
        // The log has completed every fallible check before either journal
        // becomes visible. The remaining assignment cannot allocate or fail.
        self.business.changes = Some(business);
        Ok(())
    }

    /// Prepare both transfers before moving either journal. Preflight checks
    /// only exact certificates, bounded frontiers, counts, endpoints and at
    /// most five log witnesses; it never visits historical or dirty rows.
    pub(crate) fn take_changes(&mut self) -> io::Result<super::NativeChanges> {
        let log = self.log.prepare_transfer(&self.business)?;
        let business = self.business.prepare_transfer()?;
        // Both exclusive borrows remain held. These moves are infallible,
        // preserve their resource guards and start journals at this exact cut.
        Ok(NativeChanges {
            business: business.take(),
            log: log.take(),
        })
    }

    pub(crate) fn take_checkpoint_changes(
        &mut self,
        snapshot: Option<crate::sqlite::consensus::CurrentSnapshot>,
    ) -> io::Result<(NativeChanges, Option<changes::SnapshotSelection>)> {
        if let Some(snapshot) = &snapshot {
            self.validate_snapshot(snapshot)?;
        }
        let snapshot = snapshot
            .map(|snapshot| self.business.prepare_snapshot_selection(snapshot))
            .transpose()?;
        let log = self
            .log
            .prepare_checkpoint_transfer(&self.business, snapshot.as_ref())?;
        let business = self
            .business
            .prepare_checkpoint_transfer(snapshot.as_ref())?;
        Ok((
            NativeChanges {
                business: business.take(),
                log: log.take(),
            },
            snapshot,
        ))
    }
}
