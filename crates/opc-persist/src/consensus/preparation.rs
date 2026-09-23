//! Local preparation ownership, separate from every deterministic command.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use opc_crypto::{
    ConfigCapacityEvidence, ConfigCapacityProfile, ConfigPreparationPool,
    ConfigPreparationReservation,
};

use crate::audit_authority::AuditAuthorityError;

pub(crate) struct PreparationOwnership {
    reservation: ConfigPreparationReservation,
    evidence: Option<ConfigCapacityEvidence>,
    encoding: AtomicBool,
    submitting: AtomicBool,
}

impl PreparationOwnership {
    pub(crate) fn new(
        reservation: ConfigPreparationReservation,
        evidence: Option<ConfigCapacityEvidence>,
    ) -> Arc<Self> {
        Arc::new(Self {
            reservation,
            evidence,
            encoding: AtomicBool::new(false),
            submitting: AtomicBool::new(false),
        })
    }

    pub(crate) fn belongs_to(
        &self,
        pool: &ConfigPreparationPool,
        profile: ConfigCapacityProfile,
        needs_evidence: bool,
    ) -> bool {
        pool.owns(&self.reservation)
            && (!needs_evidence
                || self
                    .evidence
                    .is_some_and(|evidence| evidence.profile() == profile))
    }

    pub(crate) fn try_encode(self: &Arc<Self>) -> Result<PreparationUse, AuditAuthorityError> {
        self.try_use(PreparationUseKind::Encoding)
    }

    pub(crate) fn try_submit(self: &Arc<Self>) -> Result<PreparationUse, AuditAuthorityError> {
        self.try_use(PreparationUseKind::Submitting)
    }

    fn try_use(
        self: &Arc<Self>,
        kind: PreparationUseKind,
    ) -> Result<PreparationUse, AuditAuthorityError> {
        self.flag(kind)
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        Ok(PreparationUse {
            owner: Arc::clone(self),
            kind,
        })
    }

    fn flag(&self, kind: PreparationUseKind) -> &AtomicBool {
        match kind {
            PreparationUseKind::Encoding => &self.encoding,
            PreparationUseKind::Submitting => &self.submitting,
        }
    }
}

#[derive(Clone, Copy)]
enum PreparationUseKind {
    Encoding,
    Submitting,
}

/// Private guards may be shared by the routing and accepted-work supervisors.
/// The flag and reservation are released only when their last owner finishes.
pub(crate) struct PreparationUse {
    owner: Arc<PreparationOwnership>,
    kind: PreparationUseKind,
}

impl Drop for PreparationUse {
    fn drop(&mut self) {
        self.owner.flag(self.kind).store(false, Ordering::Release);
    }
}

pub(crate) type SubmissionOwnership = Option<Arc<PreparationUse>>;
