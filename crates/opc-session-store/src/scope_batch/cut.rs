//! A single backend observation after the full current-configuration barrier.

use super::*;
use crate::scope_authority::ScopeAuthorityView;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ScopeBatchReadCut {
    Uninitialized,
    Initialized {
        authority: Box<ScopeState>,
        checkpoint: Box<ScopeBatchCheckpoint>,
    },
}

impl ScopeBatchReadCut {
    pub(crate) fn from_records(
        scope: &ScopeId,
        legacy: bool,
        authority: Option<([u8; 32], crate::consensus::SessionConsensusResponse)>,
        row: Option<crate::scope_storage::ScopeRow>,
    ) -> Result<Self, ScopeBatchError> {
        if legacy {
            return Err(ScopeBatchError::FormatMismatch);
        }
        let checkpoint = match row {
            None => None,
            Some(crate::scope_storage::ScopeRow::Batch(checkpoint)) => Some(*checkpoint),
            _ => return Err(ScopeBatchError::FormatMismatch),
        };
        Self::new(
            scope,
            authority
                .map(|authority| crate::scope_authority::checkpoint_state(scope, Some(authority)))
                .transpose()?,
            checkpoint,
        )
    }

    pub(crate) fn new(
        scope: &ScopeId,
        authority: Option<ScopeState>,
        checkpoint: Option<ScopeBatchCheckpoint>,
    ) -> Result<Self, ScopeBatchError> {
        match (authority, checkpoint) {
            (None, None) => Ok(Self::Uninitialized),
            (Some(authority), Some(checkpoint)) if &checkpoint.scope == scope => {
                checkpoint.validate_authority(&authority)?;
                Ok(Self::Initialized {
                    authority: Box::new(authority),
                    checkpoint: Box::new(checkpoint),
                })
            }
            _ => Err(ScopeBatchError::FormatMismatch),
        }
    }

    pub(crate) fn lookup(
        &self,
        attempt: &ScopeBatchAttempt,
    ) -> Result<ScopeBatchLookup, ScopeBatchError> {
        attempt.validate()?;
        match self {
            Self::Uninitialized => Ok(ScopeBatchLookup::NotRecorded),
            Self::Initialized {
                authority,
                checkpoint,
            } => checkpoint.lookup(attempt, permanently_fenced(&authority.view, &attempt.stamp)),
        }
    }

    pub(crate) fn reopen(&self) -> ScopeBatchReopen {
        match self {
            Self::Uninitialized => ScopeBatchReopen::Uninitialized,
            Self::Initialized {
                authority,
                checkpoint,
            } => ScopeBatchReopen::Initialized(Box::new(ScopeBatchReopenState {
                authority: authority.view.clone(),
                revision: checkpoint.revision,
                birth_floor: checkpoint.birth_floor,
                counters: checkpoint.counters,
                lanes: std::array::from_fn(|index| {
                    let lane = &checkpoint.lanes[index];
                    ScopeBatchLaneView {
                        sequence: lane.sequence,
                        discarded_through: lane.floor,
                        receipt: lane.receipt.clone(),
                    }
                }),
            })),
        }
    }
}

fn permanently_fenced(authority: &ScopeAuthorityView, stamp: &ScopeAuthorityStamp) -> bool {
    // Future or malformed combinations never gain a negative result merely
    // because their complete stamp is not currently active.
    if stamp.incarnation().get() <= authority.retired_through() {
        return true;
    }
    let Some(current) = authority.stamp() else {
        return false;
    };
    if stamp.incarnation() < current.incarnation() {
        return true;
    }
    stamp.incarnation() == current.incarnation()
        && stamp.revision() <= authority.revision()
        && stamp.execution().admission_generation() <= authority.admission_generation_floor()
        && (!authority.is_active() || stamp != current)
}

impl ScopeBatchCheckpoint {
    pub(crate) fn validate_authority(&self, authority: &ScopeState) -> Result<(), ScopeBatchError> {
        authority
            .validate()
            .map_err(|_| ScopeBatchError::FormatMismatch)?;
        self.validate_authority_view(&authority.view)
    }

    fn validate_authority_view(
        &self,
        authority: &ScopeAuthorityView,
    ) -> Result<(), ScopeBatchError> {
        self.validate_stored()?;
        let current = authority.stamp().ok_or(ScopeBatchError::FormatMismatch)?;
        current
            .validate()
            .map_err(|_| ScopeBatchError::FormatMismatch)?;
        if authority.scope() != &self.scope
            || authority.scope().slot() == &[0; 32]
            || !(1..=COUNTER_MAX).contains(&authority.revision())
            || authority.retired_through() >= current.incarnation().get()
            || authority.admission_generation_floor() != current.execution().admission_generation()
            || current.scope() != authority.scope()
            || current.revision() != authority.revision()
            || authority.is_active() == authority.closed_evidence().is_some()
            || authority
                .closed_evidence()
                .is_some_and(|evidence| evidence.digest() == &[0; 32])
        {
            return Err(ScopeBatchError::FormatMismatch);
        }
        for receipt in self.lanes.iter().filter_map(|lane| lane.receipt.as_ref()) {
            let stamp = &receipt.attempt.stamp;
            if stamp.incarnation() > current.incarnation()
                || stamp.revision() > authority.revision()
                || stamp.execution().admission_generation() > authority.admission_generation_floor()
                || (stamp.revision() == authority.revision()
                    && (!authority.is_active() || stamp != current))
                || (stamp.execution().admission_generation()
                    == authority.admission_generation_floor()
                    && (stamp.execution() != current.execution()
                        || stamp.incarnation() != current.incarnation()))
            {
                return Err(ScopeBatchError::FormatMismatch);
            }
        }
        Ok(())
    }
}

/// A read-only reopening observation. Neither variant issues an effect capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeBatchReopen {
    /// Both the authority record and required ledger are absent in the same cut.
    /// This is not an orphan scan and does not authorize initial admission.
    Uninitialized,
    /// Authority claims, stable floors and all lane receipts from one cut.
    Initialized(Box<ScopeBatchReopenState>),
}

impl ScopeBatchReopen {
    pub(super) fn validate(&self) -> Result<(), ScopeBatchError> {
        match self {
            Self::Uninitialized => Ok(()),
            Self::Initialized(view) => view.checkpoint().validate_authority_view(&view.authority),
        }
    }

    /// Resolve an exact attempt using this single authenticated observation.
    /// Decoded bytes alone are not a store proof or an effect capability. Only a
    /// trusted port's full-barrier response may inform supervised resolution.
    pub fn lookup(&self, attempt: &ScopeBatchAttempt) -> Result<ScopeBatchLookup, ScopeBatchError> {
        self.validate()?;
        attempt.validate()?;
        match self {
            Self::Uninitialized => Ok(ScopeBatchLookup::NotRecorded),
            Self::Initialized(view) => view.checkpoint().lookup(
                attempt,
                permanently_fenced(&view.authority, attempt.stamp()),
            ),
        }
    }

    pub(super) fn check_stamp(
        &self,
        stamp: &ScopeAuthorityStamp,
    ) -> Result<&ScopeBatchReopenState, ScopeBatchError> {
        self.validate()?;
        stamp.validate()?;
        let Self::Initialized(view) = self else {
            return Err(ScopeBatchError::FormatMismatch);
        };
        if view.authority.scope() != stamp.scope() {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        if stamp.incarnation().get() <= view.authority.retired_through() {
            return Err(ScopeAuthorityError::Retired.into());
        }
        if !view.authority.is_active() || view.authority.stamp() != Some(stamp) {
            return Err(ScopeAuthorityError::StaleAuthority.into());
        }
        Ok(view)
    }
}

/// Fixed-cardinality state for reconstructing a coordinator after restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeBatchReopenState {
    authority: ScopeAuthorityView,
    revision: u64,
    birth_floor: u64,
    counters: [u64; SCOPE_COUNTERS],
    lanes: [ScopeBatchLaneView; SCOPE_BATCH_LANES],
}

impl ScopeBatchReopenState {
    fn checkpoint(&self) -> ScopeBatchCheckpoint {
        ScopeBatchCheckpoint {
            scope: self.authority.scope().clone(),
            revision: self.revision,
            birth_floor: self.birth_floor,
            counters: self.counters,
            lanes: std::array::from_fn(|index| {
                let lane = &self.lanes[index];
                ScopeBatchLaneCheckpoint {
                    sequence: lane.sequence,
                    floor: lane.discarded_through,
                    receipt: lane.receipt.clone(),
                }
            }),
        }
    }
    /// Exact authority claims observed alongside the lane ledger.
    pub const fn authority(&self) -> &ScopeAuthorityView {
        &self.authority
    }
    /// Stable-scope batch revision after every observed terminal transition.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Highest birth ever allocated; deletion and incarnation changes cannot reset it.
    pub const fn birth_floor(&self) -> u64 {
        self.birth_floor
    }
    /// All sixteen monotone stable-scope counters.
    pub const fn counters(&self) -> &[u64; SCOPE_COUNTERS] {
        &self.counters
    }
    /// The complete fixed lane array from this one observation.
    pub const fn lanes(&self) -> &[ScopeBatchLaneView; SCOPE_BATCH_LANES] {
        &self.lanes
    }
}

/// One read-only terminal frontier and its immutable retained receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeBatchLaneView {
    sequence: u64,
    discarded_through: u64,
    receipt: Option<ScopeBatchReceipt>,
}

impl ScopeBatchLaneView {
    /// Last consumed terminal sequence, zero before first use.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Historical sequences whose results may have been discarded.
    pub const fn discarded_through(&self) -> u64 {
        self.discarded_through
    }
    /// Sole retained terminal receipt, absent only for an unused lane.
    pub const fn receipt(&self) -> Option<&ScopeBatchReceipt> {
        self.receipt.as_ref()
    }
}
