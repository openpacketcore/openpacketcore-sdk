//! Admission transitions for the all-member recovery protocol. Disk selection,
//! Raft responses and authority checks remain owned by the store/WAL adapters.

use super::*;
#[cfg(target_os = "linux")]
use crate::consensus::recovery_types::{Capability, Prepared, Ready, Round, Selection};
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;

#[cfg(target_os = "linux")]
pub(in crate::consensus) struct Coordinator {
    pub round: Round,
    pub selection: Option<Selection>,
    pub boundary: Option<LogId<SessionConsensusNodeId>>,
    pub ready: BTreeMap<SessionConsensusNodeId, Ready>,
    pub restart: bool,
}

#[cfg(target_os = "linux")]
type BoundaryCompletion =
    tokio::sync::watch::Receiver<Option<Result<LogId<SessionConsensusNodeId>, ()>>>;

#[cfg(target_os = "linux")]
pub(in crate::consensus) struct LocalRecovery {
    pub round: Round,
    pub prepared: Option<Prepared>,
    pub selection: Option<Selection>,
    pub proposal: Option<BoundaryCompletion>,
}

impl PersistenceProtocol {
    #[cfg(target_os = "linux")]
    pub(in crate::consensus) fn recovery_restriction(&self, reason: SessionAsyncRecoveryState) {
        let value = match reason {
            SessionAsyncRecoveryState::AwaitingRecoveryParticipants => 3,
            SessionAsyncRecoveryState::RetainedMembershipRequired => 4,
            SessionAsyncRecoveryState::RetainedHistoryConflict => 5,
            SessionAsyncRecoveryState::AuthorityRangeExhausted => 6,
            _ => return,
        };
        if value == 3 {
            // A transport retry cannot hide locally established unsupported
            // authority or a retained-state repair requirement.
            let _ =
                self.recovery_limit
                    .compare_exchange(0, value, Ordering::AcqRel, Ordering::Acquire);
        } else {
            self.recovery_limit.store(value, Ordering::Release);
        }
    }
    #[cfg(target_os = "linux")]
    pub(in crate::consensus) fn boot(&self) -> SessionConsensusRequestId {
        self.incarnation
    }

    pub(in crate::consensus) fn operation_stamp(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    #[cfg(target_os = "linux")]
    pub(in crate::consensus) fn recovery_limit(&self, capability: Capability) {
        let value = match capability {
            // A status read proves capability, not recovery progress. Keep
            // an established repair reason until an actual new preparation.
            Capability::Reserved => return,
            Capability::Legacy => 1,
            Capability::ProtectedAuthority => 2,
        };
        let _ = self
            .recovery_limit
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < 4).then_some(value)
            });
    }

    #[cfg(target_os = "linux")]
    pub(in crate::consensus) async fn is_reforming(
        &self,
        deadline: Instant,
    ) -> Result<bool, SessionConsensusPeerError> {
        let state = tokio::time::timeout_at(deadline, self.admission.read())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        Ok(matches!(
            *state,
            Admission::Preparing { .. } | Admission::Reforming { .. }
        ))
    }

    pub(in crate::consensus) async fn submission_before(
        &self,
        stamp: u64,
        deadline: Instant,
    ) -> Result<EngineAdmission, SessionConsensusPeerError> {
        let admission = self.engine_before(deadline).await?;
        if !matches!(*admission.guard, Admission::Active) || stamp != self.operation_stamp() {
            return Err(SessionConsensusPeerError::Rejected);
        }
        Ok(admission)
    }

    #[cfg(target_os = "linux")]
    pub(in crate::consensus) async fn prepare_recovery_before<F, Fut>(
        &self,
        plan: [u8; 32],
        era: u64,
        deadline: Instant,
        prepare: F,
    ) -> Result<(), SessionConsensusPeerError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), SessionConsensusPeerError>>,
    {
        let mut state = tokio::time::timeout_at(deadline, self.admission.write())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        match &*state {
            Admission::Preparing {
                plan: prior,
                era: prior_era,
            } if *prior == plan && *prior_era == era => {}
            Admission::Preparing { era: prior, .. } | Admission::Reforming { era: prior, .. }
                if *prior >= era =>
            {
                return Err(SessionConsensusPeerError::Rejected);
            }
            _ => {
                let generation = self
                    .operation_stamp()
                    .checked_add(1)
                    .ok_or(SessionConsensusPeerError::Rejected)?;
                self.active.store(false, Ordering::Release);
                self.generation.store(generation, Ordering::Release);
                self.recovery_limit.store(0, Ordering::Release);
                *state = Admission::Preparing { plan, era };
            }
        }
        // The accepted caller retains the exclusive fence even if its remote
        // response is cancelled. The preparation owns every accepted disk op.
        prepare().await
    }

    #[cfg(target_os = "linux")]
    pub(in crate::consensus) async fn select_recovery_before(
        &self,
        plan: [u8; 32],
        era: u64,
        vote: Vote<SessionConsensusNodeId>,
        deadline: Instant,
    ) -> Result<(), SessionConsensusPeerError> {
        let mut state = tokio::time::timeout_at(deadline, self.admission.write())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        match &*state {
            Admission::Preparing {
                plan: prior,
                era: prior_era,
            } if *prior == plan && *prior_era == era => {
                *state = Admission::Reforming {
                    plan,
                    era,
                    vote,
                    matched: std::sync::Mutex::new(None),
                };
                Ok(())
            }
            Admission::Reforming {
                plan: prior,
                era: prior_era,
                vote: prior_vote,
                ..
            } if *prior == plan && *prior_era == era && *prior_vote == vote => Ok(()),
            _ => Err(SessionConsensusPeerError::Rejected),
        }
    }

    #[cfg(target_os = "linux")]
    pub(in crate::consensus) async fn activate_recovery_before<F, Fut>(
        &self,
        plan: [u8; 32],
        era: u64,
        deadline: Instant,
        check: F,
    ) -> Result<bool, SessionConsensusPeerError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let mut state = tokio::time::timeout_at(deadline, self.admission.write())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        if !matches!(&*state, Admission::Reforming { plan: current, era: current_era, .. }
            if *current == plan && *current_era == era)
        {
            return Err(SessionConsensusPeerError::Rejected);
        }
        if !tokio::time::timeout_at(deadline, check())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?
        {
            return Ok(false);
        }
        *state = Admission::Active;
        self.active.store(true, Ordering::Release);
        self.progress.notify_waiters();
        Ok(true)
    }
}

impl EngineAdmission {
    #[cfg(target_os = "linux")]
    pub(in crate::consensus) fn recovery_matches(&self, plan: [u8; 32], era: u64) -> bool {
        matches!(&*self.guard, Admission::Reforming { plan: current, era: current_era, .. }
            if *current == plan && *current_era == era)
    }

    #[cfg(target_os = "linux")]
    pub(in crate::consensus) fn recovery_matched(
        &self,
        boundary: LogId<SessionConsensusNodeId>,
    ) -> bool {
        match &*self.guard {
            Admission::Reforming { matched, .. } => matched
                .lock()
                .is_ok_and(|matched| matched.is_some_and(|matched| covers(matched, boundary))),
            _ => false,
        }
    }

    #[cfg(target_os = "linux")]
    pub(in crate::consensus) fn permits_outgoing(
        &self,
        family: SessionConsensusRpcFamily,
        payload: &[u8],
    ) -> bool {
        if matches!(*self.guard, Admission::Active) {
            return true;
        }
        if !matches!(*self.guard, Admission::Reforming { .. }) {
            return false;
        }
        match family {
            SessionConsensusRpcFamily::Vote => {
                opc_consensus::decode_bounded(payload).is_ok_and(|rpc| self.permits_vote(&rpc))
            }
            SessionConsensusRpcFamily::AppendEntries => {
                opc_consensus::decode_bounded(payload).is_ok_and(|rpc| self.permits_append(&rpc))
            }
            SessionConsensusRpcFamily::InstallSnapshot => {
                opc_consensus::decode_bounded(payload).is_ok_and(|rpc| self.permits_snapshot(&rpc))
            }
            _ => false,
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl EngineAdmission {
    pub(in crate::consensus) fn permits_outgoing(
        &self,
        _family: SessionConsensusRpcFamily,
        _payload: &[u8],
    ) -> bool {
        matches!(*self.guard, Admission::Active)
    }
}
