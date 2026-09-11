//! Mode-bound transport and the cold asynchronous voter admission fence.
//!
//! A reopened volatile voter cannot participate in Raft until an already-live
//! quorum has committed a new nonce-bound entry without it. Only that leader's
//! term may then repair it. A successful matching AppendEntries through the
//! new entry, local application, and the ordinary exact authority checks must
//! all complete before votes or elections resume. No persisted generation,
//! cached match index, or heartbeat alone supplies that proof.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use opc_consensus::engine::raft::{AppendEntriesRequest, InstallSnapshotRequest};
use opc_consensus::engine::{LogId, Vote};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify, OwnedRwLockReadGuard, RwLock, Semaphore};
use tokio::time::Instant;

use super::{
    SessionAsyncRecoveryState, SessionConsensusIdentity, SessionConsensusNodeId,
    SessionConsensusPeerError, SessionConsensusRequestId, SessionConsensusRpcFamily,
    SessionPersistenceMode, SessionRaftTypeConfig,
};

// Eleven continuation bytes cannot encode a Postcard u64 or enum tag. Older
// durable engine/forward handlers therefore reject this prefix too. The
// entire prefix consumes the existing family payload budget.
const ASYNC_WIRE: &[u8] = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xffOPC-ASYNC-1\0";
pub(super) const COLD_BARRIER_WIRE: &[u8; 22] =
    b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xffOPC-COLD-1\0";
pub(super) const COLD_REPAIR_WIRE: &[u8; 24] =
    b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xffOPC-REPAIR-1\0";

pub(super) fn wrap_payload(
    mode: SessionPersistenceMode,
    payload: Vec<u8>,
    limit: usize,
) -> Result<Vec<u8>, SessionConsensusPeerError> {
    let overhead = if mode == SessionPersistenceMode::Async {
        ASYNC_WIRE.len()
    } else {
        0
    };
    if payload
        .len()
        .checked_add(overhead)
        .is_none_or(|len| len > limit)
    {
        return Err(SessionConsensusPeerError::Protocol);
    }
    if mode == SessionPersistenceMode::Durable {
        return Ok(payload);
    }
    let mut tagged = Vec::with_capacity(payload.len() + overhead);
    tagged.extend_from_slice(ASYNC_WIRE);
    tagged.extend_from_slice(&payload);
    Ok(tagged)
}

pub(super) fn unwrap_payload(
    mode: SessionPersistenceMode,
    payload: &[u8],
) -> Result<&[u8], SessionConsensusPeerError> {
    match (mode, payload.strip_prefix(ASYNC_WIRE)) {
        (SessionPersistenceMode::Durable, None) => Ok(payload),
        (SessionPersistenceMode::Async, Some(inner)) => Ok(inner),
        _ => Err(SessionConsensusPeerError::ScopeMismatch),
    }
}

pub(super) fn unwrap_owned_payload(
    mode: SessionPersistenceMode,
    mut payload: Vec<u8>,
) -> Result<Vec<u8>, SessionConsensusPeerError> {
    let prefix = payload.len() - unwrap_payload(mode, &payload)?.len();
    if prefix != 0 {
        payload.drain(..prefix);
    }
    Ok(payload)
}

pub(super) fn wrap_response(
    mode: SessionPersistenceMode,
    response: super::SessionConsensusWireResponse,
) -> super::SessionConsensusWireResponse {
    super::SessionConsensusWireResponse {
        result: response.result.and_then(|payload| {
            wrap_payload(
                mode,
                payload,
                opc_consensus::CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
            )
        }),
    }
}

pub(super) fn payload_fits(
    mode: SessionPersistenceMode,
    family: SessionConsensusRpcFamily,
    bytes: usize,
) -> bool {
    let overhead = if mode == SessionPersistenceMode::Async {
        ASYNC_WIRE.len()
    } else {
        0
    };
    bytes
        .checked_add(overhead)
        .is_some_and(|len| len <= family.max_request_payload_bytes())
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ColdBarrierRequest {
    tag: [u8; 22],
    pub incarnation: SessionConsensusRequestId,
    pub attempt: u64,
    pub nonce: SessionConsensusRequestId,
}

impl ColdBarrierRequest {
    fn new(incarnation: SessionConsensusRequestId, attempt: u64) -> Self {
        Self {
            tag: *COLD_BARRIER_WIRE,
            incarnation,
            attempt,
            nonce: SessionConsensusRequestId::new(),
        }
    }

    pub(super) fn is_valid(&self) -> bool {
        self.tag == *COLD_BARRIER_WIRE && self.attempt != 0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ColdQuorumCut {
    pub identity: SessionConsensusIdentity,
    pub request: ColdBarrierRequest,
    pub requester: SessionConsensusNodeId,
    pub voters: [u8; 32],
    pub membership: Option<LogId<SessionConsensusNodeId>>,
    pub vote: Vote<SessionConsensusNodeId>,
    pub barrier: LogId<SessionConsensusNodeId>,
    // Scheduling hint only: never substitutes for the fresh quorum cut,
    // real matching append, or exact applied-state admission checks.
    pub remembered_match: Option<LogId<SessionConsensusNodeId>>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct ColdRepairRequest {
    tag: [u8; 24],
    pub cut: ColdQuorumCut,
}

impl ColdRepairRequest {
    pub(super) fn new(cut: ColdQuorumCut) -> Self {
        Self {
            tag: *COLD_REPAIR_WIRE,
            cut,
        }
    }

    pub(super) fn is_valid(&self) -> bool {
        self.tag == *COLD_REPAIR_WIRE && self.cut.request.is_valid()
    }
}

enum Admission {
    Active,
    Quarantined {
        request: Option<ColdBarrierRequest>,
    },
    CatchingUp {
        cut: Box<ColdQuorumCut>,
        confirmed: AtomicBool,
        repair_needed: AtomicBool,
    },
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct ActivationHoldForTest {
    pub entered: Notify,
    pub release: Notify,
}

#[derive(Clone)]
pub(crate) struct PersistenceProtocol {
    mode: SessionPersistenceMode,
    incarnation: SessionConsensusRequestId,
    generation: Arc<std::sync::atomic::AtomicU64>,
    active: Arc<AtomicBool>,
    admission: Arc<RwLock<Admission>>,
    pub recovery_attempt: Arc<Mutex<()>>,
    pub progress: Arc<Notify>,
    /// Bound cancellation-safe cold RPC supervisors. The original engine
    /// request/response remains intact; no synthetic acknowledgement is made.
    pub cold_rpc_admission: Arc<Semaphore>,
    #[cfg(test)]
    activation_hold: Arc<std::sync::Mutex<Option<Arc<ActivationHoldForTest>>>>,
}

impl Default for PersistenceProtocol {
    fn default() -> Self {
        Self::new(SessionPersistenceMode::Durable, false)
    }
}

impl PersistenceProtocol {
    pub(super) fn new(mode: SessionPersistenceMode, reopened: bool) -> Self {
        let active = mode == SessionPersistenceMode::Durable || !reopened;
        Self {
            mode,
            incarnation: SessionConsensusRequestId::new(),
            generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            active: Arc::new(AtomicBool::new(active)),
            admission: Arc::new(RwLock::new(if active {
                Admission::Active
            } else {
                Admission::Quarantined { request: None }
            })),
            recovery_attempt: Arc::new(Mutex::new(())),
            progress: Arc::new(Notify::new()),
            cold_rpc_admission: Arc::new(Semaphore::new(16)),
            #[cfg(test)]
            activation_hold: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    pub(super) fn mode(&self) -> SessionPersistenceMode {
        self.mode
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn hold_activation_for_test(&self) -> Arc<ActivationHoldForTest> {
        let hold = Arc::new(ActivationHoldForTest::default());
        assert!(self
            .activation_hold
            .lock()
            .expect("activation test hold")
            .replace(Arc::clone(&hold))
            .is_none());
        hold
    }

    pub(super) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub(super) fn recovery_state(&self) -> Option<SessionAsyncRecoveryState> {
        if self.mode == SessionPersistenceMode::Durable {
            return None;
        }
        if self.is_active() {
            return Some(SessionAsyncRecoveryState::Active);
        }
        Some(match self.admission.try_read().as_deref() {
            Ok(Admission::CatchingUp { .. }) => SessionAsyncRecoveryState::CatchingUp,
            _ => SessionAsyncRecoveryState::AwaitingLiveQuorum,
        })
    }

    pub(super) async fn engine_before(
        &self,
        deadline: Instant,
    ) -> Result<EngineAdmission, SessionConsensusPeerError> {
        let guard = tokio::time::timeout_at(deadline, Arc::clone(&self.admission).read_owned())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        Ok(EngineAdmission {
            guard,
            progress: Arc::clone(&self.progress),
        })
    }

    // Drain every engine call admitted under an earlier cut before creating
    // the next nonce. A cancelled proof request leaves this fence closed.
    pub(super) async fn quarantine_before(
        &self,
        deadline: Instant,
    ) -> Result<ColdBarrierRequest, SessionConsensusPeerError> {
        let mut state = tokio::time::timeout_at(deadline, self.admission.write())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        self.active.store(false, Ordering::Release);
        *state = Admission::Quarantined { request: None };
        let attempt = self
            .generation
            .load(Ordering::Relaxed)
            .checked_add(1)
            .ok_or(SessionConsensusPeerError::Rejected)?;
        self.generation.store(attempt, Ordering::Relaxed);
        let request = ColdBarrierRequest::new(self.incarnation, attempt);
        *state = Admission::Quarantined {
            request: Some(request),
        };
        Ok(request)
    }

    pub(super) async fn accept_cut_before(
        &self,
        cut: ColdQuorumCut,
        deadline: Instant,
    ) -> Result<(), SessionConsensusPeerError> {
        let mut state = tokio::time::timeout_at(deadline, self.admission.write())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        if !matches!(*state, Admission::Quarantined { request: Some(request) } if request == cut.request)
            || self.mode != SessionPersistenceMode::Async
        {
            return Err(SessionConsensusPeerError::Rejected);
        }
        *state = Admission::CatchingUp {
            cut: Box::new(cut),
            confirmed: AtomicBool::new(false),
            repair_needed: AtomicBool::new(false),
        };
        Ok(())
    }

    pub(super) async fn take_repair_before(
        &self,
        deadline: Instant,
    ) -> Result<Option<ColdQuorumCut>, SessionConsensusPeerError> {
        let state = tokio::time::timeout_at(deadline, self.admission.read())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        Ok(match &*state {
            Admission::CatchingUp {
                cut, repair_needed, ..
            } if repair_needed.swap(false, Ordering::AcqRel) => Some(**cut),
            _ => None,
        })
    }

    pub(super) async fn activate_before<F, Fut>(
        &self,
        deadline: Instant,
        check: F,
    ) -> Result<bool, SessionConsensusPeerError>
    where
        F: FnOnce(ColdQuorumCut) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let mut state = tokio::time::timeout_at(deadline, self.admission.write())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        let Admission::CatchingUp { cut, confirmed, .. } = &*state else {
            return Ok(matches!(*state, Admission::Active));
        };
        if !confirmed.load(Ordering::Acquire) {
            return Ok(false);
        }
        // The exact attempt remains exclusively held through scope/local
        // application validation and publication. All earlier accepted cold
        // RPCs retain their read guard through definitive engine completion.
        if !tokio::time::timeout_at(deadline, check(**cut))
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?
        {
            return Ok(false);
        }
        #[cfg(test)]
        let hold = self
            .activation_hold
            .lock()
            .expect("activation test hold")
            .take();
        #[cfg(test)]
        if let Some(hold) = hold {
            hold.entered.notify_one();
            tokio::time::timeout_at(deadline, hold.release.notified())
                .await
                .map_err(|_| SessionConsensusPeerError::Timeout)?;
        }
        *state = Admission::Active;
        self.active.store(true, Ordering::Release);
        Ok(true)
    }
}

pub(super) fn covers(
    actual: LogId<SessionConsensusNodeId>,
    barrier: LogId<SessionConsensusNodeId>,
) -> bool {
    actual.leader_id == barrier.leader_id && actual.index >= barrier.index
}

pub(super) struct EngineAdmission {
    guard: OwnedRwLockReadGuard<Admission>,
    progress: Arc<Notify>,
}

impl EngineAdmission {
    // A live leader can remember matches acknowledged by this voter's old
    // volatile incarnation. Returning a regressed Conflict to Openraft would
    // violate its durable-follower contract. Keep it unavailable while the
    // exact cut's leader restores a real snapshot through the normal engine
    // install path. Never manufacture a successful append or a higher vote.
    pub(super) fn request_cold_repair(&self) -> bool {
        if let Admission::CatchingUp { repair_needed, .. } = &*self.guard {
            repair_needed.store(true, Ordering::Release);
            self.progress.notify_one();
            true
        } else {
            false
        }
    }

    pub(super) fn permits_vote(&self) -> bool {
        matches!(*self.guard, Admission::Active)
    }

    pub(super) fn permits_append(&self, rpc: &AppendEntriesRequest<SessionRaftTypeConfig>) -> bool {
        match &*self.guard {
            Admission::Active => true,
            Admission::Quarantined { .. } => false,
            Admission::CatchingUp { cut, .. } => {
                rpc.vote == cut.vote
                    && rpc
                        .leader_commit
                        .is_some_and(|committed| covers(committed, cut.barrier))
            }
        }
    }

    pub(super) fn permits_snapshot(
        &self,
        rpc: &InstallSnapshotRequest<SessionRaftTypeConfig>,
    ) -> bool {
        match &*self.guard {
            Admission::Active => true,
            Admission::Quarantined { .. } => false,
            Admission::CatchingUp { cut, .. } => {
                rpc.vote == cut.vote
                    && *rpc.meta.last_membership.log_id() == cut.membership
                    && rpc.meta.last_log_id.is_some_and(|last| {
                        last.index < cut.barrier.index || covers(last, cut.barrier)
                    })
            }
        }
    }

    // Called only after a real successful AppendEntries from the permitted
    // leader. Snapshot metadata alone is never the activation witness: after
    // snapshot catch-up the leader must still match a prefix through the cut.
    pub(super) fn confirm_append(&self, matched: Option<LogId<SessionConsensusNodeId>>) {
        if let Admission::CatchingUp { cut, confirmed, .. } = &*self.guard {
            if matched.is_some_and(|matched| covers(matched, cut.barrier))
                && !confirmed.swap(true, Ordering::AcqRel)
            {
                self.progress.notify_one();
            }
        }
    }
}
