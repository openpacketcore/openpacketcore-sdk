//! SDK-owned irreversible submission gates, independent of authentication time.
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};
use tokio::sync::{OwnedRwLockReadGuard, RwLock};

/// A local effect gate is not active, or is irreversibly closing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("scope submission gate closed")]
pub struct ScopeGateError;
const CANDIDATE: u8 = 0;
const ACTIVE: u8 = 1;
const CLOSING: u8 = 2;
pub(super) struct EffectGate {
    phase: AtomicU8,
    inflight: Arc<RwLock<()>>,
    closed: tokio::sync::Mutex<Option<[u8; 32]>>,
}
pub(super) struct CandidateGuard {
    _guard: OwnedRwLockReadGuard<()>,
}
/// An in-flight store or peer-control submission; keep it until submission ends.
#[must_use = "hold this permit through the full store or peer-control submission"]
pub struct ScopeEffectPermit {
    _guard: OwnedRwLockReadGuard<()>,
}
#[derive(Clone)]
pub(super) struct LocalQuiescence {
    fence: [u8; 32],
}
impl LocalQuiescence {
    pub(super) const fn fence_nonce(&self) -> &[u8; 32] {
        &self.fence
    }
}
impl EffectGate {
    pub(super) fn new() -> Self {
        Self {
            phase: AtomicU8::new(CANDIDATE),
            inflight: Arc::new(RwLock::new(())),
            closed: tokio::sync::Mutex::new(None),
        }
    }
    // Only the checked current-boot capability consumer may activate this gate.
    pub(super) async fn activate(&self) -> Result<(), ScopeGateError> {
        let _drain = self.inflight.write().await;
        match self
            .phase
            .compare_exchange(CANDIDATE, ACTIVE, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) | Err(ACTIVE) => Ok(()),
            Err(_) => Err(ScopeGateError),
        }
    }
    pub(super) async fn candidate(&self) -> Result<CandidateGuard, ScopeGateError> {
        if self.phase.load(Ordering::Acquire) != CANDIDATE {
            return Err(ScopeGateError);
        }
        let guard = self.inflight.clone().read_owned().await;
        if self.phase.load(Ordering::Acquire) != CANDIDATE {
            return Err(ScopeGateError);
        }
        Ok(CandidateGuard { _guard: guard })
    }
    pub(super) async fn enter(&self) -> Result<ScopeEffectPermit, ScopeGateError> {
        if self.phase.load(Ordering::Acquire) != ACTIVE {
            return Err(ScopeGateError);
        }
        let guard = self.inflight.clone().read_owned().await;
        if self.phase.load(Ordering::Acquire) != ACTIVE {
            return Err(ScopeGateError);
        }
        Ok(ScopeEffectPermit { _guard: guard })
    }
    pub(super) async fn quiesce(&self) -> Result<LocalQuiescence, ScopeGateError> {
        // Set the refusal first. Cancellation while draining cannot reopen paths.
        self.phase.fetch_max(CLOSING, Ordering::AcqRel);
        let _drain = self.inflight.write().await;
        let mut closed = self.closed.lock().await;
        let fence = match *closed {
            Some(fence) => fence,
            None => {
                let fence = super::boot::random_nonzero().map_err(|_| ScopeGateError)?;
                *closed = Some(fence);
                fence
            }
        };
        Ok(LocalQuiescence { fence })
    }
}
