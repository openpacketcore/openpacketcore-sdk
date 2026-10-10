//! Reserved class/role/peer proof capacity, separate from dispatch scheduling.
use super::wire::Class;
use opc_types::SpiffeId;
use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// Concurrent proof budgets, never a count of sessions or admitted boots.
#[derive(Clone, Copy, Debug)]
pub struct ProofBudgets {
    /// Controller exchanges per class.
    pub controller: usize,
    /// Candidate exchanges per class.
    pub candidate: usize,
    /// Unproven worker/observer exchanges per class.
    pub unproven_worker: usize,
    /// Exchanges reserved for connections proving the committed current boot.
    pub current_worker: usize,
    /// Independent allowance per principal, scope, class and share.
    pub per_peer: usize,
}
impl Default for ProofBudgets {
    fn default() -> Self {
        Self {
            controller: 8,
            candidate: 8,
            unproven_worker: 4,
            current_worker: 4,
            per_peer: 2,
        }
    }
}
impl ProofBudgets {
    /// Total simultaneously reserved exchanges across five class buckets.
    pub fn total(self) -> Result<usize, ProofPoolError> {
        let rows = [
            self.controller,
            self.candidate,
            self.unproven_worker,
            self.current_worker,
        ];
        if self.per_peer == 0 || rows.contains(&0) {
            return Err(ProofPoolError::Invalid);
        }
        let total = rows
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .and_then(|sum| sum.checked_mul(5))
            .ok_or(ProofPoolError::Invalid)?;
        if total > 128 || self.per_peer > 128 {
            return Err(ProofPoolError::Invalid);
        }
        Ok(total)
    }
}
/// Capacity waits; only invalid setup, explicit shutdown or an attempt ends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProofPoolError {
    /// Missing reserved capacity or a total above the protocol bound.
    #[error("invalid scope proof budgets")]
    Invalid,
    /// Explicit endpoint shutdown.
    #[error("scope proof pools closed")]
    Closed,
    /// A dispatched exchange reached its bounded monotonic deadline.
    #[error("scope proof deadline")]
    Deadline,
    /// OS challenge randomness is unavailable.
    #[error("scope challenge entropy unavailable")]
    EntropyUnavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProofShare {
    Controller,
    Candidate,
    WorkerUnproven,
    WorkerCurrent,
}
impl ProofShare {
    const fn index(self) -> usize {
        match self {
            Self::Controller => 0,
            Self::Candidate => 1,
            Self::WorkerUnproven => 2,
            Self::WorkerCurrent => 3,
        }
    }
}

type PrincipalScope = (SpiffeId, [u8; 32]);
struct Bucket {
    #[cfg(test)]
    capacity: usize,
    #[cfg(test)]
    waiting: std::sync::atomic::AtomicUsize,
    global: Arc<Semaphore>,
    peers: Mutex<HashMap<PrincipalScope, Weak<Semaphore>>>,
}
pub(super) struct ProofPools {
    buckets: [[Bucket; 4]; 5],
    per_peer: usize,
}
impl ProofPools {
    pub(super) fn new(budgets: ProofBudgets) -> Result<Self, ProofPoolError> {
        budgets.total()?;
        let limits = [
            budgets.controller,
            budgets.candidate,
            budgets.unproven_worker,
            budgets.current_worker,
        ];
        Ok(Self {
            buckets: std::array::from_fn(|_| {
                std::array::from_fn(|share| Bucket {
                    #[cfg(test)]
                    capacity: limits[share],
                    #[cfg(test)]
                    waiting: std::sync::atomic::AtomicUsize::new(0),
                    global: Arc::new(Semaphore::new(limits[share])),
                    peers: Mutex::new(HashMap::new()),
                })
            }),
            per_peer: budgets.per_peer,
        })
    }
    pub(super) async fn reserve(
        &self,
        class: Class,
        share: ProofShare,
        peer: &SpiffeId,
        scope: [u8; 32],
    ) -> Result<ProofCredit, ProofPoolError> {
        let bucket = &self.buckets[class.index()][share.index()];
        #[cfg(test)]
        let _waiting = ProofWaiter::new(&bucket.waiting);
        let peer_slots = {
            let peer = (peer.clone(), scope);
            let mut peers = bucket.peers.lock().map_err(|_| ProofPoolError::Closed)?;
            peers.retain(|_, slots| slots.strong_count() > 0);
            if let Some(slots) = peers.get(&peer).and_then(Weak::upgrade) {
                slots
            } else {
                let slots = Arc::new(Semaphore::new(self.per_peer));
                peers.insert(peer, Arc::downgrade(&slots));
                slots
            }
        };
        // One principal/slot queue cannot take all global permits. The scope
        // comes from trusted enrollment or live routing authorization.
        let peer = peer_slots
            .acquire_owned()
            .await
            .map_err(|_| ProofPoolError::Closed)?;
        let global = bucket
            .global
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ProofPoolError::Closed)?;
        Ok(ProofCredit {
            _peer: peer,
            _global: global,
            dispatched: Instant::now(),
        })
    }
    #[cfg(test)]
    pub(super) fn used(&self, class: Class, share: ProofShare) -> usize {
        let bucket = &self.buckets[class.index()][share.index()];
        bucket.capacity - bucket.global.available_permits()
    }
    #[cfg(test)]
    pub(super) fn waiting(&self, class: Class, share: ProofShare) -> usize {
        self.buckets[class.index()][share.index()]
            .waiting
            .load(std::sync::atomic::Ordering::Acquire)
    }
}
#[cfg(test)]
struct ProofWaiter<'a>(&'a std::sync::atomic::AtomicUsize);
#[cfg(test)]
impl<'a> ProofWaiter<'a> {
    fn new(counter: &'a std::sync::atomic::AtomicUsize) -> Self {
        counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Self(counter)
    }
}
#[cfg(test)]
impl Drop for ProofWaiter<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}
pub(super) struct ProofCredit {
    _peer: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
    dispatched: Instant,
}
impl ProofCredit {
    pub(super) async fn verify_then_retain<T, F, Fut>(
        self,
        attempt: Instant,
        operation: F,
    ) -> Result<(T, ProofDispatchCredit), ProofPoolError>
    where
        F: FnOnce([u8; 32]) -> Fut,
        Fut: Future<Output = Result<T, ProofPoolError>>,
    {
        let deadline = attempt.min(self.dispatched + Duration::from_secs(5));
        if Instant::now() >= deadline {
            return Err(ProofPoolError::Deadline);
        }
        let nonce =
            super::boot::random_nonzero().map_err(|_| ProofPoolError::EntropyUnavailable)?;
        let result = tokio::time::timeout_at(deadline, operation(nonce))
            .await
            .map_err(|_| ProofPoolError::Deadline)??;
        Ok((result, ProofDispatchCredit { _credit: self }))
    }
    pub(super) async fn with_challenge<T, F, Fut>(
        self,
        attempt: Instant,
        operation: F,
    ) -> Result<T, ProofPoolError>
    where
        F: FnOnce([u8; 32]) -> Fut,
        Fut: Future<Output = Result<T, ProofPoolError>>,
    {
        let deadline = attempt.min(self.dispatched + Duration::from_secs(5));
        if Instant::now() >= deadline {
            return Err(ProofPoolError::Deadline);
        }
        let nonce =
            super::boot::random_nonzero().map_err(|_| ProofPoolError::EntropyUnavailable)?;
        tokio::time::timeout_at(deadline, operation(nonce))
            .await
            .map_err(|_| ProofPoolError::Deadline)?
    }
}
pub(super) struct ProofDispatchCredit {
    _credit: ProofCredit,
}
