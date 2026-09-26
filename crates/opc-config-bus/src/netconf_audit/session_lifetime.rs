//! Local ownership bridge for an already reserved, SDK-authenticated session.
//!
//! This component neither admits effects nor acknowledges durable cleanup. The
//! existing worker must reserve a bounded registry entry before opening a
//! session, retain OwnedSessionLifetime there before sending a transport reply,
//! and preserve that entry until every original cleanup obligation is settled.

use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use opc_persist::audit_authority::NetconfSessionOwner;
use tokio::sync::Notify;

/// Created once for the exact existing worker, then shared with its sessions.
/// Notify stores a permit when that worker is busy; this is not another queue.
#[derive(Clone)]
pub(super) struct SessionWake(Arc<Notify>);

impl SessionWake {
    pub(super) fn new() -> Self {
        Self(Arc::new(Notify::new()))
    }

    pub(super) fn notify(&self) {
        self.0.notify_one();
    }

    /// The single worker inspects all latched revocations before waiting and
    /// again after this returns. Failed cleanup does not notify itself in a loop.
    pub(super) async fn notified(&self) {
        self.0.notified().await;
    }
}

struct SessionState {
    owner: NetconfSessionOwner,
    revoked: AtomicBool,
    wake: SessionWake,
}

impl SessionState {
    fn revoke(&self) {
        // Publish local SDK revocation before the worker can observe the latch.
        // Neither action is proof that retained cleanup has been checkpointed.
        self.owner.invalidate();
        if !self.revoked.swap(true, Ordering::AcqRel) {
            self.wake.0.notify_one();
        }
    }
}

/// The bounded worker registry alone owns this non-cloneable lifetime.
pub(super) struct OwnedSessionLifetime(Arc<SessionState>);

/// Only transport handles own this layer. The worker retains SessionState, not
/// this Arc, so the last transport clone really does run TransportEnd::drop.
struct TransportEnd(Arc<SessionState>);

impl Drop for TransportEnd {
    fn drop(&mut self) {
        self.0.revoke();
    }
}

/// A lost opening reply and the last transport clone use the same revocation
/// path. No commit-channel slot, detached task, or fallible allocation is needed.
#[derive(Clone)]
pub struct TransportSessionLifetime(Arc<TransportEnd>);

/// Queued work may retain identity and observe revocation, but must not count
/// as a live transport owner. Holding this reference cannot delay final drop.
#[derive(Clone)]
pub(crate) struct SessionReference(Arc<SessionState>);

impl OwnedSessionLifetime {
    /// Call only after the attached SDK port has authenticated and minted the
    /// owner. Retain the returned worker side before making the transport side
    /// reachable by its protocol task or polling any effect-admission future.
    pub(super) fn new(
        owner: NetconfSessionOwner,
        wake: &SessionWake,
    ) -> (Self, TransportSessionLifetime) {
        let state = Arc::new(SessionState {
            owner,
            revoked: AtomicBool::new(false),
            wake: wake.clone(),
        });
        let transport = TransportSessionLifetime(Arc::new(TransportEnd(Arc::clone(&state))));
        (Self(state), transport)
    }

    pub(super) fn owner(&self) -> &NetconfSessionOwner {
        &self.0.owner
    }

    /// Stop live use during an explicit worker drain. This acknowledges no
    /// retained effect, terminal record, checkpoint, or confirmed rollback.
    pub(super) fn revoke(&self) {
        self.0.revoke();
    }

    pub(super) fn is_revoked(&self) -> bool {
        self.0.revoked.load(Ordering::Acquire)
    }

    /// Pointer identity supplements independent current-caller/SDK checks. A
    /// matching numeric protocol session or caller is insufficient ownership.
    #[cfg(test)]
    pub(super) fn owns(&self, transport: &TransportSessionLifetime) -> bool {
        Arc::ptr_eq(&self.0, &transport.0 .0)
    }

    pub(super) fn owns_reference(&self, reference: &SessionReference) -> bool {
        Arc::ptr_eq(&self.0, &reference.0)
    }
}

impl Drop for OwnedSessionLifetime {
    fn drop(&mut self) {
        // Losing the local worker also revokes still-held transport clones. It
        // cannot acknowledge cleanup or release any retained authority fence.
        self.0.revoke();
    }
}

impl TransportSessionLifetime {
    /// Copy this into a queued operation instead of cloning transport ownership.
    pub(super) fn reference(&self) -> SessionReference {
        SessionReference(Arc::clone(&self.0 .0))
    }

    pub(super) fn belongs_to(&self, worker: &SessionWake) -> bool {
        Arc::ptr_eq(&self.0 .0.wake.0, &worker.0)
    }

    /// Revoke local serving authority immediately; retained cleanup remains worker-owned.
    pub fn revoke(&self) {
        self.0 .0.revoke();
    }
}

impl SessionReference {
    pub(super) fn is_revoked(&self) -> bool {
        self.0.revoked.load(Ordering::Acquire)
    }
    pub(super) fn belongs_to(&self, worker: &SessionWake) -> bool {
        Arc::ptr_eq(&self.0.wake.0, &worker.0)
    }
}

impl fmt::Debug for SessionReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionReference(<redacted>)")
    }
}

impl fmt::Debug for TransportSessionLifetime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransportSessionLifetime(<redacted>)")
    }
}
