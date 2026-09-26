//! Bounded session ownership for the existing serial ConfigBus worker.
//!
//! Reserve before polling the authority's open future. A reservation is not a
//! serving capability. Store the minted owner and original cleanup context here
//! before delivering a transport handle; losing that reply revokes the owner.
//!
//! Only an authenticated applied cleanup, terminal/checkpoint completion and
//! current device verification permit retirement. Pending confirmed rollback
//! keeps the device unavailable and the original slot retained.

use std::{fmt, num::NonZeroUsize};

use opc_config_model::{RequestId, TransportType, TrustedPrincipal};
use opc_mgmt_audit::{AuditEvent, AuditOperation, AuditOutcome};
use opc_persist::audit_authority::{
    AuditAuthorityError, NetconfLockDatastore, NetconfLockLease, NetconfSessionOwner,
};
use tokio::sync::oneshot;

use super::{
    session_lifetime::{
        OwnedSessionLifetime, SessionReference, SessionWake, TransportSessionLifetime,
    },
    store::{NetconfAuditStore, TargetAttempt},
};

pub(crate) enum SessionOpenError {
    Full,
    Draining,
    InvalidReservation,
    Authority(AuditAuthorityError),
}

impl SessionOpenError {
    pub(super) fn into_store_error(self) -> crate::StoreError {
        match self {
            Self::Authority(error) => {
                let _ = error;
                crate::StoreError::unavailable("NETCONF session authority unavailable")
            }
            Self::Full => crate::StoreError::unavailable("NETCONF session capacity unavailable"),
            Self::Draining | Self::InvalidReservation => {
                crate::StoreError::unavailable("NETCONF session worker unavailable")
            }
        }
    }
}

impl fmt::Debug for SessionOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionOpenError(<redacted>)")
    }
}

pub(super) type SessionOpenReply =
    oneshot::Sender<Result<TransportSessionLifetime, SessionOpenError>>;

struct SessionContext {
    principal: TrustedPrincipal,
    cleanup: AuditEvent,
}

enum Slot {
    Vacant,
    Opening(Box<SessionContext>),
    Owned(Box<WorkerSession>),
}

/// Only the serial worker accesses these entries. No lock is held across an
/// authority await, and no additional task or admission queue exists here.
pub(super) struct SessionRegistry {
    entries: Vec<Slot>,
    wake: SessionWake,
    draining: bool,
}

/// Retained independently of the transport and any individual RPC future.
pub(super) struct WorkerSession {
    context: SessionContext,
    lifetime: OwnedSessionLifetime,
    cleanup: Option<TargetAttempt>,
    leases: [Option<NetconfLockLease>; 3],
}

impl WorkerSession {
    pub(super) fn lease(&self, datastore: NetconfLockDatastore) -> Option<&NetconfLockLease> {
        self.leases[lock_slot(datastore)].as_ref()
    }
    pub(super) fn principal(&self) -> &TrustedPrincipal {
        &self.context.principal
    }

    /// Reuse this exact Internal Exec Intent when preparing/recovering cleanup.
    /// A successor requires its own SDK-authorized transition after definite,
    /// checkpointed original expiry; it must not overwrite this original event.
    #[cfg(test)]
    pub(super) fn cleanup_event(&self) -> &AuditEvent {
        &self.context.cleanup
    }

    #[cfg(test)]
    pub(super) fn cleanup_attempt(&self) -> Option<&TargetAttempt> {
        self.cleanup.as_ref()
    }

    pub(super) fn lifetime(&self) -> &OwnedSessionLifetime {
        &self.lifetime
    }
}

impl SessionRegistry {
    /// Publish only an authenticated, checkpointed typed lock transition into
    /// the exact still-live session. Failure leaves the original retained and
    /// fences subsequent mutations. A dropped transport needs cleanup instead.
    pub(super) async fn finalize_lock(
        &mut self,
        port: &NetconfAuditStore,
        original: &mut TargetAttempt,
    ) {
        let Some(publication) = original.lock_publication() else {
            return;
        };
        if self.session(publication.session).is_none() {
            return;
        }
        let lease = if publication.release {
            None
        } else {
            match port
                .claim_lock(publication.prepared, publication.receipt, original.caller())
                .await
            {
                Ok(lease) => Some(lease),
                Err(_) => return,
            }
        };
        // Claiming a lease awaits retained readback; final transport loss can
        // race that await. Queued references never keep the transport alive.
        if self.draining || publication.session.is_revoked() {
            return;
        }
        for entry in &mut self.entries {
            if let Slot::Owned(session) = entry {
                if session.lifetime.owns_reference(publication.session)
                    && !session.lifetime.is_revoked()
                {
                    session.leases[lock_slot(publication.datastore)] = lease;
                    original.mark_lock_published();
                    return;
                }
            }
        }
    }

    /// `capacity` is the admitted full-profile session bound, fixed once at
    /// worker construction. This component does not increase any existing bound.
    pub(super) fn new(capacity: NonZeroUsize, wake: SessionWake) -> Self {
        Self {
            entries: std::iter::repeat_with(|| Slot::Vacant)
                .take(capacity.get())
                .collect(),
            wake,
            draining: false,
        }
    }

    /// The existing worker, not an RPC-owned future, must invoke this method.
    /// Caller loss only closes `reply`; it does not cancel this opening future.
    pub(super) async fn open_in_worker(
        &mut self,
        port: &NetconfAuditStore,
        principal: TrustedPrincipal,
        reply: SessionOpenReply,
    ) {
        if reply.is_closed() {
            return;
        }
        let reservation = match self.reserve(principal.clone()) {
            Ok(reservation) => reservation,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        // The fixed slot and original authenticated context already exist.
        // The SDK open operation has no retained effect; minting occurs after
        // its last await. Install synchronously before polling anything else.
        match port.open_session(&principal).await {
            Ok(owner) => reservation.publish(owner, reply),
            Err(error) => {
                let _ = reply.send(Err(SessionOpenError::Authority(error)));
            }
        }
    }

    pub(super) fn reserve(
        &mut self,
        principal: TrustedPrincipal,
    ) -> Result<SessionReservation<'_>, SessionOpenError> {
        if self.draining {
            return Err(SessionOpenError::Draining);
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| matches!(entry, Slot::Vacant))
            .ok_or(SessionOpenError::Full)?;
        let cleanup = AuditEvent::new(
            RequestId::new(),
            &principal,
            TransportType::Internal,
            AuditOperation::Exec,
            AuditOutcome::Intent,
        );
        *slot = Slot::Opening(Box::new(SessionContext { principal, cleanup }));
        Ok(SessionReservation {
            slot,
            wake: &self.wake,
        })
    }

    /// Call before processing another effect and after any revocation wakeup.
    /// Reads and authenticated recovery remain separate from this write fence.
    pub(super) fn has_revoked(&self) -> bool {
        self.revoked().next().is_some()
    }

    pub(super) fn revoked(&self) -> impl Iterator<Item = &WorkerSession> {
        self.entries.iter().filter_map(|entry| match entry {
            Slot::Owned(session) if session.lifetime.is_revoked() => Some(session.as_ref()),
            _ => None,
        })
    }

    /// A registry lookup supplements, but does not replace, the port's current
    /// SDK-owner and independently projected caller verification.
    pub(super) fn session(&self, reference: &SessionReference) -> Option<&WorkerSession> {
        if self.draining || !reference.belongs_to(&self.wake) {
            return None;
        }
        self.entries.iter().find_map(|entry| match entry {
            Slot::Owned(session)
                if !session.lifetime.is_revoked() && session.lifetime.owns_reference(reference) =>
            {
                Some(session.as_ref())
            }
            _ => None,
        })
    }

    /// Revoke local serving authority while retaining every owned entry. An
    /// unavailable cleanup/checkpoint must produce recovery-required shutdown,
    /// never an empty-registry or successful-drain claim.
    pub(super) fn begin_drain(&mut self) {
        self.draining = true;
        for entry in &self.entries {
            if let Slot::Owned(session) = entry {
                session.lifetime.revoke();
            }
        }
    }

    /// A bounded pass retries original work only. Failure retains the same slot,
    /// event, handle, expiry and known outcome. No timer or retry task is added.
    pub(super) async fn cleanup_revoked(&mut self, port: &NetconfAuditStore) {
        for slot in &mut self.entries {
            let Slot::Owned(session) = slot else { continue };
            if !session.lifetime.is_revoked() {
                continue;
            }
            if session.cleanup.is_none() {
                match port
                    .prepare_cleanup(
                        session.lifetime.owner(),
                        &session.context.principal,
                        &session.context.cleanup,
                    )
                    .await
                {
                    Ok(original) => session.cleanup = Some(original),
                    Err(_) => continue,
                }
            }
            let Some(original) = session.cleanup.as_mut() else {
                continue;
            };
            // Retention precedes the first possible admission await. Losing the
            // transport or a shutdown waiter never owns this future.
            let _ = port.execute_target(original).await;
            if original.applied_cleanup_settled() && port.verify_current().await.is_ok() {
                *slot = Slot::Vacant;
            }
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries
            .iter()
            .all(|entry| matches!(entry, Slot::Vacant))
    }
}

/// A dropped pre-open reservation frees only an unminted slot. An installed SDK
/// owner remains in the worker registry even if transport delivery fails.
pub(super) struct SessionReservation<'a> {
    slot: &'a mut Slot,
    wake: &'a SessionWake,
}

impl SessionReservation<'_> {
    /// No await separates SDK owner minting, worker retention and reply send.
    /// A failed send drops its transport-only Arc and latches revocation.
    pub(super) fn publish(self, owner: NetconfSessionOwner, reply: SessionOpenReply) {
        let context = match std::mem::replace(self.slot, Slot::Vacant) {
            Slot::Opening(context) => *context,
            previous => {
                *self.slot = previous;
                owner.invalidate();
                let _ = reply.send(Err(SessionOpenError::InvalidReservation));
                return;
            }
        };
        let (lifetime, transport) = OwnedSessionLifetime::new(owner, self.wake);
        *self.slot = Slot::Owned(Box::new(WorkerSession {
            context,
            lifetime,
            cleanup: None,
            leases: [None, None, None],
        }));
        let _ = reply.send(Ok(transport));
    }
}

fn lock_slot(datastore: NetconfLockDatastore) -> usize {
    match datastore {
        NetconfLockDatastore::Running => 0,
        NetconfLockDatastore::Candidate => 1,
        NetconfLockDatastore::Startup => 2,
    }
}

impl Drop for SessionReservation<'_> {
    fn drop(&mut self) {
        if matches!(self.slot, Slot::Opening(_)) {
            *self.slot = Slot::Vacant;
        }
    }
}
