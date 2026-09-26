//! Recovery uses the existing bounded commit channel and its single owner.

use std::{
    fmt,
    num::NonZeroUsize,
    panic::AssertUnwindSafe,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use futures_util::FutureExt;
use opc_config_model::{CommitError, OpcConfig, RequestId, TrustedPrincipal};
use opc_mgmt_audit::AuditSink;
use tokio::sync::oneshot;

use super::{
    result::{from_original, NetconfMutationResult, NetconfRecoveryHandle},
    store::NetconfAuditStore,
    worker::TargetWorker,
};
use crate::{commit::WorkerRequest, AuthorityMode, ConfigBus, ManagedDatastore, StoreError};

/// Captured once during bus construction. A later trait call cannot replace the
/// concrete port or observation sink used by this worker and its capabilities.
#[derive(Clone)]
pub(crate) struct WorkerAttachment {
    port: NetconfAuditStore,
    observations: Arc<dyn AuditSink>,
    pub(crate) signal: WorkerSignal,
}

impl WorkerAttachment {
    pub(crate) fn from_store<C: OpcConfig>(store: &dyn ManagedDatastore<C>) -> Option<Self> {
        let port = store.required_netconf_audit_store()?;
        port.provider().ok()?;
        Some(Self {
            port,
            observations: store.required_audit_observations()?,
            signal: WorkerSignal::new(),
        })
    }

    pub(crate) fn worker(&self, capacity: NonZeroUsize) -> TargetWorker {
        TargetWorker::new(self.port.clone(), capacity, self.signal.wake.clone())
    }
}

#[derive(Clone)]
pub(crate) struct WorkerSignal {
    draining: Arc<AtomicBool>,
    wake: super::session_lifetime::SessionWake,
}
impl WorkerSignal {
    fn new() -> Self {
        Self {
            draining: Arc::new(AtomicBool::new(false)),
            wake: super::session_lifetime::SessionWake::new(),
        }
    }
    pub(crate) fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }
    fn drain(&self) {
        self.draining.store(true, Ordering::Release);
        self.wake.notify();
    }
    pub(crate) async fn notified(&self) {
        self.wake.notified().await;
    }
}

/// Retained session lifecycle, lock admission and original recovery for one worker.
///
/// This bounded capability does not advertise a complete NETCONF target profile.
/// Candidate/startup edits, confirmed rollback and expired-cleanup successors
/// still require their complete protocol lifecycle before a server may enable them.
///
/// A clone uses the same bounded channel. A different bus over the same store
/// is not equivalent. Caller authentication and authorization remain separate;
/// the capability never creates an Intent through an observation sink.
#[derive(Clone)]
pub struct RequiredNetconfAudit<C: OpcConfig> {
    bus: ConfigBus<C>,
    attachment: WorkerAttachment,
}

impl<C: OpcConfig> ConfigBus<C> {
    /// Obtain this worker's closed retained audit capability.
    ///
    /// Both the existing running observation port and an SDK target port with
    /// its encrypting provider must have been captured at worker construction.
    /// This does not activate a retained profile or mint device/session authority.
    pub fn required_netconf_audit(&self) -> Result<RequiredNetconfAudit<C>, StoreError> {
        if self.authority_mode == AuthorityMode::Shadow {
            return Err(StoreError::unavailable("NETCONF audit worker unavailable"));
        }
        let attachment = self
            .netconf_audit
            .as_ref()
            .ok_or_else(|| StoreError::unavailable("required NETCONF audit is unsupported"))?;
        Ok(RequiredNetconfAudit {
            bus: self.clone(),
            attachment: attachment.clone(),
        })
    }
}

impl<C: OpcConfig> RequiredNetconfAudit<C> {
    /// Whether this is the same worker channel, including ordinary bus clones.
    pub fn belongs_to(&self, bus: &ConfigBus<C>) -> bool {
        self.bus.tx.same_channel(&bus.tx)
    }

    /// The attached read/denial port, which still refuses standalone Intents.
    pub fn observation_sink(&self) -> Arc<dyn AuditSink> {
        Arc::clone(&self.attachment.observations)
    }

    /// Reserve a bounded worker slot before minting SDK session authority.
    /// The returned transport owner must live in the actual protocol runner.
    /// Cancellation of this waiter cannot cancel an admitted opening operation.
    pub async fn open_session(
        &self,
        principal: &TrustedPrincipal,
    ) -> Result<super::session_lifetime::TransportSessionLifetime, StoreError> {
        if self.attachment.signal.is_draining() {
            return Err(session_unavailable());
        }
        let (reply, receiver) = oneshot::channel();
        self.bus
            .tx
            .try_send(WorkerRequest::NetconfSession(Box::new(
                SessionMessage::Open {
                    principal: principal.clone(),
                    reply,
                },
            )))
            .map_err(|_| session_unavailable())?;
        receiver
            .await
            .map_err(|_| session_unavailable())?
            .map_err(super::session_registry::SessionOpenError::into_store_error)
    }

    /// Acquire one retained lock for this exact live session and current caller.
    /// The embedding protocol must authorize the lock operation first. This
    /// method grants no NACM permission and never accepts a numeric session ID.
    pub async fn acquire_lock(
        &self,
        session: &super::session_lifetime::TransportSessionLifetime,
        principal: &TrustedPrincipal,
        event: opc_mgmt_audit::AuditEvent,
        datastore: opc_persist::audit_authority::NetconfLockDatastore,
    ) -> Result<NetconfMutationResult, CommitError> {
        self.change_lock(session, principal, event, datastore, false)
            .await
    }

    /// Release this session's retained lock using its worker-owned SDK lease.
    /// The protocol must authorize unlock first. Caller equality or a numeric
    /// session ID cannot stand in for the exact live transport owner and lease.
    /// A lost reply is recovered by its original request ID, never a new effect.
    pub async fn release_lock(
        &self,
        session: &super::session_lifetime::TransportSessionLifetime,
        principal: &TrustedPrincipal,
        event: opc_mgmt_audit::AuditEvent,
        datastore: opc_persist::audit_authority::NetconfLockDatastore,
    ) -> Result<NetconfMutationResult, CommitError> {
        self.change_lock(session, principal, event, datastore, true)
            .await
    }

    async fn change_lock(
        &self,
        session: &super::session_lifetime::TransportSessionLifetime,
        principal: &TrustedPrincipal,
        event: opc_mgmt_audit::AuditEvent,
        datastore: opc_persist::audit_authority::NetconfLockDatastore,
        release: bool,
    ) -> Result<NetconfMutationResult, CommitError> {
        if !session.belongs_to(&self.attachment.signal.wake) || self.attachment.signal.is_draining()
        {
            return Err(CommitError::new(
                opc_config_model::CommitErrorCode::AdmissionRejected,
                "NETCONF session worker mismatch",
            ));
        }
        let (reply, receiver) = oneshot::channel();
        self.bus
            .tx
            .try_send(WorkerRequest::NetconfSession(Box::new(
                SessionMessage::Lock {
                    session: session.reference(),
                    principal: principal.clone(),
                    event,
                    datastore,
                    release,
                    reply,
                },
            )))
            .map_err(|_| recovery_unavailable())?;
        // A missing reply has no operation handle: recover_request with the
        // original request ID. It is never permission to retry fresh work.
        receiver.await.map_err(|_| recovery_unavailable())
    }

    /// Close admission out of band, drain the existing worker, and join it.
    /// A cancelled waiter leaves both the shutdown latch and JoinHandle owned.
    /// RecoveryRequired is not successful cleanup or rollback completion.
    pub async fn shutdown(
        &self,
    ) -> Result<super::worker_join::WorkerExit, super::worker_join::WorkerLost> {
        self.attachment.signal.drain();
        match &self.bus.netconf_join {
            Some(join) => join.join().await,
            None => Err(super::worker_join::WorkerLost),
        }
    }

    /// Recover only the original authenticated result and any owed completion.
    ///
    /// The current trusted caller is independent of the token. Queue exhaustion,
    /// a lost reply or an unavailable worker leaves this original unknown; none
    /// permits fresh admission, expiry extension or replacement work. Once sent,
    /// the serial worker owns this recovery even if its reply future is dropped.
    pub async fn recover(
        &self,
        handle: &NetconfRecoveryHandle,
        principal: &TrustedPrincipal,
    ) -> NetconfMutationResult {
        let (reply, receiver) = oneshot::channel();
        let message = RecoveryMessage::Handle {
            handle: Box::new(handle.clone()),
            principal: principal.clone(),
            reply,
        };
        if self
            .bus
            .tx
            .try_send(WorkerRequest::NetconfRecovery(Box::new(message)))
            .is_err()
        {
            return NetconfMutationResult::Unknown(handle.clone());
        }
        receiver
            .await
            .unwrap_or_else(|_| NetconfMutationResult::Unknown(handle.clone()))
    }

    /// Recover an original reply retained by this worker for the trusted caller.
    ///
    /// A cache miss is no evidence about whether an earlier effect happened and
    /// grants no retry permission. After process replacement use the protected
    /// original handle. The registry is a bounded reply cache, not the retained
    /// authority's request-uniqueness or operation-recovery boundary.
    pub async fn recover_request(
        &self,
        request: RequestId,
        principal: &TrustedPrincipal,
    ) -> Result<Option<NetconfMutationResult>, CommitError> {
        let (reply, receiver) = oneshot::channel();
        let message = RecoveryMessage::Request {
            request,
            principal: principal.clone(),
            reply,
        };
        self.bus
            .tx
            .try_send(WorkerRequest::NetconfRecovery(Box::new(message)))
            .map_err(|_| recovery_unavailable())?;
        receiver.await.map_err(|_| recovery_unavailable())?
    }
}

impl<C: OpcConfig> fmt::Debug for RequiredNetconfAudit<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequiredNetconfAudit(<redacted>)")
    }
}

pub(crate) enum RecoveryMessage {
    Handle {
        handle: Box<NetconfRecoveryHandle>,
        principal: TrustedPrincipal,
        reply: oneshot::Sender<NetconfMutationResult>,
    },
    Request {
        request: RequestId,
        principal: TrustedPrincipal,
        reply: oneshot::Sender<Result<Option<NetconfMutationResult>, CommitError>>,
    },
}

/// Called only by the already existing ConfigBus worker, without an extra task
/// or channel. Original registry state stays outside every unwind boundary.
pub(crate) async fn recover_in_worker(worker: Option<&mut TargetWorker>, message: RecoveryMessage) {
    match message {
        RecoveryMessage::Handle {
            handle,
            principal,
            reply,
        } => {
            let handle = *handle;
            let recovered = AssertUnwindSafe(async {
                match worker {
                    Some(worker) => {
                        from_original(worker.recover(handle.original.clone(), &principal).await)
                    }
                    None => NetconfMutationResult::Unknown(handle.clone()),
                }
            })
            .catch_unwind()
            .await
            .unwrap_or(NetconfMutationResult::Unknown(handle));
            let _ = reply.send(recovered);
        }
        RecoveryMessage::Request {
            request,
            principal,
            reply,
        } => {
            let recovered = AssertUnwindSafe(async {
                let worker = worker.ok_or_else(recovery_unavailable)?;
                worker
                    .recover_request(request, &principal)
                    .await
                    .map(|original| original.map(from_original))
                    .map_err(|_| recovery_unavailable())
            })
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err(recovery_unavailable()));
            let _ = reply.send(recovered);
        }
    }
}

fn recovery_unavailable() -> CommitError {
    CommitError::outcome_unknown("original NETCONF recovery is unavailable")
}

fn session_unavailable() -> StoreError {
    StoreError::unavailable("NETCONF session authority unavailable")
}

pub(crate) enum SessionMessage {
    Open {
        principal: TrustedPrincipal,
        reply: super::session_registry::SessionOpenReply,
    },
    Lock {
        session: super::session_lifetime::SessionReference,
        principal: TrustedPrincipal,
        event: opc_mgmt_audit::AuditEvent,
        datastore: opc_persist::audit_authority::NetconfLockDatastore,
        release: bool,
        reply: oneshot::Sender<NetconfMutationResult>,
    },
}

pub(crate) async fn session_in_worker(worker: Option<&mut TargetWorker>, message: SessionMessage) {
    match message {
        SessionMessage::Open { principal, reply } => {
            if let Some(worker) = worker {
                let port = worker.port().clone();
                worker
                    .sessions
                    .open_in_worker(&port, principal, reply)
                    .await;
            } else {
                let _ = reply.send(Err(super::session_registry::SessionOpenError::Draining));
            }
        }
        SessionMessage::Lock {
            session,
            principal,
            event,
            datastore,
            release,
            reply,
        } => {
            let result = match worker {
                Some(worker) => {
                    let result = if release {
                        worker
                            .release_lock(&session, &principal, &event, datastore)
                            .await
                    } else {
                        worker
                            .acquire_lock(&session, &principal, &event, datastore)
                            .await
                    };
                    match result {
                        Ok(original) => from_original(original),
                        Err(refusal) => refusal.into_result(),
                    }
                }
                None => NetconfMutationResult::Refused(CommitError::new(
                    opc_config_model::CommitErrorCode::AdmissionRejected,
                    "NETCONF session worker unavailable",
                )),
            };
            let _ = reply.send(result);
        }
    }
}
