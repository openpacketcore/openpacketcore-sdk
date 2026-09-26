//! Original-operation dispatch state for the existing serial ConfigBus worker.
//!
//! This module owns no task, channel, timer, provider, or application callback.
//! Protocol authorization precedes worker admission. The worker validates the
//! exact session and prepares the request through its attached concrete port
//! before transferring the original here for admission.

use std::{num::NonZeroUsize, panic::AssertUnwindSafe};

use futures_util::FutureExt;
use opc_config_model::{RequestId, TrustedPrincipal};
use opc_persist::audit_authority::{AuditAuthorityError, AuditCaller, AuditOperationHandle};

use super::{
    registry::{RegistryRefusal, TargetRegistry},
    store::{NetconfAuditStore, TargetAttempt, TargetReply},
};

/// Construct once when the existing worker accepts its verified attachment.
/// A later attachment cannot replace this state or its unresolved original.
pub(crate) struct TargetWorker {
    port: NetconfAuditStore,
    originals: TargetRegistry,
    pub(super) sessions: super::session_registry::SessionRegistry,
}

/// The handle and result travel together even when the receiving RPC is lost.
/// There is deliberately no Debug implementation for operation identities.
pub(super) struct OriginalReply {
    pub(super) handle: AuditOperationHandle,
    pub(super) result: TargetReply,
    pub(super) lock_ready: bool,
}

pub(super) enum BeforeAdmissionRefusal {
    Authority(AuditAuthorityError),
    Registry(RegistryRefusal),
}

impl BeforeAdmissionRefusal {
    pub(super) fn into_result(self) -> super::NetconfMutationResult {
        let error = match self {
            Self::Authority(AuditAuthorityError::RecoveryRequired)
            | Self::Registry(RegistryRefusal::OriginalUnsettled) => {
                opc_config_model::CommitError::recovery_required(
                    "NETCONF original recovery required",
                )
            }
            Self::Authority(_) | Self::Registry(_) => opc_config_model::CommitError::new(
                opc_config_model::CommitErrorCode::AdmissionRejected,
                "NETCONF session effect refused",
            ),
        };
        super::NetconfMutationResult::Refused(error)
    }
}

impl TargetWorker {
    pub(super) fn new(
        port: NetconfAuditStore,
        capacity: NonZeroUsize,
        wake: super::session_lifetime::SessionWake,
    ) -> Self {
        Self {
            port,
            originals: TargetRegistry::new(),
            sessions: super::session_registry::SessionRegistry::new(capacity, wake),
        }
    }

    pub(super) fn port(&self) -> &NetconfAuditStore {
        &self.port
    }

    /// The enclosing serial worker also refuses a later ordinary mutation while
    /// this fence is active. Reads and original recovery remain separate.
    /// Clearing this local fence never clears the authority's retained fence.
    pub(crate) fn has_unsettled(&self) -> bool {
        self.originals.has_unsettled() || self.sessions.has_revoked()
    }

    pub(crate) async fn cleanup(&mut self) {
        // An unresolved effect precedes cleanup; it cannot be replaced by an
        // EndSession request under a fresh operation identity.
        self.originals
            .recover_unsettled(&self.port, &mut self.sessions)
            .await;
        if !self.originals.has_unsettled() {
            self.sessions.cleanup_revoked(&self.port).await;
        }
    }

    pub(crate) fn begin_drain(&mut self) {
        self.sessions.begin_drain();
    }

    pub(crate) async fn finish_drain(&mut self) -> super::worker_join::WorkerExit {
        self.begin_drain();
        self.cleanup().await;
        if self.sessions.is_empty()
            && !self.originals.has_unsettled()
            && self.port.verify_current().await.is_ok()
        {
            super::worker_join::WorkerExit::Drained
        } else {
            super::worker_join::WorkerExit::RecoveryRequired
        }
    }

    pub(super) async fn acquire_lock(
        &mut self,
        reference: &super::session_lifetime::SessionReference,
        principal: &TrustedPrincipal,
        event: &opc_mgmt_audit::AuditEvent,
        datastore: opc_persist::audit_authority::NetconfLockDatastore,
    ) -> Result<OriginalReply, BeforeAdmissionRefusal> {
        self.change_lock(reference, principal, event, datastore, false)
            .await
    }

    pub(super) async fn release_lock(
        &mut self,
        reference: &super::session_lifetime::SessionReference,
        principal: &TrustedPrincipal,
        event: &opc_mgmt_audit::AuditEvent,
        datastore: opc_persist::audit_authority::NetconfLockDatastore,
    ) -> Result<OriginalReply, BeforeAdmissionRefusal> {
        self.change_lock(reference, principal, event, datastore, true)
            .await
    }

    async fn change_lock(
        &mut self,
        reference: &super::session_lifetime::SessionReference,
        principal: &TrustedPrincipal,
        event: &opc_mgmt_audit::AuditEvent,
        datastore: opc_persist::audit_authority::NetconfLockDatastore,
        release: bool,
    ) -> Result<OriginalReply, BeforeAdmissionRefusal> {
        self.check_new(event.request_id, principal)?;
        if self.sessions.has_revoked() {
            return Err(BeforeAdmissionRefusal::Authority(
                AuditAuthorityError::RecoveryRequired,
            ));
        }
        let session = self
            .sessions
            .session(reference)
            .ok_or(BeforeAdmissionRefusal::Authority(
                AuditAuthorityError::BindingMismatch,
            ))?;
        // Compare the independently authenticated principal, then let the SDK
        // project and verify the exact current session before preparing effect.
        if session.principal() != principal {
            return Err(BeforeAdmissionRefusal::Authority(
                AuditAuthorityError::BindingMismatch,
            ));
        }
        let mut original = if release {
            let lease = session
                .lease(datastore)
                .ok_or(BeforeAdmissionRefusal::Authority(
                    AuditAuthorityError::BindingMismatch,
                ))?;
            self.port
                .prepare_unlock(
                    session.lifetime().owner(),
                    lease,
                    principal,
                    event,
                    datastore,
                )
                .await
        } else {
            self.port
                .prepare_lock(session.lifetime().owner(), principal, event, datastore)
                .await
        }
        .map_err(BeforeAdmissionRefusal::Authority)?;
        // Revocation can race every preparation await. The SDK also rechecks
        // owner activity during preparation; this is the final local boundary.
        if self.sessions.session(reference).is_none() {
            return Err(BeforeAdmissionRefusal::Authority(
                AuditAuthorityError::BindingMismatch,
            ));
        }
        original.bind_session(reference.clone());
        self.execute(event.request_id, principal, original).await
    }

    /// Check before model/provider preparation. The same check runs again when
    /// retaining the original, before its first admission await.
    pub(super) fn check_new(
        &self,
        request: RequestId,
        principal: &TrustedPrincipal,
    ) -> Result<(), BeforeAdmissionRefusal> {
        let caller = self
            .port
            .caller(principal)
            .map_err(BeforeAdmissionRefusal::Authority)?;
        self.originals
            .check_new(request, caller)
            .map_err(BeforeAdmissionRefusal::Registry)
    }

    /// Only the enclosing worker calls this, after exact session/base checks,
    /// model authorization and the concrete SDK preparation have completed.
    /// This future must remain worker-owned when a reply receiver disappears.
    pub(super) async fn execute(
        &mut self,
        request: RequestId,
        principal: &TrustedPrincipal,
        original: TargetAttempt,
    ) -> Result<OriginalReply, BeforeAdmissionRefusal> {
        let caller = self
            .port
            .caller(principal)
            .map_err(BeforeAdmissionRefusal::Authority)?;
        if !self.port.owns_original(&original) || original.caller() != caller {
            return Err(BeforeAdmissionRefusal::Authority(
                AuditAuthorityError::BindingMismatch,
            ));
        }
        let handle = self
            .originals
            .retain_new(request, original)
            .map_err(BeforeAdmissionRefusal::Registry)?;
        // No admission future has been polled until after this owned insertion.
        Ok(self
            .dispatch_retained(handle, caller, Dispatch::Execute)
            .await)
    }

    /// Lookup is independently caller-authenticated before any cache access.
    /// A cached known result precedes fallible current-device/provider reads.
    /// Failure to reconstruct an uncached original never permits fresh work.
    pub(super) async fn recover(
        &mut self,
        handle: AuditOperationHandle,
        principal: &TrustedPrincipal,
    ) -> OriginalReply {
        let caller =
            match std::panic::catch_unwind(AssertUnwindSafe(|| self.port.caller(principal))) {
                Ok(Ok(caller)) => caller,
                Ok(Err(_)) | Err(_) => return unknown(handle),
            };

        if self.originals.original_mut(&handle, caller).is_some() {
            return self
                .dispatch_retained(handle, caller, Dispatch::Recover)
                .await;
        }

        // Capturing both future construction and polling prevents an adapter
        // panic from converting a possibly transmitted original into refusal.
        let recovered =
            AssertUnwindSafe(async { self.port.recover_original(&handle, principal).await })
                .catch_unwind()
                .await;
        let original = match recovered {
            Ok(Ok(Some(original))) => original,
            Ok(Ok(None)) | Ok(Err(_)) | Err(_) => return unknown(handle),
        };
        if original.handle() != &handle
            || original.caller() != caller
            || !self.port.owns_original(&original)
        {
            return unknown(handle);
        }
        // Recovery returns a started preparation. It can only lookup or finish
        // its original outcome; it never becomes a fresh-admission candidate.
        if self.originals.retain_recovered(original).is_err() {
            return unknown(handle);
        }
        self.dispatch_retained(handle, caller, Dispatch::Recover)
            .await
    }

    /// Recover a lost local reply without accepting caller-asserted operation
    /// identity. A cache miss conveys no result and grants no retry permission;
    /// process replacement uses the explicit authenticated recovery handle.
    pub(super) async fn recover_request(
        &mut self,
        request: RequestId,
        principal: &TrustedPrincipal,
    ) -> Result<Option<OriginalReply>, AuditAuthorityError> {
        let caller =
            match std::panic::catch_unwind(AssertUnwindSafe(|| self.port.caller(principal))) {
                Ok(projected) => projected?,
                Err(_) => return Err(AuditAuthorityError::Unavailable),
            };
        let Some(handle) = self.originals.original_handle(request, caller) else {
            return Ok(None);
        };
        Ok(Some(
            self.dispatch_retained(handle, caller, Dispatch::Recover)
                .await,
        ))
    }

    async fn dispatch_retained(
        &mut self,
        handle: AuditOperationHandle,
        caller: AuditCaller,
        dispatch: Dispatch,
    ) -> OriginalReply {
        let port = self.port.clone();
        let Some(original) = self.originals.original_mut(&handle, caller) else {
            return unknown(handle);
        };
        // State lives outside the unwind boundary. In particular, a panic in
        // terminal persistence cannot erase an already authenticated receipt.
        let attempted = AssertUnwindSafe(async {
            let result = match dispatch {
                Dispatch::Execute => port.execute_target(original).await,
                Dispatch::Recover => port.recover_target(original).await,
            };
            self.sessions.finalize_lock(&port, original).await;
            result
        })
        .catch_unwind()
        .await;
        let result = match attempted {
            Ok(result) => result,
            Err(_) => original.retained_reply(),
        };
        OriginalReply {
            handle,
            result,
            lock_ready: original.lock_ready(),
        }
    }
}

enum Dispatch {
    Execute,
    Recover,
}

fn unknown(handle: AuditOperationHandle) -> OriginalReply {
    OriginalReply {
        handle,
        result: TargetReply::Unknown,
        lock_ready: false,
    }
}
