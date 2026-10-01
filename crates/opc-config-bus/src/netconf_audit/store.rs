//! Concrete retained NETCONF authority used only by the bounded ConfigBus worker.
use std::{fmt, sync::Arc, time::Duration};

use opc_config_model::{RequestId, TransportType, TrustedPrincipal};
use opc_key::{KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose};
use opc_mgmt_audit::{AuditEvent, AuditOperation, AuditOutcome};
use opc_persist::audit_authority::{
    AuditAdmission, AuditAuthorityError, AuditCaller, AuditOperationHandle, AuditOperationReceipt,
    AuditOperationState, AuditPrivacyProjection, NetconfAppliedOutcome, NetconfDeviceOwner,
    NetconfLockDatastore, NetconfLockLease, NetconfSessionOwner, PreparedNetconfLock,
    PreparedTargetMutation,
};
use opc_persist::{ConsensusConfigStore, ManagementAuditEventRecord};
use opc_types::TenantId;

use crate::StoreError;

#[cfg(test)]
#[path = "retirement_reply_observation.rs"]
mod retirement_reply_observation;

/// A concrete SDK authority for the retained NETCONF profile.
///
/// Construction checks the original store worker and already established device
/// through the current quorum and independent checkpoint. It neither activates
/// storage nor creates a device. An observation sink or a caller-asserted result
/// cannot construct this port. The ConfigBus worker additionally binds sessions
/// and owns each original preparation before admission. The embedding protocol
/// must authorize requests before submitting them to the worker.
#[derive(Clone)]
pub struct NetconfAuditStore {
    inner: Arc<Authority>,
    provider: Option<Arc<dyn KeyProvider>>,
}

struct Authority {
    store: Arc<ConsensusConfigStore>,
    privacy: Arc<dyn AuditPrivacyProjection>,
    lifetime: Duration,
    device: NetconfDeviceOwner,
    #[cfg(test)]
    retirement_reply: retirement_reply_observation::ReplySlot,
}

impl NetconfAuditStore {
    /// Bind an existing SDK device to its exact consensus worker.
    ///
    /// `privacy` must match the provisioned ledger. Authentication supplies the
    /// principal independently on every session/request; projection alone grants
    /// no permission. `lifetime` is the existing bounded operation lifetime and
    /// does not extend any protocol deadline.
    pub async fn new(
        store: Arc<ConsensusConfigStore>,
        privacy: Arc<dyn AuditPrivacyProjection>,
        lifetime: Duration,
        device: NetconfDeviceOwner,
    ) -> Result<Self, StoreError> {
        if lifetime.subsec_nanos() != 0 || !(1..=3600).contains(&lifetime.as_secs()) {
            return Err(StoreError::internal("invalid audit operation lifetime"));
        }
        store
            .verify_netconf_device_owner(&device)
            .await
            .map_err(|_| StoreError::unavailable("NETCONF device authority unavailable"))?;
        Ok(Self {
            inner: Arc::new(Authority {
                store,
                privacy,
                lifetime,
                device,
                #[cfg(test)]
                retirement_reply: retirement_reply_observation::ReplySlot::default(),
            }),
            provider: None,
        })
    }

    pub(crate) async fn verify_current(&self) -> Result<(), StoreError> {
        self.inner
            .store
            .verify_netconf_device_owner(&self.inner.device)
            .await
            .map_err(|_| StoreError::unavailable("NETCONF device authority unavailable"))
    }

    // Only the SDK encrypting wrapper attaches its own provider. This method
    // needs 'static for this explicit full-profile attachment; ordinary generic
    // EncryptingManagedDatastore implementations keep their existing bounds.
    pub(crate) fn with_provider<P: KeyProvider + ?Sized + 'static>(
        &self,
        provider: Arc<P>,
    ) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            provider: Some(Arc::new(SharedProvider(provider))),
        }
    }

    pub(super) fn provider(&self) -> Result<&dyn KeyProvider, AuditAuthorityError> {
        self.provider
            .as_deref()
            .ok_or(AuditAuthorityError::KeyUnavailable)
    }

    pub(super) fn caller(
        &self,
        principal: &TrustedPrincipal,
    ) -> Result<AuditCaller, AuditAuthorityError> {
        AuditCaller::project(
            self.inner.privacy.as_ref(),
            principal.tenant.as_str(),
            &opc_mgmt_audit::principal_descriptor(principal),
        )
    }

    pub(super) async fn open_session(
        &self,
        principal: &TrustedPrincipal,
    ) -> Result<NetconfSessionOwner, AuditAuthorityError> {
        self.inner
            .store
            .open_netconf_session(&self.inner.device, self.caller(principal)?)
            .await
    }

    pub(super) async fn verify_session(
        &self,
        session: &NetconfSessionOwner,
        principal: &TrustedPrincipal,
    ) -> Result<AuditCaller, AuditAuthorityError> {
        let caller = self.caller(principal)?;
        self.inner
            .store
            .verify_netconf_session_owner(session, caller)
            .await?;
        Ok(caller)
    }

    pub(super) async fn prepare_cleanup(
        &self,
        session: &NetconfSessionOwner,
        principal: &TrustedPrincipal,
        event: &AuditEvent,
    ) -> Result<TargetAttempt, AuditAuthorityError> {
        let caller = self.caller(principal)?;
        let event =
            super::event::convert_event(event).map_err(|_| AuditAuthorityError::BindingMismatch)?;
        let prepared = self
            .inner
            .store
            .prepare_netconf_session_cleanup(
                session,
                self.inner.privacy.as_ref(),
                &event,
                self.inner.lifetime,
            )
            .await;
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => self
                .inner
                .store
                .retained_netconf_session_cleanup(
                    session,
                    caller,
                    self.inner.privacy.as_ref(),
                    &event,
                )?
                .ok_or(error)?,
        };
        let mut original = self.original_target(prepared, caller, None);
        // Only this closed SDK preparation may resume cleanup after transport
        // loss. A recovered payload or another generic target is insufficient.
        original.cleanup = true;
        Ok(original)
    }

    pub(super) async fn retire_cleanup(
        &self,
        session: &NetconfSessionOwner,
        principal: &TrustedPrincipal,
        attempt: &mut TargetAttempt,
    ) -> TargetReply {
        let caller = match self.caller(principal) {
            Ok(caller)
                if caller == attempt.caller && self.owns_original(attempt) && attempt.cleanup =>
            {
                caller
            }
            _ => return TargetReply::Refused(AuditAuthorityError::BindingMismatch),
        };
        if attempt.known.is_some() {
            return self.complete_known(attempt).await;
        }
        let Some(prepared) = attempt.prepared.as_ref() else {
            return TargetReply::Unknown;
        };
        // Retain the exact original through this await. A lost retirement reply
        // is not a rejection and cannot authorize a successor. The SDK serializes
        // this no-effect decision against any in-flight original Admit/Apply.
        let was_pending = attempt.cleanup_retirement_pending;
        attempt.cleanup_retirement_pending = true;
        match self
            .inner
            .store
            .retire_netconf_session_cleanup_local(session, prepared, caller)
            .await
        {
            AuditAdmission::Applied(receipt)
                if {
                    #[cfg(test)]
                    self.inner
                        .retirement_reply
                        .hold(prepared.handle(), &receipt)
                        .await;
                    attempt.accept_known(&receipt)
                } =>
            {
                attempt.admission_refusal = None;
                self.complete_known(attempt).await
            }
            AuditAdmission::Rejected(error) => {
                // This refusal says nothing about an older cancelled/Unknown
                // retirement. It cannot restore definite non-admission then.
                attempt.cleanup_retirement_pending = was_pending;
                if was_pending {
                    TargetReply::Unknown
                } else {
                    TargetReply::Refused(error)
                }
            }
            _ => TargetReply::Unknown,
        }
    }

    pub(super) async fn prepare_cleanup_successor(
        &self,
        session: &NetconfSessionOwner,
        principal: &TrustedPrincipal,
        previous: &TargetAttempt,
        event: &AuditEvent,
    ) -> Result<TargetAttempt, AuditAuthorityError> {
        let caller = self.caller(principal)?;
        if caller != previous.caller
            || !self.owns_original(previous)
            || !previous.rejected_cleanup_settled()
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let prepared = previous
            .prepared
            .as_ref()
            .ok_or(AuditAuthorityError::BindingMismatch)?;
        let event =
            super::event::convert_event(event).map_err(|_| AuditAuthorityError::BindingMismatch)?;
        let next = self
            .inner
            .store
            .prepare_netconf_session_cleanup_after_retirement(
                session,
                prepared,
                self.inner.privacy.as_ref(),
                &event,
            )
            .await;
        let next = match next {
            Ok(next) => next,
            Err(error) => self
                .inner
                .store
                .retained_netconf_session_cleanup(
                    session,
                    caller,
                    self.inner.privacy.as_ref(),
                    &event,
                )?
                .ok_or(error)?,
        };
        if next.handle() == previous.handle() {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let mut next = self.original_target(next, caller, None);
        next.cleanup = true;
        Ok(next)
    }

    pub(super) async fn freeze_running(
        &self,
        session: &NetconfSessionOwner,
        principal: &TrustedPrincipal,
    ) -> Result<opc_persist::audit_authority::NetconfRunningEditRead, AuditAuthorityError> {
        self.verify_session(session, principal).await?;
        self.inner.store.read_netconf_running_edit(session).await
    }

    pub(super) async fn prepare_running(
        &self,
        session: &NetconfSessionOwner,
        frozen: &opc_persist::audit_authority::NetconfRunningEditRead,
        commit: opc_persist::AttestedConfigCommit,
        operation: super::running::RunningOperation,
        principal: &TrustedPrincipal,
        event: &AuditEvent,
    ) -> Result<TargetAttempt, AuditAuthorityError> {
        let intent = self
            .bind_intent(
                event.request_id,
                principal,
                event.transport,
                operation.audit_operation(),
                event,
            )
            .map_err(|_| AuditAuthorityError::BindingMismatch)?;
        let prepared = self
            .inner
            .store
            .prepare_netconf_running_replacement(
                session,
                frozen,
                commit,
                self.inner.privacy.as_ref(),
                &intent.event,
                self.inner.lifetime,
            )
            .await?;
        let mut original = self.original_target(prepared, intent.caller, Some(intent.request_id));
        original.running_owner = Some(session.clone());
        Ok(original)
    }

    pub(super) async fn prepare_lock(
        &self,
        session: &NetconfSessionOwner,
        principal: &TrustedPrincipal,
        event: &AuditEvent,
        datastore: NetconfLockDatastore,
    ) -> Result<TargetAttempt, AuditAuthorityError> {
        let intent = self
            .bind_intent(
                event.request_id,
                principal,
                event.transport,
                AuditOperation::Exec,
                event,
            )
            .map_err(|_| AuditAuthorityError::BindingMismatch)?;
        self.verify_session(session, principal).await?;
        let prepared = self
            .inner
            .store
            .prepare_netconf_lock_acquisition(
                session,
                datastore,
                self.inner.privacy.as_ref(),
                &intent.event,
                self.inner.lifetime,
            )
            .await?;
        Ok(self.lock_target(prepared, intent, datastore, false))
    }

    pub(super) async fn prepare_unlock(
        &self,
        session: &NetconfSessionOwner,
        lease: &NetconfLockLease,
        principal: &TrustedPrincipal,
        event: &AuditEvent,
        datastore: NetconfLockDatastore,
    ) -> Result<TargetAttempt, AuditAuthorityError> {
        let intent = self
            .bind_intent(
                event.request_id,
                principal,
                event.transport,
                AuditOperation::Exec,
                event,
            )
            .map_err(|_| AuditAuthorityError::BindingMismatch)?;
        self.verify_session(session, principal).await?;
        self.inner
            .store
            .verify_netconf_lock_lease(lease, intent.caller)
            .await?;
        let prepared = self
            .inner
            .store
            .prepare_netconf_lock_release(
                session,
                lease,
                self.inner.privacy.as_ref(),
                &intent.event,
                self.inner.lifetime,
            )
            .await?;
        Ok(self.lock_target(prepared, intent, datastore, true))
    }

    fn lock_target(
        &self,
        prepared: PreparedNetconfLock,
        intent: BoundIntent,
        datastore: NetconfLockDatastore,
        release: bool,
    ) -> TargetAttempt {
        let mut original = self.original_target(
            prepared.mutation().clone(),
            intent.caller,
            Some(intent.request_id),
        );
        // Keep the typed SDK preparation before the first Intent await. A
        // mutation/receipt pair alone cannot mint the exact session's lease.
        original.lock = Some(Box::new(LockTransition {
            prepared,
            datastore,
            release,
        }));
        original
    }

    pub(super) async fn claim_lock(
        &self,
        prepared: &PreparedNetconfLock,
        receipt: &AuditOperationReceipt,
        caller: AuditCaller,
    ) -> Result<NetconfLockLease, AuditAuthorityError> {
        self.inner
            .store
            .claim_netconf_lock_lease(prepared, receipt, caller)
            .await
    }

    pub(super) fn bind_intent(
        &self,
        request_id: RequestId,
        principal: &TrustedPrincipal,
        transport: TransportType,
        operation: AuditOperation,
        event: &AuditEvent,
    ) -> Result<BoundIntent, StoreError> {
        if !matches!(
            transport,
            TransportType::NetconfSsh | TransportType::NetconfTls
        ) || event.request_id != request_id
            || event.principal != opc_mgmt_audit::principal_descriptor(principal)
            || event.tenant != principal.tenant.as_str()
            || event.transport != transport
            || event.operation != operation
            || event.outcome != AuditOutcome::Intent
            || event.tx_id.is_some()
        {
            return Err(StoreError::unavailable(
                "NETCONF audit request binding mismatch",
            ));
        }
        Ok(BoundIntent {
            request_id,
            caller: self
                .caller(principal)
                .map_err(|_| StoreError::unavailable("NETCONF audit projection unavailable"))?,
            event: super::event::convert_event(event)?,
        })
    }

    // This is checked before transferring a new preparation to the registry.
    // Equal underlying stores do not replace the originally attached port.
    pub(super) fn owns_original(&self, attempt: &TargetAttempt) -> bool {
        Arc::ptr_eq(&self.inner, &attempt.authority)
    }

    pub(super) fn original_target(
        &self,
        prepared: PreparedTargetMutation,
        caller: AuditCaller,
        request_id: Option<RequestId>,
    ) -> TargetAttempt {
        TargetAttempt {
            request_id,
            authority: Arc::clone(&self.inner),
            handle: prepared.handle().clone(),
            prepared: Some(prepared),
            caller,
            started: false,
            known: None,
            completion_settled: false,
            admission_refusal: None,
            session: None,
            lock: None,
            lock_ready: false,
            running_owner: None,
            running_admission_deadline: None,
            acknowledged_intent: None,
            cleanup: false,
            cleanup_retirement_pending: false,
            published_commit: None,
        }
    }

    /// Recover protected original bytes from the retained authority, including
    /// after a worker replacement. The independently authenticated caller is
    /// projected afresh; neither the token nor the new session supplies it.
    /// Absence and failure never allow a new admission under this handle.
    pub(super) async fn recover_original(
        &self,
        handle: &AuditOperationHandle,
        principal: &TrustedPrincipal,
    ) -> Result<Option<TargetAttempt>, AuditAuthorityError> {
        let caller = self.caller(principal)?;
        let Some(prepared) = self
            .inner
            .store
            .recover_netconf_target(handle, caller)
            .await?
        else {
            return Ok(None);
        };
        if prepared.handle() != handle {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let mut original = self.original_target(prepared, caller, None);
        // A replacement worker must never treat retained preparation as fresh
        // permission to submit. Only readback and original completion may run.
        original.started = true;
        Ok(Some(original))
    }

    /// The caller retains `attempt` in the bounded worker registry before this
    /// first await. A cancelled RPC receiver never owns this future. Re-entering
    /// after uncertainty performs only lookup/known completion. A retained real
    /// acknowledgement permits original submission; a definite cleanup refusal
    /// permits retrying only that same preparation on a later bounded pass.
    pub(super) async fn execute_target(&self, attempt: &mut TargetAttempt) -> TargetReply {
        if !Arc::ptr_eq(&self.inner, &attempt.authority) {
            return TargetReply::Refused(AuditAuthorityError::BindingMismatch);
        }
        // A definite refusal permits another bounded pass over the same cleanup
        // original. Unknown admission and acknowledged work never take this
        // route. The SDK rechecks state and the unchanged handle/expiry; stale
        // cleanup still requires a separately authorized SDK successor.
        let retry_cleanup = attempt.cleanup
            && !attempt.cleanup_retirement_pending
            && attempt.admission_refusal.is_some()
            && attempt.acknowledged_intent.is_none()
            && attempt.known.is_none();
        if attempt.started && !retry_cleanup {
            return self.recover_target(attempt).await;
        }
        let Some(prepared) = attempt.prepared.as_ref() else {
            return TargetReply::Refused(AuditAuthorityError::BindingMismatch);
        };
        if attempt
            .session
            .as_ref()
            .is_some_and(|session| session.is_revoked())
        {
            attempt.admission_refusal = Some(AuditAuthorityError::BindingMismatch);
            return TargetReply::Refused(AuditAuthorityError::BindingMismatch);
        }
        attempt.admission_refusal = None;
        attempt.started = true;
        let admission = match (&attempt.running_owner, attempt.running_admission_deadline) {
            (Some(session), Some(deadline)) => {
                self.inner
                    .store
                    .admit_netconf_running_replacement_local_until(
                        session,
                        prepared,
                        attempt.caller,
                        deadline,
                    )
                    .await
            }
            (Some(_), None) => AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch),
            (None, _) => {
                self.inner
                    .store
                    .admit_netconf_target_local(prepared, attempt.caller)
                    .await
            }
        };
        let admitted = match admission {
            AuditAdmission::Rejected(error) => {
                attempt.admission_refusal = Some(error);
                if !attempt.cleanup {
                    attempt.prepared = None;
                }
                return TargetReply::Refused(error);
            }
            AuditAdmission::Unknown(_) => return TargetReply::Unknown,
            AuditAdmission::Applied(receipt) => receipt,
        };
        if admitted.handle() != &attempt.handle {
            return TargetReply::Unknown;
        }
        match admitted.state() {
            AuditOperationState::Intent
            | AuditOperationState::TargetV1(_)
            | AuditOperationState::Rejected => {}
            _ => return TargetReply::Unknown,
        }
        if attempt.running_owner.is_some() || attempt.cleanup {
            // Preserve the SDK-authenticated acknowledgement, not a caller claim
            // or an indeterminate Intent lookup. Running and closed EndSession
            // obligations may finish after revocation under their fixed original.
            // Other generic targets retain their existing revocation policy.
            attempt.acknowledged_intent = Some(admitted.clone());
        }
        if attempt.running_owner.is_none()
            && attempt
                .session
                .as_ref()
                .is_some_and(|session| session.is_revoked())
        {
            // Intent may exist. Refusing the effect does not erase its debt.
            return TargetReply::Unknown;
        }
        // Only this original, acknowledged Intent permits an effect submission.
        // For a known outcome the SDK only validates and returns the same receipt.
        match self
            .inner
            .store
            .submit_netconf_target_local(prepared, &admitted, attempt.caller)
            .await
        {
            AuditAdmission::Applied(receipt) if attempt.accept_known(&receipt) => {
                self.complete_known(attempt).await
            }
            // A refusal of this call is not proof that an earlier transmission
            // did not apply. Keep the original and obtain authoritative readback.
            AuditAdmission::Rejected(_) | AuditAdmission::Unknown(_) => {
                self.recover_target(attempt).await
            }
            AuditAdmission::Applied(_) => TargetReply::Unknown,
        }
    }

    pub(super) async fn recover_target(&self, attempt: &mut TargetAttempt) -> TargetReply {
        if !Arc::ptr_eq(&self.inner, &attempt.authority) {
            return TargetReply::Refused(AuditAuthorityError::BindingMismatch);
        }
        // Once authenticated, the result also precedes an older no-effect
        // refusal retained before a cancelled retirement was recovered.
        if attempt.known.is_some() {
            return self.complete_known(attempt).await;
        }
        if let Some(refusal) = attempt
            .admission_refusal
            .filter(|_| !attempt.cleanup_retirement_pending)
        {
            return TargetReply::Refused(refusal);
        }
        if !attempt.started {
            return TargetReply::Refused(AuditAuthorityError::BindingMismatch);
        }
        let Some(prepared) = attempt.prepared.as_ref() else {
            return TargetReply::Unknown;
        };
        if let Some(admitted) = attempt.acknowledged_intent.as_ref() {
            match self
                .inner
                .store
                .submit_netconf_target_local(prepared, admitted, attempt.caller)
                .await
            {
                AuditAdmission::Applied(receipt) if attempt.accept_known(&receipt) => {
                    return self.complete_known(attempt).await;
                }
                _ => return TargetReply::Unknown,
            }
        }
        match self
            .inner
            .store
            .lookup_audit_operation(&attempt.handle, attempt.caller)
            .await
        {
            Ok(Some(receipt))
                if matches!(
                    receipt.state(),
                    AuditOperationState::TargetV1(_) | AuditOperationState::Rejected
                ) =>
            {
                // This known-only route authenticates the receipt's full result
                // against the original preparation. It cannot submit an effect.
                match self
                    .inner
                    .store
                    .submit_netconf_target_local(prepared, &receipt, attempt.caller)
                    .await
                {
                    AuditAdmission::Applied(receipt) if attempt.accept_known(&receipt) => {
                        self.complete_known(attempt).await
                    }
                    _ => TargetReply::Unknown,
                }
            }
            // An absent/pruned/expired row or unresolved Intent cannot authorize
            // a replacement request or a second effect. The retained authority
            // reconciles its original obligation under its fixed expiry.
            _ => TargetReply::Unknown,
        }
    }

    async fn complete_known(&self, attempt: &mut TargetAttempt) -> TargetReply {
        let Some(receipt) = attempt.known.as_ref() else {
            return TargetReply::Unknown;
        };
        if !attempt.completion_settled
            && self
                .inner
                .store
                .complete_required_audit_outcome(receipt, attempt.caller)
                .await
                .is_ok()
        {
            attempt.completion_settled = true;
        }
        // Failure here must never downgrade a known target result or rejection.
        // The retained terminal/checkpoint obligation fences later effects.
        TargetReply::Known {
            receipt: Box::new(receipt.clone()),
            completion_pending: !attempt.completion_settled,
        }
    }
}

struct SharedProvider<P: ?Sized>(Arc<P>);

#[async_trait::async_trait]
impl<P: KeyProvider + ?Sized> KeyProvider for SharedProvider<P> {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        self.0.get_active_key(purpose, tenant).await
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        self.0.get_key_by_id(key_id).await
    }

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        self.0.rotate_key(purpose, tenant).await
    }
}

impl fmt::Debug for NetconfAuditStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfAuditStore(<redacted>)")
    }
}

pub(super) struct BoundIntent {
    request_id: RequestId,
    caller: AuditCaller,
    event: ManagementAuditEventRecord,
}

pub(super) struct TargetAttempt {
    request_id: Option<RequestId>,
    authority: Arc<Authority>,
    handle: AuditOperationHandle,
    prepared: Option<PreparedTargetMutation>,
    caller: AuditCaller,
    started: bool,
    known: Option<AuditOperationReceipt>,
    completion_settled: bool,
    admission_refusal: Option<AuditAuthorityError>,
    session: Option<super::session_lifetime::SessionReference>,
    lock: Option<Box<LockTransition>>,
    lock_ready: bool,
    // An SDK owner clone observes transport invalidation; it is not a transport
    // owner and cannot keep the transport's final-Drop lifetime alive.
    running_owner: Option<NetconfSessionOwner>,
    // Only fresh Running Intent admission uses the original request deadline.
    // Acknowledged/known originals retain their separate recovery obligation.
    running_admission_deadline: Option<std::time::Instant>,
    acknowledged_intent: Option<AuditOperationReceipt>,
    // Set only by prepare_cleanup after actual inactive-session SDK preparation.
    cleanup: bool,
    // Retained before the no-effect retirement await. An older definite refusal
    // cannot hide a later cancelled or indeterminate durable retirement.
    cleanup_retirement_pending: bool,
    published_commit: Option<Box<opc_config_model::CommitResult>>,
}

struct LockTransition {
    prepared: PreparedNetconfLock,
    datastore: NetconfLockDatastore,
    release: bool,
}

pub(super) struct LockPublication<'a> {
    pub(super) prepared: &'a PreparedNetconfLock,
    pub(super) receipt: &'a AuditOperationReceipt,
    pub(super) session: &'a super::session_lifetime::SessionReference,
    pub(super) datastore: NetconfLockDatastore,
    pub(super) release: bool,
}

impl TargetAttempt {
    pub(super) fn requires_lock_publication(&self) -> bool {
        self.lock.is_some()
            && self.admission_refusal.is_none()
            && self
                .known
                .as_ref()
                .is_none_or(|receipt| !matches!(receipt.state(), AuditOperationState::Rejected))
            && self
                .session
                .as_ref()
                .is_some_and(|session| !session.is_revoked())
    }

    pub(super) fn lock_publication(&self) -> Option<LockPublication<'_>> {
        let lock = self.lock.as_ref()?;
        let receipt = self.known.as_ref()?;
        if !self.completion_settled || !matches!(receipt.state(), AuditOperationState::TargetV1(_))
        {
            return None;
        }
        Some(LockPublication {
            prepared: &lock.prepared,
            receipt,
            session: self.session.as_ref()?,
            datastore: lock.datastore,
            release: lock.release,
        })
    }

    pub(super) fn mark_lock_published(&mut self) {
        self.lock = None;
        self.lock_ready = true;
    }

    pub(super) fn lock_ready(&self) -> bool {
        self.lock_ready
    }

    pub(super) fn bind_running_session(
        &mut self,
        session: super::session_lifetime::SessionReference,
        deadline: std::time::Instant,
    ) {
        self.bind_session(session);
        self.running_admission_deadline = Some(deadline);
    }

    pub(super) fn bind_session(&mut self, session: super::session_lifetime::SessionReference) {
        self.session = Some(session);
    }
    pub(super) fn request_id(&self) -> Option<RequestId> {
        self.request_id
    }

    pub(super) fn handle(&self) -> &AuditOperationHandle {
        &self.handle
    }

    pub(super) fn caller(&self) -> AuditCaller {
        self.caller
    }

    // Used only for this session's closed EndSession preparation. A known
    // rejection, revoked token or terminal record alone never frees its slot.
    pub(super) fn applied_cleanup_settled(&self) -> bool {
        self.completion_settled
            && self.known.as_ref().is_some_and(|receipt| {
                matches!(receipt.state(), AuditOperationState::TargetV1(result)
                if matches!(result.outcome(), NetconfAppliedOutcome::Lifecycle { .. }))
            })
    }

    pub(super) fn rejected_cleanup_settled(&self) -> bool {
        self.cleanup
            && self.completion_settled
            && self
                .known
                .as_ref()
                .is_some_and(|r| r.state() == AuditOperationState::Rejected)
    }

    pub(super) fn completion_settled(&self) -> bool {
        self.completion_settled
    }

    pub(super) fn admission_refused(&self) -> bool {
        self.admission_refusal.is_some() && !self.cleanup_retirement_pending
    }

    /// Inspect only worker-owned progress after a panic/report failure. This
    /// never replaces an authenticated result with the reporting failure.
    pub(super) fn retained_reply(&self) -> TargetReply {
        if let Some(receipt) = &self.known {
            return TargetReply::Known {
                receipt: Box::new(receipt.clone()),
                completion_pending: !self.completion_settled,
            };
        }
        if self.cleanup_retirement_pending {
            return TargetReply::Unknown;
        }
        if let Some(refusal) = self.admission_refusal {
            return TargetReply::Refused(refusal);
        }
        if self.started {
            TargetReply::Unknown
        } else {
            TargetReply::Refused(AuditAuthorityError::Unavailable)
        }
    }

    pub(super) fn published_commit(&self) -> Option<&opc_config_model::CommitResult> {
        self.published_commit.as_deref()
    }

    pub(super) fn mark_running_published(&mut self, result: opc_config_model::CommitResult) {
        self.published_commit = Some(Box::new(result));
    }

    pub(super) fn running_publication(&self) -> Option<super::running::RunningPublication> {
        let AuditOperationState::TargetV1(result) = self.known.as_ref()?.state() else {
            return None;
        };
        let NetconfAppliedOutcome::RunningReplaced {
            tx_id,
            running_version,
            plaintext_digest,
        } = result.outcome()
        else {
            return None;
        };
        Some(super::running::RunningPublication::new(
            tx_id,
            running_version,
            plaintext_digest,
            self.caller,
            self.request_id,
        ))
    }

    pub(super) fn requires_running_publication(&self) -> bool {
        self.running_publication().is_some() && self.published_commit.is_none()
    }

    fn accept_known(&mut self, receipt: &AuditOperationReceipt) -> bool {
        if receipt.handle() != &self.handle
            || !matches!(
                receipt.state(),
                AuditOperationState::TargetV1(_) | AuditOperationState::Rejected
            )
            || self
                .known
                .as_ref()
                .is_some_and(|known| known.state() != receipt.state())
        {
            return false;
        }
        self.known = Some(receipt.clone());
        self.admission_refusal = None;
        self.cleanup_retirement_pending = false;
        // The SDK validated this closed preparation against this exact known
        // result before accepting it. Only the bounded receipt is needed for
        // subsequent completion; do not retain completed encrypted payloads.
        // Cleanup retains its small signed original until slot retirement or
        // an authenticated successor replaces it. Other completed encrypted
        // target payloads keep the existing release behavior.
        if !self.cleanup {
            self.prepared = None;
        }
        self.running_owner = None;
        self.running_admission_deadline = None;
        self.acknowledged_intent = None;
        true
    }
}

pub(super) enum TargetReply {
    /// No target mutation was admitted by this call; prior attempts remain distinct.
    Refused(AuditAuthorityError),
    /// Original outcome remains unknown; retain it and forbid replacement.
    Unknown,
    /// Authenticated original outcome survives later completion/report failure.
    Known {
        receipt: Box<AuditOperationReceipt>,
        completion_pending: bool,
    },
}
