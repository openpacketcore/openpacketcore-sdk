//! Local recovery capabilities for original retained confirmed rollback.

use std::sync::{Arc, Mutex};

use super::{
    AuditAuthorityError, AuditCaller, AuditPrivacyProjection, AuditPrivacyPurpose,
    NetconfDeviceOwner, NetconfPendingConfirmation, NetconfWorkerBinding, PreparedTargetMutation,
    ProjectedAuditEvent,
};

/// Retained cause selected by an authenticated SDK read, never caller input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetconfRollbackCause {
    /// The original confirmed deadline has elapsed.
    Timeout,
    /// The original nonpersistent owner's session cleanup has applied.
    SessionLoss,
    /// An explicit new device incarnation retained reboot cleanup.
    DeviceReboot,
}

/// Recovery-only scope under an exact SDK worker and retained device. This cannot open
/// sessions, acquire locks, stage configuration or manufacture client authority.
/// Every new read checks current retained device ownership and audit obligations.
#[derive(Clone)]
pub struct NetconfRecoveryOwner {
    pub(crate) worker: NetconfWorkerBinding,
    pub(crate) authority: crate::ConfigConsensusIdentity,
    pub(crate) profile_incarnation: [u8; 16],
    pub(crate) device_incarnation: [u8; 16],
    pub(crate) caller: AuditCaller,
    pub(crate) cache: NetconfRecoveryCache,
}

impl NetconfDeviceOwner {
    /// Derive this device's separate recovery scope. This neither checks current
    /// liveness nor grants serving authority after cleanup. Device-owner clones
    /// share one bounded original rollback preparation.
    pub fn recovery_owner(&self) -> NetconfRecoveryOwner {
        NetconfRecoveryOwner {
            worker: self.worker.clone(),
            authority: self.authority,
            profile_incarnation: self.profile_incarnation,
            device_incarnation: self.device_incarnation,
            caller: self.caller,
            cache: self.recovery.clone(),
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct NetconfRecoveryCache(Arc<Mutex<Option<NetconfRollbackRead>>>);

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NetconfRollbackView {
    pub(crate) authority: crate::ConfigConsensusIdentity,
    pub(crate) profile_incarnation: [u8; 16],
    pub(crate) device_incarnation: [u8; 16],
    pub(crate) administrator: AuditCaller,
    pub(crate) projection: super::AuditToken,
    pub(crate) caller: AuditCaller,
    pub(crate) pending: NetconfPendingConfirmation,
    pub(crate) previous_device: [u8; 16],
    pub(crate) cause: NetconfRollbackCause,
    pub(crate) original_deadline: i64,
    pub(crate) tentative_transaction: opc_types::TxId,
    pub(crate) running_version: u64,
    pub(crate) parent_version: u64,
    pub(crate) schema: opc_types::SchemaDigest,
    pub(crate) plaintext_digest: [u8; 32],
    pub(crate) encrypted: Vec<u8>,
}

struct NetconfRollbackAttempt {
    prepared: PreparedTargetMutation,
    predecessor: Option<super::AuditOperationHandle>,
}

struct NetconfRollbackState {
    view: NetconfRollbackView,
    attempt: Mutex<Option<NetconfRollbackAttempt>>,
}

/// One original retained rollback parent and cause. All clones share the exact
/// first prepared operation. Reading grants no effect authority; an admitted
/// intent and its independent checkpoint must precede application.
#[derive(Clone)]
pub struct NetconfRollbackRead(Arc<NetconfRollbackState>);

impl NetconfRollbackRead {
    /// Exact pending confirmation selected by the retained read.
    pub fn pending(&self) -> NetconfPendingConfirmation {
        self.0.view.pending
    }

    /// Original caller obtained from the authenticated pending effect. Use it
    /// only with this read's exact retained mutation for required audit admission,
    /// submission and recovery; it is not a new client authentication result.
    pub fn original_caller(&self) -> AuditCaller {
        self.0.view.caller
    }

    /// Original retained cause; elapsed RPC time does not select a cause.
    pub fn cause(&self) -> NetconfRollbackCause {
        self.0.view.cause
    }

    /// Original confirmed deadline, in Unix seconds. Preparation cannot extend it.
    pub fn original_deadline(&self) -> i64 {
        self.0.view.original_deadline
    }

    /// Current tentative running revision that the rollback must succeed.
    pub fn running_version(&self) -> u64 {
        self.0.view.running_version
    }

    /// Original tentative transaction, protected data rather than diagnostics.
    pub fn tentative_transaction(&self) -> opc_types::TxId {
        self.0.view.tentative_transaction
    }

    /// Retained parent revision used by its authenticated encryption AAD.
    pub fn parent_version(&self) -> u64 {
        self.0.view.parent_version
    }

    /// Schema of the exact original parent configuration.
    pub fn schema(&self) -> opc_types::SchemaDigest {
        self.0.view.schema
    }

    /// Encrypted original parent. Decrypt through the existing provider with
    /// expected tenant and schema before model validation; never log these bytes.
    pub fn encrypted_configuration(&self) -> &[u8] {
        &self.0.view.encrypted
    }

    /// Preserve this exact operation after cancellation or uncertain delivery.
    /// This local read does not refresh a parent, expiry, event or caller and
    /// remains available after device changes and audit-reporting failures.
    pub fn original(&self) -> Result<Option<PreparedTargetMutation>, AuditAuthorityError> {
        self.0
            .attempt
            .lock()
            .map(|attempt| attempt.as_ref().map(|current| current.prepared.clone()))
            .map_err(|_| AuditAuthorityError::Unavailable)
    }

    pub(crate) fn view(&self) -> &NetconfRollbackView {
        &self.0.view
    }

    pub(crate) fn verify_owner(
        &self,
        owner: &NetconfRecoveryOwner,
    ) -> Result<(), AuditAuthorityError> {
        let view = self.view();
        if view.authority != owner.authority
            || view.profile_incarnation != owner.profile_incarnation
            || view.device_incarnation != owner.device_incarnation
            || view.administrator != owner.caller
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let slot = owner
            .cache
            .0
            .lock()
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        if slot
            .as_ref()
            .is_none_or(|read| !Arc::ptr_eq(&read.0, &self.0))
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(())
    }

    pub(crate) fn project_event(
        &self,
        privacy: &dyn AuditPrivacyProjection,
        mut event: ProjectedAuditEvent,
    ) -> Result<ProjectedAuditEvent, AuditAuthorityError> {
        let view = self.view();
        if event.caller != view.administrator
            || event.projection != view.projection
            || event.transport != crate::ManagementAuditTransportCode::Internal
            || event.operation != crate::ManagementAuditOperationCode::Exec
            || event.outcome != crate::ManagementAuditOutcomeCode::Intent
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        // The embedding authenticates the recovery administrator, while the
        // retained pending effect supplies its original projected client. No
        // raw principal or client credential is reconstructed or accepted here.
        event.request = privacy.project(
            AuditPrivacyPurpose::Request,
            &[
                b"netconf-confirmed-recovery-v1",
                &view.caller.tenant.0,
                &view.caller.principal.0,
                &view.pending.value,
                &event.request.0,
            ],
        )?;
        event.transaction = Some(privacy.project(
            AuditPrivacyPurpose::Transaction,
            &[
                b"netconf-confirmed-recovery-v1",
                &view.caller.tenant.0,
                &view.caller.principal.0,
                view.tentative_transaction.as_uuid().as_bytes(),
            ],
        )?);
        event.caller = view.caller;
        Ok(event)
    }

    pub(crate) fn verify_tenant(
        &self,
        privacy: &dyn AuditPrivacyProjection,
        tenant: &opc_types::TenantId,
    ) -> Result<(), AuditAuthorityError> {
        if privacy.project(AuditPrivacyPurpose::Tenant, &[tenant.as_str().as_bytes()])?
            != self.view().caller.tenant
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(())
    }

    pub(crate) fn verify_event(
        &self,
        event: &ProjectedAuditEvent,
    ) -> Result<(), AuditAuthorityError> {
        if event.caller != self.view().caller
            || event.projection != self.view().projection
            || event.transport != crate::ManagementAuditTransportCode::Internal
            || event.operation != crate::ManagementAuditOperationCode::Exec
            || event.outcome != crate::ManagementAuditOutcomeCode::Intent
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(())
    }

    pub(crate) fn retain(
        &self,
        owner: &NetconfRecoveryOwner,
        prepared: PreparedTargetMutation,
    ) -> Result<PreparedTargetMutation, AuditAuthorityError> {
        self.verify_owner(owner)?;
        self.verify_event(&prepared.handle.body.event)?;
        let mut slot = self
            .0
            .attempt
            .lock()
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        if let Some(original) = &*slot {
            return Self::same_preparation(&original.prepared, &prepared);
        }
        *slot = Some(NetconfRollbackAttempt {
            prepared: prepared.clone(),
            predecessor: None,
        });
        Ok(prepared)
    }
}

impl NetconfRecoveryOwner {
    // The caller has already checked current retained scope and settled audit
    // debt. Keep one current read/attempt; callers' old clones remain truthful.
    pub(crate) fn remember(
        &self,
        view: NetconfRollbackView,
    ) -> Result<NetconfRollbackRead, AuditAuthorityError> {
        if view.authority != self.authority
            || view.profile_incarnation != self.profile_incarnation
            || view.device_incarnation != self.device_incarnation
            || view.administrator != self.caller
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let mut slot = self
            .cache
            .0
            .lock()
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        if let Some(original) = &*slot {
            if original.pending() == view.pending {
                if original.view() != &view {
                    return Err(AuditAuthorityError::BindingMismatch);
                }
                return Ok(original.clone());
            }
            // A different pending operation requires a newer tentative revision.
            // A delayed read must not discard its retained original attempt.
            if view.running_version <= original.running_version() {
                return Err(AuditAuthorityError::RollbackDetected);
            }
        }
        let read = NetconfRollbackRead(Arc::new(NetconfRollbackState {
            view,
            attempt: Mutex::new(None),
        }));
        *slot = Some(read.clone());
        Ok(read)
    }
}

/// Original frozen parent plus an attested, encrypted rollback successor.
/// No user credential or caller-selected internal cause is accepted here.
pub struct NetconfRollback<'a> {
    pub(crate) frozen: &'a NetconfRollbackRead,
    pub(crate) commit: crate::AttestedConfigCommit,
    pub(crate) provider: &'a dyn opc_key::KeyProvider,
}

impl<'a> NetconfRollback<'a> {
    /// Bind the original read and existing provider before required admission.
    pub fn new(
        frozen: &'a NetconfRollbackRead,
        commit: crate::AttestedConfigCommit,
        provider: &'a dyn opc_key::KeyProvider,
    ) -> Self {
        Self {
            frozen,
            commit,
            provider,
        }
    }
}

macro_rules! redacted {
    ($($ty:ty),+ $(,)?) => {$(
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "(<redacted>)"))
            }
        }
    )+};
}
redacted!(
    NetconfRecoveryOwner,
    NetconfRollbackRead,
    NetconfRollback<'_>,
    NetconfRollbackSuccessor<'_>
);

impl NetconfRollbackRead {
    fn same_preparation(
        original: &PreparedTargetMutation,
        proposed: &PreparedTargetMutation,
    ) -> Result<PreparedTargetMutation, AuditAuthorityError> {
        let mut effect = proposed.effect.clone();
        effect.expires_at = original.effect.expires_at;
        if original.handle.body.event != proposed.handle.body.event
            || original.effect != effect
            || original
                .handle
                .body
                .expires_at
                .checked_sub(original.handle.body.issued_at)
                != proposed
                    .handle
                    .body
                    .expires_at
                    .checked_sub(proposed.handle.body.issued_at)
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(original.clone())
    }

    pub(crate) fn successor_context(
        &self,
        owner: &NetconfRecoveryOwner,
        previous: &PreparedTargetMutation,
        event: &ProjectedAuditEvent,
    ) -> Result<(), AuditAuthorityError> {
        self.verify_owner(owner)?;
        self.verify_event(event)?;
        self.verify_event(&previous.handle.body.event)?;
        if event.request == previous.handle.body.event.request {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let slot = self
            .0
            .attempt
            .lock()
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        let current = slot.as_ref().ok_or(AuditAuthorityError::BindingMismatch)?;
        if current.prepared == *previous {
            return Ok(());
        }
        if current.predecessor.as_ref() == Some(previous.handle()) {
            // Selection already happened. Recover that exact original without
            // calling the provider, refreshing expiry or accepting new content.
            return Err(AuditAuthorityError::RecoveryRequired);
        }
        Err(AuditAuthorityError::BindingMismatch)
    }

    pub(crate) fn verify_rejected_predecessor(
        &self,
        previous: &PreparedTargetMutation,
        ledger: &super::ledger::LedgerState,
        key: &crate::AuditKey,
        now: i64,
    ) -> Result<(), AuditAuthorityError> {
        self.verify_event(&previous.handle.body.event)?;
        previous.verify_effect(key)?;
        if ledger.recover_target(key, previous.handle(), self.original_caller())? != *previous {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let operation = ledger
            .operations
            .iter()
            .find(|operation| operation.handle == previous.handle)
            .ok_or(AuditAuthorityError::BindingMismatch)?;
        if now < previous.handle.body.expires_at
            || operation.state != super::AuditOperationState::Rejected
            || !operation.terminal_recorded
            || ledger
                .continuity
                .as_ref()
                .and_then(|chain| chain.checkpoint.as_ref())
                .is_none_or(|checkpoint| checkpoint.sequence() < operation.last_sequence)
        {
            return Err(AuditAuthorityError::RecoveryRequired);
        }
        Ok(())
    }

    pub(crate) fn retain_successor(
        &self,
        owner: &NetconfRecoveryOwner,
        previous: &PreparedTargetMutation,
        prepared: PreparedTargetMutation,
        ledger: &super::ledger::LedgerState,
        key: &crate::AuditKey,
        now: i64,
    ) -> Result<PreparedTargetMutation, AuditAuthorityError> {
        self.verify_owner(owner)?;
        self.verify_event(&prepared.handle.body.event)?;
        prepared.verify_effect(key)?;
        self.verify_rejected_predecessor(previous, ledger, key, now)?;
        if prepared.handle.body.event.request == previous.handle.body.event.request
            || prepared.handle.body.issued_at < previous.handle.body.expires_at
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let mut slot = self
            .0
            .attempt
            .lock()
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        let current = slot.as_ref().ok_or(AuditAuthorityError::BindingMismatch)?;
        if current.prepared == *previous {
            *slot = Some(NetconfRollbackAttempt {
                prepared: prepared.clone(),
                predecessor: Some(previous.handle().clone()),
            });
            return Ok(prepared);
        }
        if current.predecessor.as_ref() != Some(previous.handle()) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Self::same_preparation(&current.prepared, &prepared)
    }
}

/// A separately authorized retry of an expired, settled rejected rollback.
/// The exact previous attempt must belong to the original frozen read. Neither
/// elapsed time nor an absent result proves rejection. The original confirmed
/// deadline and parent are unchanged; a new request cannot discover an old result.
pub struct NetconfRollbackSuccessor<'a> {
    pub(crate) previous: &'a PreparedTargetMutation,
    pub(crate) rollback: NetconfRollback<'a>,
}

impl<'a> NetconfRollbackSuccessor<'a> {
    /// Supply the exact previous preparation and an attested successor for the
    /// same original read. This constructs input only, without recovery authority.
    pub fn new(previous: &'a PreparedTargetMutation, rollback: NetconfRollback<'a>) -> Self {
        Self { previous, rollback }
    }
}

// One bounded entry per exact worker; the capability keeps only a weak link.
#[derive(Default)]
pub(crate) struct NetconfRecoveryRegistry(Mutex<Option<NetconfRecoveryEntry>>);

struct NetconfRecoveryEntry {
    owner: NetconfRecoveryOwner,
    sequence: u64,
}

impl NetconfRecoveryRegistry {
    // Call only after a current authenticated retained device read, settled
    // obligations and independent checkpoint validation. A delayed older read
    // cannot replace the registry installed by a newer completed opening.
    pub(crate) fn bind<T: Send + Sync + 'static>(
        &self,
        worker: &Arc<T>,
        owner: NetconfRecoveryOwner,
        sequence: u64,
    ) -> Result<NetconfRecoveryOwner, AuditAuthorityError> {
        if !owner.worker.belongs_to(worker) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let mut slot = self
            .0
            .lock()
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        if let Some(current) = slot.as_mut() {
            if !current.owner.worker.belongs_to(worker)
                || current.owner.authority != owner.authority
                || current.owner.profile_incarnation != owner.profile_incarnation
            {
                return Err(AuditAuthorityError::BindingMismatch);
            }
            if sequence < current.sequence {
                return Err(AuditAuthorityError::RollbackDetected);
            }
            if current.owner.device_incarnation == owner.device_incarnation {
                if current.owner.caller != owner.caller {
                    return Err(AuditAuthorityError::BindingMismatch);
                }
                current.sequence = sequence;
                return Ok(current.owner.clone());
            }
            if sequence == current.sequence {
                return Err(AuditAuthorityError::BindingMismatch);
            }
        }
        *slot = Some(NetconfRecoveryEntry {
            owner: owner.clone(),
            sequence,
        });
        Ok(owner)
    }
}
