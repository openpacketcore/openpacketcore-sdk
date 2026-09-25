//! Public management authority using the same owner, proposal queue and read barrier.

use super::{derive_durable_request_id, ConsensusConfigStore};
use crate::audit_authority::ledger::{HandleBody, LedgerState};
use crate::audit_authority::{
    AuditAdmission, AuditAuthorityError, AuditCaller, AuditLedgerLimits, AuditOperationBinding,
    AuditOperationHandle, AuditOperationReceipt, AuditPrivacyProjection, AuditPrivacyPurpose,
    PreparedAuditedMutation, ProjectedAuditEvent,
};
use crate::consensus::audit::AuditCommand;
use crate::consensus::audit_mutation::AuditedConfigEffect;
use crate::consensus::{ConfigMutationIntent, PreparedConfigCommit};
use crate::{AttestedConfigCommit, ManagementAuditEventRecord};

impl ConsensusConfigStore {
    /// Provision the bounded ledger through configuration consensus. Identical
    /// retries are idempotent; changing its identity, projection or limits fails.
    /// This never creates another persistence owner or changes configuration version.
    pub async fn initialize_audit_authority(
        &self,
        privacy: &dyn AuditPrivacyProjection,
        limits: AuditLedgerLimits,
    ) -> Result<(), AuditAuthorityError> {
        let projection = privacy.project(AuditPrivacyPurpose::KeyIdentity, &[])?;
        let command = if let Some(policy) = &self.inner.audit_continuity {
            AuditCommand::InitializeWithContinuity {
                projection,
                limits,
                initial_epoch: policy.initial_epoch,
            }
        } else {
            AuditCommand::Initialize { projection, limits }
        };
        let request = derive_durable_request_id(self.inner.identity, b"audit-initialize", &[]);
        self.submit_request(request, ConfigMutationIntent::ManagementAudit(command))
            .await
            .map_err(|_| AuditAuthorityError::Unavailable)?
            .result
            .map_err(super::super::audit::map_failure)?;
        if self.inner.audit_continuity.is_some() {
            self.provision_audit_checkpoint().await?;
        }
        Ok(())
    }

    /// Project a standalone intent before any queue or storage. This handle can
    /// only be rejected or completed as a non-configuration operation; it cannot
    /// authorize a caller-asserted configuration commit result.
    pub fn prepare_audit_intent(
        &self,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        base_version: opc_types::ConfigVersion,
        canonical_operation: &[u8],
        lifetime: std::time::Duration,
    ) -> Result<AuditOperationHandle, AuditAuthorityError> {
        if event.outcome() != crate::ManagementAuditOutcomeCode::Intent {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let event = ProjectedAuditEvent::project(privacy, event)?;
        let binding = AuditOperationBinding::project(
            privacy,
            &event,
            base_version.get(),
            canonical_operation,
        )?;
        self.issue_audit_handle(event, binding, None, lifetime)
    }

    /// Bind an authenticated encrypted commit, including its exact parent,
    /// candidate, mode and confirmed-resolution metadata, before intent admission.
    /// A changed payload cannot use the resulting handle. Cancel/rollback commits
    /// use the same atomic successor representation as ordinary configuration writes.
    pub fn prepare_audited_commit(
        &self,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        commit: AttestedConfigCommit,
        lifetime: std::time::Duration,
    ) -> Result<PreparedAuditedMutation, AuditAuthorityError> {
        let (record, audit, resolution) = commit.into_parts();
        let base = record
            .version
            .get()
            .checked_sub(1)
            .ok_or(AuditAuthorityError::InvalidInput)?;
        let commit = PreparedConfigCommit::prepare(record, audit, self.inner.backend.audit_key())
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        self.prepare_audited_effect(
            privacy,
            event,
            base,
            AuditedConfigEffect::Append {
                commit: Box::new(commit),
                resolution,
            },
            lifetime,
        )
    }

    /// Bind one exact pending confirmation and base version before intent admission.
    pub fn prepare_audited_confirmation(
        &self,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        tx_id: opc_types::TxId,
        base_version: opc_types::ConfigVersion,
        lifetime: std::time::Duration,
    ) -> Result<PreparedAuditedMutation, AuditAuthorityError> {
        self.prepare_audited_effect(
            privacy,
            event,
            base_version.get(),
            AuditedConfigEffect::Confirm { tx_id },
            lifetime,
        )
    }

    /// Bind an exact rollback-point mutation and base version. The existing
    /// validated label contract is preserved; the label is not audit identity
    /// and is never included in this operation's diagnostic representation.
    pub fn prepare_audited_rollback_point(
        &self,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        tx_id: opc_types::TxId,
        base_version: opc_types::ConfigVersion,
        label: Option<String>,
        lifetime: std::time::Duration,
    ) -> Result<PreparedAuditedMutation, AuditAuthorityError> {
        let label = label
            .map(super::super::types::ValidatedRollbackLabel::try_new)
            .transpose()
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        self.prepare_audited_effect(
            privacy,
            event,
            base_version.get(),
            AuditedConfigEffect::RollbackPoint { tx_id, label },
            lifetime,
        )
    }

    fn prepare_audited_effect(
        &self,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        base: u64,
        effect: AuditedConfigEffect,
        lifetime: std::time::Duration,
    ) -> Result<PreparedAuditedMutation, AuditAuthorityError> {
        let digest = effect.digest(self.inner.backend.audit_key())?;
        let event = ProjectedAuditEvent::project(privacy, event)?;
        let binding = AuditOperationBinding::project(privacy, &event, base, &digest)?;
        Ok(PreparedAuditedMutation {
            handle: self.issue_audit_handle(event, binding, Some(digest), lifetime)?,
            effect,
        })
    }

    fn issue_audit_handle(
        &self,
        event: ProjectedAuditEvent,
        binding: AuditOperationBinding,
        mutation: Option<[u8; 32]>,
        lifetime: std::time::Duration,
    ) -> Result<AuditOperationHandle, AuditAuthorityError> {
        if lifetime.subsec_nanos() != 0 || !(1..=3600).contains(&lifetime.as_secs()) {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let issued_at = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        let expires_at = issued_at
            .checked_add(lifetime.as_secs() as i64)
            .ok_or(AuditAuthorityError::InvalidInput)?;
        AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity: self.inner.identity,
                binding,
                event,
                issued_at,
                expires_at,
                nonce: *uuid::Uuid::new_v4().as_bytes(),
                key_epoch: self.inner.backend.audit_key().epoch(),
                mutation,
            },
            self.inner.backend.audit_key(),
        )
    }

    /// Admit the exact prepared intent and reserve its outcome/terminal capacity.
    /// Unknown or rejected admission is never permission to submit configuration.
    /// Retain the handle before calling; cancellation does not retract accepted work.
    pub async fn admit_audit_operation(
        &self,
        handle: &AuditOperationHandle,
        caller: AuditCaller,
    ) -> AuditAdmission {
        self.audit_operation_command(
            handle,
            caller,
            b"audit-intent",
            ConfigMutationIntent::ManagementAudit(AuditCommand::Intent(handle.clone())),
        )
        .await
    }

    /// Submit only with an acknowledged receipt for the exact intent. The ledger
    /// and authoritative configuration result change in one state-machine transaction.
    /// Accepted proposals remain owned by the existing consensus supervisor if
    /// this future is cancelled. Recover by looking up the retained handle.
    pub async fn submit_audited_mutation(
        &self,
        prepared: &PreparedAuditedMutation,
        admitted: &AuditOperationReceipt,
        caller: AuditCaller,
    ) -> AuditAdmission {
        if admitted.handle != prepared.handle
            || prepared
                .verify_effect(self.inner.backend.audit_key())
                .is_err()
        {
            return AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch);
        }
        self.audit_operation_command(
            &prepared.handle,
            caller,
            b"audit-config",
            ConfigMutationIntent::AuditedMutation(prepared.clone()),
        )
        .await
    }

    /// Durably close an uncommitted intent. A racing known commit is returned as
    /// committed by lookup and can never be rewritten as rejection.
    pub async fn reject_audit_operation(
        &self,
        handle: &AuditOperationHandle,
        caller: AuditCaller,
    ) -> AuditAdmission {
        self.audit_operation_command(
            handle,
            caller,
            b"audit-reject",
            ConfigMutationIntent::ManagementAudit(AuditCommand::Reject(handle.clone())),
        )
        .await
    }

    /// Fulfil the reserved terminal obligation after an authoritative outcome.
    /// Failure or response loss cannot alter that outcome; lookup remains available.
    pub async fn finish_audit_operation(
        &self,
        handle: &AuditOperationHandle,
        caller: AuditCaller,
    ) -> AuditAdmission {
        self.audit_operation_command(
            handle,
            caller,
            b"audit-terminal",
            ConfigMutationIntent::ManagementAudit(AuditCommand::Terminal(handle.clone())),
        )
        .await
    }

    /// Complete the exact known outcome's terminal record and independent
    /// checkpoint when this store requires audit continuity. Without that
    /// profile, terminal completion retains its existing supervisor lifecycle.
    ///
    /// An error preserves the supplied authoritative outcome and retained debt;
    /// it cannot turn a known commit into rejection or authorize another effect.
    /// New mutations remain refused until the debt is checkpointed. Recovery
    /// retries this same operation without changing its original expiry.
    pub async fn complete_required_audit_outcome(
        &self,
        receipt: &AuditOperationReceipt,
        caller: AuditCaller,
    ) -> Result<(), AuditAuthorityError> {
        receipt
            .handle
            .verify(self.inner.backend.audit_key(), self.inner.identity, caller)?;
        if self.inner.audit_continuity.is_none() {
            return Ok(());
        }
        let terminal = match self.finish_audit_operation(&receipt.handle, caller).await {
            AuditAdmission::Applied(terminal)
                if terminal.state() == receipt.state() && terminal.terminal_recorded() =>
            {
                terminal
            }
            AuditAdmission::Rejected(error) => return Err(error),
            _ => return Err(AuditAuthorityError::Unavailable),
        };
        if terminal.state() == crate::audit_authority::AuditOperationState::Intent {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        self.checkpoint_audit_tail().await
    }

    /// Admit an intent only through this node's current local leader. No
    /// management mutation is forwarded after deposition. Reads may still use
    /// the ordinary authenticated quorum barrier.
    pub async fn admit_audit_operation_local(
        &self,
        handle: &AuditOperationHandle,
        caller: AuditCaller,
    ) -> AuditAdmission {
        self.audit_operation_command_with_route(
            handle,
            caller,
            b"audit-intent",
            ConfigMutationIntent::ManagementAudit(AuditCommand::Intent(handle.clone())),
            true,
        )
        .await
    }

    /// Apply the exact admitted configuration effect only on this node's
    /// current leader. A possibly admitted effect returns Unknown and retains
    /// the same durable operation; it must not be blindly resubmitted elsewhere.
    pub async fn submit_audited_mutation_local(
        &self,
        prepared: &PreparedAuditedMutation,
        admitted: &AuditOperationReceipt,
        caller: AuditCaller,
    ) -> AuditAdmission {
        if admitted.handle != prepared.handle
            || prepared
                .verify_effect(self.inner.backend.audit_key())
                .is_err()
        {
            return AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch);
        }
        self.audit_operation_command_with_route(
            &prepared.handle,
            caller,
            b"audit-config",
            ConfigMutationIntent::AuditedMutation(prepared.clone()),
            true,
        )
        .await
    }

    async fn audit_operation_command(
        &self,
        handle: &AuditOperationHandle,
        caller: AuditCaller,
        purpose: &[u8],
        command: ConfigMutationIntent,
    ) -> AuditAdmission {
        self.audit_operation_command_with_route(handle, caller, purpose, command, false)
            .await
    }

    async fn audit_operation_command_with_route(
        &self,
        handle: &AuditOperationHandle,
        caller: AuditCaller,
        purpose: &[u8],
        command: ConfigMutationIntent,
        local_only: bool,
    ) -> AuditAdmission {
        if let Err(error) =
            handle.verify(self.inner.backend.audit_key(), self.inner.identity, caller)
        {
            return AuditAdmission::Rejected(error);
        }
        let request = derive_durable_request_id(self.inner.identity, purpose, &handle.mac);
        // Preflight is known not to admit work. After submission starts any
        // transport/storage uncertainty is conservatively Unknown.
        if super::preflight_config_command_replication_budget(
            self.inner.identity,
            request,
            &command,
        )
        .is_err()
        {
            return AuditAdmission::Rejected(AuditAuthorityError::InvalidInput);
        }
        let ledger = match self.read_audit_ledger().await {
            Ok(ledger) => ledger,
            Err(error) => return AuditAdmission::Rejected(error),
        };
        // A pruned, expired handle cannot reuse an older successful request
        // cache entry as admission. Existing retained receipts remain readable
        // after expiry; only a proven absent operation requires a live handle.
        match ledger.lookup(self.inner.backend.audit_key(), handle, caller) {
            Err(error) => return AuditAdmission::Rejected(error),
            Ok(None) => {
                let now = self
                    .inner
                    .clock
                    .now_utc()
                    .as_offset_datetime()
                    .unix_timestamp();
                if let Err(error) = handle.require_live(now) {
                    return AuditAdmission::Rejected(error);
                }
            }
            Ok(Some(_)) => {}
        }
        if matches!(command, ConfigMutationIntent::AuditedMutation(_))
            && self.inner.audit_continuity.is_some()
        {
            let receipt = match ledger.lookup(self.inner.backend.audit_key(), handle, caller) {
                Ok(Some(receipt)) => receipt,
                _ => return AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch),
            };
            // Exact replay preserves an already authoritative outcome, including
            // while its terminal checkpoint is still outstanding.
            if receipt.state() != crate::audit_authority::AuditOperationState::Intent {
                return AuditAdmission::Applied(receipt);
            }
            if ledger
                .operations
                .iter()
                .any(|op| ledger.mutation_outcome_needs_checkpoint(op))
            {
                return AuditAdmission::Rejected(AuditAuthorityError::RecoveryRequired);
            }
            if let Err(error) = self.checkpoint_audit_tail().await {
                return AuditAdmission::Rejected(error);
            }
        }
        let response = if local_only {
            self.submit_request_on_local_leader(request, command).await
        } else {
            self.submit_request(request, command).await
        };
        match response {
            Err(_) => AuditAdmission::Unknown(handle.clone()),
            Ok(response) => {
                if let Some(proof) = &response.audit_receipt {
                    let receipt = match proof.read_back(
                        self.inner.backend.audit_key(),
                        self.inner.identity,
                        handle,
                        caller,
                    ) {
                        Ok(receipt) => receipt,
                        Err(_) => return AuditAdmission::Unknown(handle.clone()),
                    };
                    // Settled outcomes cannot change. The applying quorum has
                    // already authenticated this result; a later read outage
                    // must not turn it back into an unknown configuration result.
                    // Intent may have since expired/resolved, so refresh it below.
                    if receipt.state() != crate::audit_authority::AuditOperationState::Intent {
                        return AuditAdmission::Applied(receipt);
                    }
                }
                match self.lookup_audit_operation(handle, caller).await {
                    Ok(Some(receipt)) => AuditAdmission::Applied(receipt),
                    Ok(None) => match response.result {
                        Err(failure) => {
                            AuditAdmission::Rejected(super::super::audit::map_failure(failure))
                        }
                        Ok(()) => AuditAdmission::Unknown(handle.clone()),
                    },
                    // Lookup returns Expired only after a quorum read proved no
                    // receipt exists. Preserve that definite refusal when apply
                    // also rejected this command; an outage is still Unknown.
                    Err(AuditAuthorityError::Expired) if response.result.is_err() => {
                        AuditAdmission::Rejected(AuditAuthorityError::Expired)
                    }
                    Err(_) => AuditAdmission::Unknown(handle.clone()),
                }
            }
        }
    }

    /// Authorized, quorum-current lookup. `None` means no admitted operation at
    /// this barrier, not permission to create a new handle. A fixed expired
    /// handle with no retained receipt fails closed even after restart.
    /// `caller` must be derived from trusted authentication, never decoded from
    /// the client's handle or supplied as an unauthenticated request field.
    pub async fn lookup_audit_operation(
        &self,
        handle: &AuditOperationHandle,
        caller: AuditCaller,
    ) -> Result<Option<AuditOperationReceipt>, AuditAuthorityError> {
        handle.verify(self.inner.backend.audit_key(), self.inner.identity, caller)?;
        let ledger = self.read_audit_ledger().await?;
        let receipt = ledger.lookup(self.inner.backend.audit_key(), handle, caller)?;
        if receipt.is_none() {
            handle.require_live(
                self.inner
                    .clock
                    .now_utc()
                    .as_offset_datetime()
                    .unix_timestamp(),
            )?;
        }
        Ok(receipt)
    }

    /// Prepare a denial or other observation with the same durable handle,
    /// fixed expiry and authorized recovery path as an intent. This records only
    /// an observation and can never claim an authoritative configuration commit.
    pub fn prepare_audit_observation(
        &self,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        lifetime: std::time::Duration,
    ) -> Result<AuditOperationHandle, AuditAuthorityError> {
        if event.outcome() == crate::ManagementAuditOutcomeCode::Intent {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let event = ProjectedAuditEvent::project(privacy, event)?;
        let canonical =
            serde_json::to_vec(&event).map_err(|_| AuditAuthorityError::InvalidInput)?;
        let binding = AuditOperationBinding::project(privacy, &event, 0, &canonical)?;
        self.issue_audit_handle(event, binding, None, lifetime)
    }

    /// Recover bounded terminal obligations under this configuration authority.
    /// Run at startup and from the management supervisor. Known outcomes are
    /// completed idempotently. Only expired undecided intents may be rejected;
    /// a configuration proposal racing that rejection is serialized by the same
    /// state machine. No new handle or extended expiry is created.
    /// This is a privileged SDK maintenance port, not a northbound caller API.
    pub async fn reconcile_audit_obligations(
        &self,
        limit: usize,
    ) -> Result<crate::audit_authority::AuditRecoveryProgress, AuditAuthorityError> {
        use crate::audit_authority::{AuditOperationState, AuditRecoveryProgress};
        if !(1..=1024).contains(&limit) {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let ledger = self.read_audit_ledger().await?;
        let now = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        let mut progress = AuditRecoveryProgress::default();
        let mut operations: Vec<_> = ledger
            .operations
            .iter()
            .filter(|op| !op.terminal_recorded || ledger.mutation_outcome_needs_checkpoint(op))
            .cloned()
            .collect();
        // A still-live intent at the front of the ledger must not starve
        // later terminal obligations when the caller uses a small work limit.
        operations.sort_by_key(|op| {
            op.state == AuditOperationState::Intent && op.handle.require_live(now).is_ok()
        });
        for op in operations.into_iter().take(limit) {
            progress.inspected += 1;
            let caller = op.handle.body.binding.caller;
            if op.state == AuditOperationState::Intent {
                if op.handle.require_live(now).is_ok() {
                    progress.pending += 1;
                    continue;
                }
                if !matches!(self.reject_audit_operation(&op.handle,caller).await,
                    AuditAdmission::Applied(ref receipt) if receipt.state() != AuditOperationState::Intent)
                {
                    progress.unknown += 1;
                    continue;
                }
            }
            match self.finish_audit_operation(&op.handle, caller).await {
                AuditAdmission::Applied(ref receipt) if receipt.terminal_recorded() => {
                    if self
                        .complete_required_audit_outcome(receipt, caller)
                        .await
                        .is_ok()
                    {
                        progress.completed += 1;
                    } else {
                        progress.unknown += 1;
                    }
                }
                _ => progress.unknown += 1,
            }
        }
        Ok(progress)
    }

    pub(super) async fn read_audit_ledger(&self) -> Result<LedgerState, AuditAuthorityError> {
        let ledger = self.read_audit_ledger_without_checkpoint().await?;
        self.verify_audit_checkpoint(&ledger).await?;
        Ok(ledger)
    }

    pub(super) async fn read_audit_ledger_without_checkpoint(
        &self,
    ) -> Result<LedgerState, AuditAuthorityError> {
        self.linearizable_barrier()
            .await
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        let backend = self.inner.backend.clone();
        let identity = self.inner.identity;
        super::super::run_backend_sqlite_with_timeout(
            &self.inner.backend,
            self.inner.operation_timeout,
            move |conn, cancellation| {
                cancellation.check_io()?;
                super::super::audit::read_with_keys_sync(
                    conn,
                    backend.audit_key(),
                    backend.management_audit_keys().as_deref(),
                    identity,
                )
            },
        )
        .await
        .map_err(|_| AuditAuthorityError::Unavailable)?
        .ok_or(AuditAuthorityError::Unavailable)
    }
}

impl ConsensusConfigStore {
    fn require_netconf_target_profile(&self) -> Result<(), AuditAuthorityError> {
        if self.inner.audit_continuity.is_none()
            || self
                .inner
                .backend
                .retained_binding
                .as_ref()
                .is_none_or(|binding| {
                    binding.profile() != crate::RetainedConfigProfile::NetconfTargetsV1
                })
        {
            return Err(AuditAuthorityError::Unavailable);
        }
        Ok(())
    }

    fn verify_netconf_target(
        &self,
        prepared: &crate::audit_authority::PreparedTargetMutation,
        caller: AuditCaller,
    ) -> Result<(), AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        prepared
            .handle()
            .verify(self.inner.backend.audit_key(), self.inner.identity, caller)?;
        prepared.verify_effect(self.inner.backend.audit_key())
    }

    /// Recover the original encrypted target description using its original
    /// handle and independently authenticated caller. This quorum-current read
    /// verifies the independent checkpoint and never submits an effect, creates
    /// another request, or extends expiry. Retained results remain recoverable
    /// after expiry; an absent expired operation fails closed.
    ///
    /// `caller` must come from trusted authentication, not from the handle or a
    /// client-supplied field. Returned bytes are protected recovery data and must
    /// not be placed in diagnostics. Only the independently admitted retained
    /// NETCONF profile with audit continuity supports this operation.
    pub async fn recover_netconf_target(
        &self,
        handle: &AuditOperationHandle,
        caller: AuditCaller,
    ) -> Result<Option<crate::audit_authority::PreparedTargetMutation>, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        handle.verify(self.inner.backend.audit_key(), self.inner.identity, caller)?;
        let ledger = self.read_audit_ledger().await?;
        if ledger
            .lookup(self.inner.backend.audit_key(), handle, caller)?
            .is_none()
        {
            handle.require_live(
                self.inner
                    .clock
                    .now_utc()
                    .as_offset_datetime()
                    .unix_timestamp(),
            )?;
            return Ok(None);
        }
        ledger
            .recover_target(self.inner.backend.audit_key(), handle, caller)
            .map(Some)
    }

    /// Admit an exact SDK-prepared target intent through this node's local
    /// leader. Before queueing, check current target/source/lock expectations,
    /// retained recovery reservations, and both complete command sizes. The
    /// independent checkpoint is verified before admission; submission must
    /// additionally checkpoint this exact intent. No target or local registry
    /// effect is authorized by rejected or indeterminate admission.
    ///
    /// Keep the original prepared value before calling. Cancellation does not
    /// retract consensus work; recover the original handle instead of preparing
    /// replacement work. This method cannot construct a target from caller-
    /// asserted ciphertext, session, or outcome fields.
    pub async fn admit_netconf_target_local(
        &self,
        prepared: &crate::audit_authority::PreparedTargetMutation,
        caller: AuditCaller,
    ) -> AuditAdmission {
        use crate::consensus::audit_mutation::TargetAuditCommandV1;
        if let Err(error) = self.verify_netconf_target(prepared, caller) {
            return AuditAdmission::Rejected(error);
        }
        let admit = ConfigMutationIntent::ManagementAudit(AuditCommand::NetconfTarget(Box::new(
            TargetAuditCommandV1::Admit(prepared.clone()),
        )));
        let apply = ConfigMutationIntent::ManagementAudit(AuditCommand::NetconfTarget(Box::new(
            TargetAuditCommandV1::Apply(prepared.clone()),
        )));
        for (purpose, command) in [
            (b"netconf-target-intent".as_slice(), &admit),
            (b"netconf-target-effect".as_slice(), &apply),
        ] {
            let request =
                derive_durable_request_id(self.inner.identity, purpose, &prepared.handle.mac);
            if super::preflight_config_command_replication_budget(
                self.inner.identity,
                request,
                command,
            )
            .is_err()
            {
                return AuditAdmission::Rejected(AuditAuthorityError::InvalidInput);
            }
        }
        match self.preflight_netconf_target(prepared).await {
            Ok(Some(receipt)) => return AuditAdmission::Applied(receipt),
            Ok(None) => {}
            Err(error) => return AuditAdmission::Rejected(error),
        }
        self.audit_operation_command_with_route(
            prepared.handle(),
            caller,
            b"netconf-target-intent",
            admit,
            true,
        )
        .await
    }

    /// Submit only the exact retained target description with its acknowledged
    /// admission receipt. The original intent must be independently checkpointed
    /// before the effect is queued. Application rechecks changing generations,
    /// ownership and fixed expiry, retaining an atomic typed result or rejection.
    /// A known result is returned unchanged even when terminal completion is owed.
    pub async fn submit_netconf_target_local(
        &self,
        prepared: &crate::audit_authority::PreparedTargetMutation,
        admitted: &AuditOperationReceipt,
        caller: AuditCaller,
    ) -> AuditAdmission {
        use crate::consensus::audit_mutation::TargetAuditCommandV1;
        if let Err(error) = self.verify_netconf_target(prepared, caller) {
            return AuditAdmission::Rejected(error);
        }
        if admitted.handle != prepared.handle {
            return AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch);
        }
        // Receipts have no public constructor or untrusted decoder. Preserve
        // this already authenticated exact result before any fallible read.
        match admitted.state() {
            crate::audit_authority::AuditOperationState::TargetV1(result) => {
                return match prepared.validate_result(result) {
                    Ok(()) => AuditAdmission::Applied(admitted.clone()),
                    Err(error) => AuditAdmission::Rejected(error),
                };
            }
            crate::audit_authority::AuditOperationState::Rejected => {
                return AuditAdmission::Applied(admitted.clone());
            }
            crate::audit_authority::AuditOperationState::Intent => {}
            _ => return AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch),
        }
        let ledger = match self.read_audit_ledger().await {
            Ok(ledger) => ledger,
            Err(error) => return AuditAdmission::Rejected(error),
        };
        if !ledger
            .recover_target(self.inner.backend.audit_key(), prepared.handle(), caller)
            .is_ok_and(|original| original == *prepared)
        {
            return AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch);
        }
        let receipt = match ledger.lookup(self.inner.backend.audit_key(), prepared.handle(), caller)
        {
            Ok(Some(receipt)) => receipt,
            _ => return AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch),
        };
        if receipt.state() != crate::audit_authority::AuditOperationState::Intent {
            return AuditAdmission::Applied(receipt);
        }
        if ledger.operations.iter().any(|operation| {
            (operation.handle != prepared.handle && !operation.terminal_recorded)
                || ledger.mutation_outcome_needs_checkpoint(operation)
        }) {
            return AuditAdmission::Rejected(AuditAuthorityError::RecoveryRequired);
        }
        if let Err(error) = self.checkpoint_audit_tail().await {
            return AuditAdmission::Rejected(error);
        }
        self.audit_operation_command_with_route(
            prepared.handle(),
            caller,
            b"netconf-target-effect",
            ConfigMutationIntent::ManagementAudit(AuditCommand::NetconfTarget(Box::new(
                TargetAuditCommandV1::Apply(prepared.clone()),
            ))),
            true,
        )
        .await
    }

    async fn preflight_netconf_target(
        &self,
        prepared: &crate::audit_authority::PreparedTargetMutation,
    ) -> Result<Option<AuditOperationReceipt>, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        self.linearizable_barrier()
            .await
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        let prepared = prepared.clone();
        let backend = self.inner.backend.clone();
        let identity = self.inner.identity;
        let now = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        let (ledger, decision) = super::super::run_backend_sqlite_with_timeout(
            &self.inner.backend,
            self.inner.operation_timeout,
            move |conn, cancellation| {
                let unavailable = || std::io::Error::other("target authority unavailable");
                let tx = conn.unchecked_transaction().map_err(|_| unavailable())?;
                super::super::sqlite::validate_live_history_schema_for_profile(
                    &tx,
                    cancellation,
                    crate::RetainedConfigProfile::NetconfTargetsV1,
                )?;
                let keys = backend.management_audit_keys().ok_or_else(unavailable)?;
                let ledger = super::super::audit::read_with_keys_sync(
                    &tx,
                    backend.audit_key(),
                    Some(&keys),
                    identity,
                )?
                .ok_or_else(unavailable)?;
                let decision = super::super::audit_targets::preflight_target_sync(
                    &tx,
                    backend.audit_key(),
                    &prepared,
                    &ledger,
                    &keys,
                    now,
                    cancellation,
                )?;
                cancellation.check_io()?;
                tx.commit().map_err(|_| unavailable())?;
                Ok((ledger, decision))
            },
        )
        .await
        .map_err(|_| AuditAuthorityError::Unavailable)?;
        self.verify_audit_checkpoint(&ledger).await?;
        decision
    }
}

impl ConsensusConfigStore {
    /// Prepare one explicit NETCONF device start under trusted embedding
    /// authorization. This is a lifecycle operation, not an authenticated
    /// client's NETCONF RPC: only an Internal Intent event is accepted.
    ///
    /// A fresh inactive authority prepares activation; an established one binds
    /// its exact previous device and profile. This does not upgrade a legacy
    /// store. No owner is usable before this exact intent, result, and terminal
    /// checkpoint complete. Retain the returned original mutation for admission
    /// and recovery; calling this method again creates a different preparation
    /// and cannot recover an already transmitted operation.
    pub async fn prepare_netconf_device(
        &self,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        lifetime: std::time::Duration,
    ) -> Result<crate::audit_authority::PreparedNetconfDevice, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        if event.transport() != crate::ManagementAuditTransportCode::Internal
            || event.outcome() != crate::ManagementAuditOutcomeCode::Intent
            || lifetime.subsec_nanos() != 0
            || !(1..=3600).contains(&lifetime.as_secs())
        {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let event = ProjectedAuditEvent::project(privacy, event)?;
        let issued_at = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        let expires_at = issued_at
            .checked_add(lifetime.as_secs() as i64)
            .ok_or(AuditAuthorityError::InvalidInput)?;
        let view = self.read_netconf_device_view().await?;
        let effect = view.prepare(
            &event,
            expires_at,
            *uuid::Uuid::new_v4().as_bytes(),
            *uuid::Uuid::new_v4().as_bytes(),
        )?;
        let digest = effect.digest(self.inner.backend.audit_key())?;
        let binding =
            AuditOperationBinding::project(privacy, &event, view.running_version, &digest)?;
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity: self.inner.identity,
                binding,
                event,
                issued_at,
                expires_at,
                nonce: *uuid::Uuid::new_v4().as_bytes(),
                key_epoch: self.inner.backend.audit_key().epoch(),
                mutation: Some(digest),
            },
            self.inner.backend.audit_key(),
        )?;
        let prepared = crate::audit_authority::PreparedTargetMutation { handle, effect };
        prepared.verify_effect(self.inner.backend.audit_key())?;
        self.preflight_netconf_target(&prepared).await?;
        Ok(crate::audit_authority::PreparedNetconfDevice {
            worker: crate::audit_authority::NetconfWorkerBinding::new(&self.inner),
            prepared,
        })
    }

    /// Claim this worker's device capability after the exact lifecycle result
    /// and its terminal/checkpoint obligations are complete. An older applied
    /// result does not override a newer retained device. Outstanding cleanup
    /// refuses serving ownership without erasing the already known result.
    ///
    /// Decoding an original mutation cannot reconstruct the preparation's local
    /// worker binding. A replacement worker must first reconcile the old effect
    /// and then perform its own explicit device-start transition.
    pub async fn claim_netconf_device_owner(
        &self,
        prepared: &crate::audit_authority::PreparedNetconfDevice,
        receipt: &AuditOperationReceipt,
        caller: AuditCaller,
    ) -> Result<crate::audit_authority::NetconfDeviceOwner, AuditAuthorityError> {
        if !prepared.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        self.verify_netconf_target(&prepared.prepared, caller)?;
        if receipt.handle != prepared.prepared.handle {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let crate::audit_authority::AuditOperationState::TargetV1(result) = receipt.state() else {
            return Err(AuditAuthorityError::BindingMismatch);
        };
        prepared.prepared.validate_result(result)?;
        let owner = crate::audit_authority::NetconfDeviceOwner {
            worker: prepared.worker.clone(),
            authority: self.inner.identity,
            profile_incarnation: prepared.prepared.effect.profile_incarnation,
            device_incarnation: prepared.prepared.effect.device_incarnation,
            caller,
        };
        self.verify_netconf_device_owner(&owner).await?;
        Ok(owner)
    }

    /// Check the exact issuing worker, authority scope and current retained
    /// device ownership through a quorum read and independent checkpoint.
    /// This does not authenticate a NETCONF session or grant NACM permission.
    pub async fn verify_netconf_device_owner(
        &self,
        owner: &crate::audit_authority::NetconfDeviceOwner,
    ) -> Result<(), AuditAuthorityError> {
        if !owner.worker.belongs_to(&self.inner) || owner.authority != self.inner.identity {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        self.read_netconf_device_view().await?.verify_owner(owner)
    }

    async fn read_netconf_device_view(
        &self,
    ) -> Result<super::super::audit_targets::NetconfDeviceView, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        self.linearizable_barrier()
            .await
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        let backend = self.inner.backend.clone();
        let identity = self.inner.identity;
        let (ledger, view) = super::super::run_backend_sqlite_with_timeout(
            &self.inner.backend,
            self.inner.operation_timeout,
            move |conn, cancellation| {
                let unavailable = || std::io::Error::other("device authority unavailable");
                let tx = conn.unchecked_transaction().map_err(|_| unavailable())?;
                super::super::sqlite::validate_live_history_schema_for_profile(
                    &tx,
                    cancellation,
                    crate::RetainedConfigProfile::NetconfTargetsV1,
                )?;
                let keys = backend.management_audit_keys().ok_or_else(unavailable)?;
                let ledger = super::super::audit::read_with_keys_sync(
                    &tx,
                    backend.audit_key(),
                    Some(&keys),
                    identity,
                )?
                .ok_or_else(unavailable)?;
                let view = super::super::audit_targets::read_device_view_sync(
                    &tx,
                    backend.audit_key(),
                    &ledger,
                    cancellation,
                )?;
                cancellation.check_io()?;
                tx.commit().map_err(|_| unavailable())?;
                Ok((ledger, view))
            },
        )
        .await
        .map_err(|_| AuditAuthorityError::Unavailable)?;
        self.verify_audit_checkpoint(&ledger).await?;
        Ok(view)
    }
}

impl ConsensusConfigStore {
    /// Issue a fresh session incarnation after the trusted transport has
    /// authenticated `caller` independently. This verifies the retained device;
    /// it does not perform transport authentication or grant NACM permission.
    /// Numeric NETCONF session IDs cannot be used as authority capabilities.
    pub async fn open_netconf_session(
        &self,
        device: &crate::audit_authority::NetconfDeviceOwner,
        caller: AuditCaller,
    ) -> Result<crate::audit_authority::NetconfSessionOwner, AuditAuthorityError> {
        self.verify_netconf_device_owner(device).await?;
        crate::audit_authority::NetconfSessionOwner::new(
            device.clone(),
            caller,
            *uuid::Uuid::new_v4().as_bytes(),
        )
    }

    /// Check exact worker/device ownership and a locally active session belonging
    /// to the independently authenticated caller. The registry and ConfigBus
    /// must additionally hold their exact worker/operation capability.
    pub async fn verify_netconf_session_owner(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        caller: AuditCaller,
    ) -> Result<(), AuditAuthorityError> {
        if session.caller != caller || !session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        session.require_active()?;
        self.read_netconf_device_view()
            .await?
            .verify_session(session)?;
        session.require_active()
    }

    /// Prepare an exact retained lock acquisition; no lock or intent is granted
    /// by preparation alone. Retain the returned mutation before admission.
    pub async fn prepare_netconf_lock_acquisition(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        datastore: crate::audit_authority::NetconfLockDatastore,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        lifetime: std::time::Duration,
    ) -> Result<crate::audit_authority::PreparedNetconfLock, AuditAuthorityError> {
        self.prepare_netconf_lock(session, datastore, None, privacy, event, lifetime)
            .await
    }

    /// Prepare release of this session's exact retained lease. Candidate release
    /// includes the authority's atomic discard and tombstone transition. A known
    /// applied release remains known even when later audit reporting fails.
    pub async fn prepare_netconf_lock_release(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        lease: &crate::audit_authority::NetconfLockLease,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        lifetime: std::time::Duration,
    ) -> Result<crate::audit_authority::PreparedNetconfLock, AuditAuthorityError> {
        self.prepare_netconf_lock(
            session,
            lease.datastore,
            Some(lease),
            privacy,
            event,
            lifetime,
        )
        .await
    }

    /// Claim the lease established by this exact acquisition after terminal
    /// checkpoint completion. A receipt cannot restore a released or replaced
    /// lease, nor can an equal principal stand in for the original session.
    pub async fn claim_netconf_lock_lease(
        &self,
        prepared: &crate::audit_authority::PreparedNetconfLock,
        receipt: &AuditOperationReceipt,
        caller: AuditCaller,
    ) -> Result<crate::audit_authority::NetconfLockLease, AuditAuthorityError> {
        let bad = AuditAuthorityError::BindingMismatch;
        if !prepared.session.device.worker.belongs_to(&self.inner)
            || prepared.session.caller != caller
            || receipt.handle != prepared.prepared.handle
            || u8::from(prepared.prepared.effect.action) != 2
        {
            return Err(bad);
        }
        prepared.session.require_active()?;
        self.verify_netconf_target(&prepared.prepared, caller)?;
        let crate::audit_authority::AuditOperationState::TargetV1(result) = receipt.state() else {
            return Err(bad);
        };
        prepared.prepared.validate_result(result)?;
        let expected = prepared.prepared.effect.lock.as_ref().ok_or(bad)?;
        let lease = crate::audit_authority::NetconfLockLease {
            session: prepared.session.clone(),
            datastore: prepared.datastore,
            incarnation: expected
                .incarnation
                .checked_add(1)
                .ok_or(AuditAuthorityError::Full)?,
        };
        self.verify_netconf_lock_lease(&lease, caller).await?;
        Ok(lease)
    }

    /// Verify a currently held retained lease for the exact active session,
    /// caller, worker, device, datastore and monotonically increasing counter.
    pub async fn verify_netconf_lock_lease(
        &self,
        lease: &crate::audit_authority::NetconfLockLease,
        caller: AuditCaller,
    ) -> Result<(), AuditAuthorityError> {
        if lease.session.caller != caller || !lease.session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        lease.session.require_active()?;
        self.read_netconf_device_view().await?.verify_lease(lease)?;
        lease.session.require_active()
    }

    async fn prepare_netconf_lock(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        datastore: crate::audit_authority::NetconfLockDatastore,
        release: Option<&crate::audit_authority::NetconfLockLease>,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        lifetime: std::time::Duration,
    ) -> Result<crate::audit_authority::PreparedNetconfLock, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        if !session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        if lifetime.subsec_nanos() != 0 || !(1..=3600).contains(&lifetime.as_secs()) {
            return Err(AuditAuthorityError::InvalidInput);
        }
        session.require_active()?;
        let event = ProjectedAuditEvent::project(privacy, event)?;
        let issued_at = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        let expires_at = issued_at
            .checked_add(lifetime.as_secs() as i64)
            .ok_or(AuditAuthorityError::InvalidInput)?;
        let view = self.read_netconf_device_view().await?;
        let effect = view.prepare_lock(session, &event, datastore, release, expires_at)?;
        let digest = effect.digest(self.inner.backend.audit_key())?;
        let binding =
            AuditOperationBinding::project(privacy, &event, view.running_version, &digest)?;
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity: self.inner.identity,
                binding,
                event,
                issued_at,
                expires_at,
                nonce: *uuid::Uuid::new_v4().as_bytes(),
                key_epoch: self.inner.backend.audit_key().epoch(),
                mutation: Some(digest),
            },
            self.inner.backend.audit_key(),
        )?;
        let prepared = crate::audit_authority::PreparedTargetMutation { handle, effect };
        prepared.verify_effect(self.inner.backend.audit_key())?;
        self.preflight_netconf_target(&prepared).await?;
        session.require_active()?;
        Ok(crate::audit_authority::PreparedNetconfLock {
            session: session.clone(),
            datastore,
            prepared,
        })
    }
}

impl ConsensusConfigStore {
    /// Prepare the original cleanup for a locally invalidated session. Only an
    /// Internal Exec Intent attributed to that session's original caller is
    /// accepted. This issues no replacement client credentials or serving token.
    ///
    /// All clones retain one original closed mutation before any admission.
    /// Identical retries return it without extending expiry; another event or
    /// lifetime is refused. Preparation does not release a lock, discard a
    /// candidate, or acknowledge rollback. The ConfigBus worker must keep its
    /// cleanup fence through admission, exact result recovery and checkpoint
    /// completion, independently of the protocol future. A pending confirmed
    /// rollback remains a separate retained obligation after session cleanup.
    ///
    /// The returned mutation uses the ordinary target admission/submission and
    /// original-handle recovery APIs. Even if preparation is interrupted, any
    /// cached original is reused by the next identical call. Replacing the
    /// device owner is a distinct retained reboot operation, not session retry.
    pub async fn prepare_netconf_session_cleanup(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        lifetime: std::time::Duration,
    ) -> Result<crate::audit_authority::PreparedTargetMutation, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        if !session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        if lifetime.subsec_nanos() != 0 || !(1..=3600).contains(&lifetime.as_secs()) {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let event = ProjectedAuditEvent::project(privacy, event)?;
        if let Some(original) = session.original_cleanup(&event, lifetime)? {
            self.verify_netconf_target(&original, session.caller)?;
            self.preflight_netconf_target(&original).await?;
            return Ok(original);
        }
        let issued_at = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        let expires_at = issued_at
            .checked_add(lifetime.as_secs() as i64)
            .ok_or(AuditAuthorityError::InvalidInput)?;
        let view = self.read_netconf_device_view().await?;
        let effect = view.prepare_session_cleanup(session, &event, expires_at)?;
        let digest = effect.digest(self.inner.backend.audit_key())?;
        let binding =
            AuditOperationBinding::project(privacy, &event, view.running_version, &digest)?;
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity: self.inner.identity,
                binding,
                event,
                issued_at,
                expires_at,
                nonce: *uuid::Uuid::new_v4().as_bytes(),
                key_epoch: self.inner.backend.audit_key().epoch(),
                mutation: Some(digest),
            },
            self.inner.backend.audit_key(),
        )?;
        let prepared = crate::audit_authority::PreparedTargetMutation { handle, effect };
        prepared.verify_effect(self.inner.backend.audit_key())?;
        let original = session.retain_cleanup(prepared)?;
        self.preflight_netconf_target(&original).await?;
        Ok(original)
    }
}

impl ConsensusConfigStore {
    /// Prepare a separately authorized cleanup attempt after the exact original
    /// expired and was definitively rejected with its terminal checkpoint settled.
    /// A timeout, absent/pruned operation, outstanding intent, or known applied
    /// cleanup cannot authorize replacement. The original result stays unchanged.
    ///
    /// `previous` must be the attempt retained by this exact inactive session.
    /// Supply a new Internal Exec Intent for the same authenticated caller and
    /// projection. Concurrent identical retries select one successor before any
    /// admission; different requests or stale predecessors are refused. Keep its
    /// original handle through ordinary target admission, submission and recovery.
    ///
    /// Preparation never clears the worker's cleanup fence, reactivates a session,
    /// or changes a confirmed deadline/rollback parent. End-session cleanup and
    /// confirmed rollback remain separate retained obligations. Store/checkpoint
    /// unavailability preserves the original attempt and permits no effect.
    pub async fn prepare_netconf_session_cleanup_successor(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        previous: &crate::audit_authority::PreparedTargetMutation,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        lifetime: std::time::Duration,
    ) -> Result<crate::audit_authority::PreparedTargetMutation, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        if !session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        if lifetime.subsec_nanos() != 0 || !(1..=3600).contains(&lifetime.as_secs()) {
            return Err(AuditAuthorityError::InvalidInput);
        }
        self.verify_netconf_target(previous, session.caller)?;
        let event = ProjectedAuditEvent::project(privacy, event)?;
        if let Some(original) = session.successor_cleanup(previous, &event, lifetime)? {
            self.verify_netconf_target(&original, session.caller)?;
            self.preflight_netconf_target(&original).await?;
            return Ok(original);
        }
        let issued_at = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        let expires_at = issued_at
            .checked_add(lifetime.as_secs() as i64)
            .ok_or(AuditAuthorityError::InvalidInput)?;
        let ledger = self.read_audit_ledger().await?;
        previous.verify_settled_cleanup_rejection(
            session,
            &ledger,
            self.inner.backend.audit_key(),
            issued_at,
        )?;
        let view = self.read_netconf_device_view().await?;
        let effect = view.prepare_session_cleanup(session, &event, expires_at)?;
        let digest = effect.digest(self.inner.backend.audit_key())?;
        let binding =
            AuditOperationBinding::project(privacy, &event, view.running_version, &digest)?;
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity: self.inner.identity,
                binding,
                event,
                issued_at,
                expires_at,
                nonce: *uuid::Uuid::new_v4().as_bytes(),
                key_epoch: self.inner.backend.audit_key().epoch(),
                mutation: Some(digest),
            },
            self.inner.backend.audit_key(),
        )?;
        let prepared = crate::audit_authority::PreparedTargetMutation { handle, effect };
        let original = session.retain_cleanup_successor(
            previous,
            prepared,
            &ledger,
            self.inner.backend.audit_key(),
            issued_at,
        )?;
        self.preflight_netconf_target(&original).await?;
        Ok(original)
    }
}

impl ConsensusConfigStore {
    /// Prepare one exact encrypted candidate/startup copy into running under
    /// the existing RFC 019 target profile. The original source and destination
    /// come from the original frozen read and are authenticated through the
    /// key provider; preparation never refreshes either. Request metadata may differ,
    /// but their serialized configuration bytes and schema must be identical.
    /// The intent must carry the NETCONF copy-config `Replace` operation.
    ///
    /// This does not grant NACM permission or admit an effect. Retain the result
    /// before intent admission. Unknown outcomes recover this original operation;
    /// a fresh preparation must never replace a possibly transmitted request.
    pub async fn prepare_netconf_copy_to_running(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        copy: crate::audit_authority::NetconfRunningCopy<'_>,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        lifetime: std::time::Duration,
    ) -> Result<crate::audit_authority::PreparedTargetMutation, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        if !session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let frozen = copy.frozen;
        frozen.verify_session(session)?;
        if lifetime.subsec_nanos() != 0 || !(1..=3600).contains(&lifetime.as_secs()) {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let tenant = opc_types::TenantId::new(event.tenant())
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        let event = ProjectedAuditEvent::project(privacy, event)?;
        let issued_at = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        let expires_at = issued_at
            .checked_add(lifetime.as_secs() as i64)
            .ok_or(AuditAuthorityError::InvalidInput)?;
        let effect = frozen
            .prepare_copy(
                session,
                copy,
                &tenant,
                &event,
                expires_at,
                self.inner.backend.audit_key(),
            )
            .await?;
        let digest = effect.digest(self.inner.backend.audit_key())?;
        let binding =
            AuditOperationBinding::project(privacy, &event, frozen.source.running_base, &digest)?;
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity: self.inner.identity,
                binding,
                event,
                issued_at,
                expires_at,
                nonce: *uuid::Uuid::new_v4().as_bytes(),
                key_epoch: self.inner.backend.audit_key().epoch(),
                mutation: Some(digest),
            },
            self.inner.backend.audit_key(),
        )?;
        let prepared = crate::audit_authority::PreparedTargetMutation { handle, effect };
        prepared.verify_effect(self.inner.backend.audit_key())?;
        self.preflight_netconf_target(&prepared).await?;
        frozen.verify_session(session)?;
        Ok(prepared)
    }

    /// Prepare ordinary candidate promotion from an original frozen read.
    /// The Exec intent binds the original generation, staging owner, running
    /// base and exact provider-authenticated configuration. Applying it commits
    /// running and retires that candidate atomically. It cannot resolve pending
    /// confirmation or promote a running fallback. Retain the original before
    /// admission; unknown transmission recovers only that operation.
    pub async fn prepare_netconf_candidate_promotion(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        promotion: crate::audit_authority::NetconfCandidatePromotion<'_>,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        lifetime: std::time::Duration,
    ) -> Result<crate::audit_authority::PreparedTargetMutation, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        if !session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let frozen = promotion.frozen;
        frozen.verify_session(session)?;
        if lifetime.subsec_nanos() != 0 || !(1..=3600).contains(&lifetime.as_secs()) {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let tenant = opc_types::TenantId::new(event.tenant())
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        let event = ProjectedAuditEvent::project(privacy, event)?;
        let issued_at = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        let expires_at = issued_at
            .checked_add(lifetime.as_secs() as i64)
            .ok_or(AuditAuthorityError::InvalidInput)?;
        let effect = frozen
            .prepare_promotion(
                session,
                promotion,
                &tenant,
                &event,
                expires_at,
                self.inner.backend.audit_key(),
            )
            .await?;
        let digest = effect.digest(self.inner.backend.audit_key())?;
        let binding = AuditOperationBinding::project(
            privacy,
            &event,
            frozen.candidate().running_base_version(),
            &digest,
        )?;
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity: self.inner.identity,
                binding,
                event,
                issued_at,
                expires_at,
                nonce: *uuid::Uuid::new_v4().as_bytes(),
                key_epoch: self.inner.backend.audit_key().epoch(),
                mutation: Some(digest),
            },
            self.inner.backend.audit_key(),
        )?;
        let prepared = crate::audit_authority::PreparedTargetMutation { handle, effect };
        prepared.verify_effect(self.inner.backend.audit_key())?;
        self.preflight_netconf_target(&prepared).await?;
        frozen.verify_session(session)?;
        Ok(prepared)
    }

    /// Freeze a candidate/startup source and the running destination before
    /// decrypting, validating or encrypting copy content. The quorum-current
    /// transaction binds the source generation/fallback, running version, both
    /// locks, device and ledger; the independent checkpoint is verified before
    /// returning an opaque read. Absent startup and initial empty running are
    /// refused. Authorization and model validation remain upstream.
    pub async fn read_netconf_running_copy(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        source: crate::audit_authority::NetconfLockDatastore,
    ) -> Result<crate::audit_authority::NetconfRunningCopyRead, AuditAuthorityError> {
        self.read_netconf_running_source(session, source)
            .await?
            .freeze(session)
    }

    /// Freeze an actual staged candidate for ordinary promotion, before
    /// decrypting or preparing its running envelope. The original staging
    /// session, caller and base must match; fallback, foreign locks, pending
    /// confirmation and unresolved audit obligations are refused. This uses
    /// the same quorum-current read and independent checkpoint as running copy.
    pub async fn read_netconf_candidate_promotion(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
    ) -> Result<crate::audit_authority::NetconfCandidatePromotionRead, AuditAuthorityError> {
        self.read_netconf_running_source(
            session,
            crate::audit_authority::NetconfLockDatastore::Candidate,
        )
        .await?
        .freeze_promotion(session)
    }

    async fn read_netconf_running_source(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        source: crate::audit_authority::NetconfLockDatastore,
    ) -> Result<super::super::audit_targets::NetconfCopyView, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        if !session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        session.require_active()?;
        self.linearizable_barrier()
            .await
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        let backend = self.inner.backend.clone();
        let identity = self.inner.identity;
        let (ledger, view) = super::super::run_backend_sqlite_with_timeout(
            &self.inner.backend,
            self.inner.operation_timeout,
            move |conn, cancellation| {
                let unavailable = || std::io::Error::other("copy authority unavailable");
                let tx = conn.unchecked_transaction().map_err(|_| unavailable())?;
                super::super::sqlite::validate_live_history_schema_for_profile(
                    &tx,
                    cancellation,
                    crate::RetainedConfigProfile::NetconfTargetsV1,
                )?;
                let keys = backend.management_audit_keys().ok_or_else(unavailable)?;
                let ledger = super::super::audit::read_with_keys_sync(
                    &tx,
                    backend.audit_key(),
                    Some(&keys),
                    identity,
                )?
                .ok_or_else(unavailable)?;
                let view = super::super::audit_targets::read_copy_view_sync(
                    &tx,
                    backend.audit_key(),
                    &ledger,
                    source,
                    cancellation,
                )?;
                cancellation.check_io()?;
                tx.commit().map_err(|_| unavailable())?;
                Ok((ledger, view))
            },
        )
        .await
        .map_err(|_| AuditAuthorityError::Unavailable)?;
        self.verify_audit_checkpoint(&ledger).await?;
        view
    }
}

impl ConsensusConfigStore {
    /// Prepare candidate discard or startup deletion for the exact active
    /// session and current retained target. Candidate requires an Exec Intent;
    /// startup requires a Delete Intent. Running is not a removable target.
    ///
    /// Preparation captures the target counter, running base, lock and device
    /// ownership under a quorum-current, independently checkpointed read. It
    /// changes no state and grants no admission. Retain the original prepared
    /// value before required-intent admission and recover only that operation
    /// after cancellation or an unknown outcome. Applying removal advances the
    /// target tombstone even when it was already absent; exact replay does not.
    ///
    /// Pending confirmation permits only its original session's candidate
    /// discard. Removal never confirms or cancels that pending operation, alters
    /// its rollback parent, or extends its deadline. Terminal debt and lifecycle
    /// cleanup continue to fence preparation and application.
    pub async fn prepare_netconf_target_removal(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        datastore: crate::audit_authority::NetconfLockDatastore,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        lifetime: std::time::Duration,
    ) -> Result<crate::audit_authority::PreparedTargetMutation, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        if !session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        session.require_active()?;
        if lifetime.subsec_nanos() != 0 || !(1..=3600).contains(&lifetime.as_secs()) {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let event = ProjectedAuditEvent::project(privacy, event)?;
        let issued_at = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        let expires_at = issued_at
            .checked_add(lifetime.as_secs() as i64)
            .ok_or(AuditAuthorityError::InvalidInput)?;
        let view = self.read_netconf_removal_view(datastore).await?;
        let effect = view.prepare(session, &event, expires_at)?;
        let digest = effect.digest(self.inner.backend.audit_key())?;
        let binding =
            AuditOperationBinding::project(privacy, &event, view.device.running_version, &digest)?;
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity: self.inner.identity,
                binding,
                event,
                issued_at,
                expires_at,
                nonce: *uuid::Uuid::new_v4().as_bytes(),
                key_epoch: self.inner.backend.audit_key().epoch(),
                mutation: Some(digest),
            },
            self.inner.backend.audit_key(),
        )?;
        let prepared = crate::audit_authority::PreparedTargetMutation { handle, effect };
        prepared.verify_effect(self.inner.backend.audit_key())?;
        self.preflight_netconf_target(&prepared).await?;
        session.require_active()?;
        Ok(prepared)
    }

    async fn read_netconf_removal_view(
        &self,
        datastore: crate::audit_authority::NetconfLockDatastore,
    ) -> Result<super::super::audit_targets::NetconfRemovalView, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        self.linearizable_barrier()
            .await
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        let backend = self.inner.backend.clone();
        let identity = self.inner.identity;
        let (ledger, view) = super::super::run_backend_sqlite_with_timeout(
            &self.inner.backend,
            self.inner.operation_timeout,
            move |conn, cancellation| {
                let unavailable = || std::io::Error::other("target removal authority unavailable");
                let tx = conn.unchecked_transaction().map_err(|_| unavailable())?;
                super::super::sqlite::validate_live_history_schema_for_profile(
                    &tx,
                    cancellation,
                    crate::RetainedConfigProfile::NetconfTargetsV1,
                )?;
                let keys = backend.management_audit_keys().ok_or_else(unavailable)?;
                let ledger = super::super::audit::read_with_keys_sync(
                    &tx,
                    backend.audit_key(),
                    Some(&keys),
                    identity,
                )?
                .ok_or_else(unavailable)?;
                let view = super::super::audit_targets::read_removal_view_sync(
                    &tx,
                    backend.audit_key(),
                    &ledger,
                    datastore,
                    cancellation,
                )?;
                cancellation.check_io()?;
                tx.commit().map_err(|_| unavailable())?;
                Ok((ledger, view))
            },
        )
        .await
        .map_err(|_| AuditAuthorityError::Unavailable)?;
        self.verify_audit_checkpoint(&ledger).await?;
        view
    }
}

impl ConsensusConfigStore {
    /// Read one frozen candidate/startup edit base for this exact SDK session.
    /// The target, running fallback, lock, device, ledger and checkpoint anchor
    /// are read in one transaction after the quorum barrier. The independent
    /// checkpoint is verified before the opaque value is returned. No state is
    /// changed and no admission is granted; NACM authorization remains upstream.
    pub async fn read_netconf_target(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        datastore: crate::audit_authority::NetconfLockDatastore,
    ) -> Result<crate::audit_authority::NetconfTargetRead, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        if !session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        session.require_active()?;
        self.linearizable_barrier()
            .await
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        let backend = self.inner.backend.clone();
        let identity = self.inner.identity;
        let original = session.clone();
        let (ledger, view) = super::super::run_backend_sqlite_with_timeout(
            &self.inner.backend,
            self.inner.operation_timeout,
            move |conn, cancellation| {
                let unavailable = || std::io::Error::other("target read authority unavailable");
                let tx = conn.unchecked_transaction().map_err(|_| unavailable())?;
                super::super::sqlite::validate_live_history_schema_for_profile(
                    &tx,
                    cancellation,
                    crate::RetainedConfigProfile::NetconfTargetsV1,
                )?;
                let keys = backend.management_audit_keys().ok_or_else(unavailable)?;
                let ledger = super::super::audit::read_with_keys_sync(
                    &tx,
                    backend.audit_key(),
                    Some(&keys),
                    identity,
                )?
                .ok_or_else(unavailable)?;
                let view = super::super::audit_targets::read_target_view_sync(
                    &tx,
                    backend.audit_key(),
                    &ledger,
                    datastore,
                    &original,
                    cancellation,
                )?;
                cancellation.check_io()?;
                tx.commit().map_err(|_| unavailable())?;
                Ok((ledger, view))
            },
        )
        .await
        .map_err(|_| AuditAuthorityError::Unavailable)?;
        self.verify_audit_checkpoint(&ledger).await?;
        let view = view?;
        view.verify_session(session)?;
        Ok(view)
    }

    /// Encrypt a validated edit or inline copy against its original frozen read.
    /// This never refreshes a stale counter after the worker computed content.
    /// The existing provider creates the exact target-bound envelope; plaintext
    /// and provider references are not retained. This does not prepare a copy
    /// from another datastore, admit an intent or change configuration state.
    ///
    /// Preserve the returned original before admission. Once transmission may
    /// have occurred, recover that operation instead of preparing a replacement.
    /// Required admission rechecks complete command/replication bounds, exact
    /// expectations, independent checkpoint and terminal/lifecycle fences.
    pub async fn prepare_netconf_target_replacement(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        replacement: crate::audit_authority::NetconfTargetReplacement<'_>,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        lifetime: std::time::Duration,
    ) -> Result<crate::audit_authority::PreparedTargetMutation, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        let frozen = replacement.frozen;
        if !session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        frozen.verify_session(session)?;
        if lifetime.subsec_nanos() != 0 || !(1..=3600).contains(&lifetime.as_secs()) {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let tenant = opc_types::TenantId::new(event.tenant())
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        let event = ProjectedAuditEvent::project(privacy, event)?;
        let issued_at = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        let expires_at = issued_at
            .checked_add(lifetime.as_secs() as i64)
            .ok_or(AuditAuthorityError::InvalidInput)?;
        let effect = frozen
            .prepare_replacement(session, replacement, tenant, &event, expires_at)
            .await?;
        let digest = effect.digest(self.inner.backend.audit_key())?;
        let binding =
            AuditOperationBinding::project(privacy, &event, frozen.running_base, &digest)?;
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity: self.inner.identity,
                binding,
                event,
                issued_at,
                expires_at,
                nonce: *uuid::Uuid::new_v4().as_bytes(),
                key_epoch: self.inner.backend.audit_key().epoch(),
                mutation: Some(digest),
            },
            self.inner.backend.audit_key(),
        )?;
        let prepared = crate::audit_authority::PreparedTargetMutation { handle, effect };
        prepared.verify_effect(self.inner.backend.audit_key())?;
        self.preflight_netconf_target(&prepared).await?;
        frozen.verify_session(session)?;
        Ok(prepared)
    }
}

impl ConsensusConfigStore {
    /// Read a source and distinct candidate/startup destination for this session.
    /// Both stores, running fallback, locks, device, ledger and checkpoint anchor
    /// are read in one transaction after the quorum barrier. The independent
    /// checkpoint is verified before the opaque value is returned. No state is
    /// changed and no admission is granted; NACM authorization remains upstream.
    pub async fn read_netconf_target_copy(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        source: crate::audit_authority::NetconfLockDatastore,
        destination: crate::audit_authority::NetconfLockDatastore,
    ) -> Result<crate::audit_authority::NetconfTargetCopyRead, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        if !session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        session.require_active()?;
        self.linearizable_barrier()
            .await
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        let backend = self.inner.backend.clone();
        let identity = self.inner.identity;
        let original = session.clone();
        let (ledger, view) = super::super::run_backend_sqlite_with_timeout(
            &self.inner.backend,
            self.inner.operation_timeout,
            move |conn, cancellation| {
                let unavailable = || std::io::Error::other("target copy authority unavailable");
                let tx = conn.unchecked_transaction().map_err(|_| unavailable())?;
                super::super::sqlite::validate_live_history_schema_for_profile(
                    &tx,
                    cancellation,
                    crate::RetainedConfigProfile::NetconfTargetsV1,
                )?;
                let keys = backend.management_audit_keys().ok_or_else(unavailable)?;
                let ledger = super::super::audit::read_with_keys_sync(
                    &tx,
                    backend.audit_key(),
                    Some(&keys),
                    identity,
                )?
                .ok_or_else(unavailable)?;
                let view = super::super::audit_targets::read_target_copy_view_sync(
                    &tx,
                    backend.audit_key(),
                    &ledger,
                    source,
                    destination,
                    &original,
                    cancellation,
                )?;
                cancellation.check_io()?;
                tx.commit().map_err(|_| unavailable())?;
                Ok((ledger, view))
            },
        )
        .await
        .map_err(|_| AuditAuthorityError::Unavailable)?;
        self.verify_audit_checkpoint(&ledger).await?;
        let view = view?;
        view.destination.verify_session(session)?;
        view.source.verify_session(session)?;
        Ok(view)
    }

    /// Prepare a datastore copy against its original authenticated source and
    /// destination. The existing provider verifies exact configuration equality
    /// and encrypts the destination with the complete source/target binding.
    /// New replay metadata may differ; source and destination schema cannot.
    ///
    /// This admits no intent and changes no state. Preserve the returned
    /// original before transmission; uncertain delivery permits only recovery
    /// of that exact operation. Admission rechecks current source and target,
    /// both lock owners, lifecycle/debt and complete replication bounds.
    pub async fn prepare_netconf_target_copy(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        copy: crate::audit_authority::NetconfTargetCopy<'_>,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        lifetime: std::time::Duration,
    ) -> Result<crate::audit_authority::PreparedTargetMutation, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        let frozen = copy.frozen;
        if !session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        frozen.destination.verify_session(session)?;
        frozen.source.verify_session(session)?;
        if lifetime.subsec_nanos() != 0 || !(1..=3600).contains(&lifetime.as_secs()) {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let tenant = opc_types::TenantId::new(event.tenant())
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        let event = ProjectedAuditEvent::project(privacy, event)?;
        let issued_at = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        let expires_at = issued_at
            .checked_add(lifetime.as_secs() as i64)
            .ok_or(AuditAuthorityError::InvalidInput)?;
        let effect = frozen
            .prepare_copy(session, copy, tenant, &event, expires_at)
            .await?;
        let digest = effect.digest(self.inner.backend.audit_key())?;
        let binding = AuditOperationBinding::project(
            privacy,
            &event,
            frozen.destination.running_base,
            &digest,
        )?;
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity: self.inner.identity,
                binding,
                event,
                issued_at,
                expires_at,
                nonce: *uuid::Uuid::new_v4().as_bytes(),
                key_epoch: self.inner.backend.audit_key().epoch(),
                mutation: Some(digest),
            },
            self.inner.backend.audit_key(),
        )?;
        let prepared = crate::audit_authority::PreparedTargetMutation { handle, effect };
        prepared.verify_effect(self.inner.backend.audit_key())?;
        self.preflight_netconf_target(&prepared).await?;
        frozen.destination.verify_session(session)?;
        frozen.source.verify_session(session)?;
        Ok(prepared)
    }
}

impl ConsensusConfigStore {
    /// Prepare an exact tentative candidate promotion, fixed original deadline
    /// and provider-encrypted session/persistent ownership. Requires an original
    /// nonempty running parent; admission, checkpoint and application remain
    /// separate. Retain this prepared value before any possible transmission.
    pub async fn prepare_netconf_tentative_promotion(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        promotion: crate::audit_authority::NetconfTentativePromotion<'_>,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        lifetime: std::time::Duration,
    ) -> Result<crate::audit_authority::PreparedTargetMutation, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        if !session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let frozen = promotion.frozen;
        frozen.verify_session(session)?;
        if lifetime.subsec_nanos() != 0 || !(1..=3600).contains(&lifetime.as_secs()) {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let tenant = opc_types::TenantId::new(event.tenant())
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        let event = ProjectedAuditEvent::project(privacy, event)?;
        let issued_at = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        let expires_at = issued_at
            .checked_add(lifetime.as_secs() as i64)
            .ok_or(AuditAuthorityError::InvalidInput)?;
        let effect = frozen
            .prepare_tentative(
                session,
                promotion,
                &tenant,
                &event,
                issued_at..expires_at,
                self.inner.backend.audit_key(),
            )
            .await?;
        let digest = effect.digest(self.inner.backend.audit_key())?;
        let binding = AuditOperationBinding::project(
            privacy,
            &event,
            frozen.candidate().running_base_version(),
            &digest,
        )?;
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity: self.inner.identity,
                binding,
                event,
                issued_at,
                expires_at,
                nonce: *uuid::Uuid::new_v4().as_bytes(),
                key_epoch: self.inner.backend.audit_key().epoch(),
                mutation: Some(digest),
            },
            self.inner.backend.audit_key(),
        )?;
        let prepared = crate::audit_authority::PreparedTargetMutation { handle, effect };
        prepared.verify_effect(self.inner.backend.audit_key())?;
        self.preflight_netconf_target(&prepared).await?;
        frozen.verify_session(session)?;
        Ok(prepared)
    }

    /// Read the exact retained pending operation and candidate state under the
    /// authenticated quorum-current transaction and independent checkpoint.
    /// Persistent ownership still requires the same projected caller and tenant;
    /// the credential is verified only during preparation. No local cache or
    /// caller-supplied pending identity can create this capability.
    pub async fn read_netconf_pending_confirmation(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
    ) -> Result<crate::audit_authority::NetconfPendingRead, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        if !session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        session.require_active()?;
        self.linearizable_barrier()
            .await
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        let retained_session = session.clone();
        let backend = self.inner.backend.clone();
        let identity = self.inner.identity;
        let (ledger, view) = super::super::run_backend_sqlite_with_timeout(
            &self.inner.backend,
            self.inner.operation_timeout,
            move |conn, cancellation| {
                let unavailable = || std::io::Error::other("copy authority unavailable");
                let tx = conn.unchecked_transaction().map_err(|_| unavailable())?;
                super::super::sqlite::validate_live_history_schema_for_profile(
                    &tx,
                    cancellation,
                    crate::RetainedConfigProfile::NetconfTargetsV1,
                )?;
                let keys = backend.management_audit_keys().ok_or_else(unavailable)?;
                let ledger = super::super::audit::read_with_keys_sync(
                    &tx,
                    backend.audit_key(),
                    Some(&keys),
                    identity,
                )?
                .ok_or_else(unavailable)?;
                let view = super::super::audit_targets::read_pending_view_sync(
                    &tx,
                    backend.audit_key(),
                    &ledger,
                    &retained_session,
                    cancellation,
                )?;
                cancellation.check_io()?;
                tx.commit().map_err(|_| unavailable())?;
                Ok((ledger, view))
            },
        )
        .await
        .map_err(|_| AuditAuthorityError::Unavailable)?;
        self.verify_audit_checkpoint(&ledger).await?;
        let frozen = view?;
        frozen.verify_session(session)?;
        Ok(frozen)
    }

    /// Prepare confirmation of the original pending operation without another
    /// running revision. This requires an empty candidate, correct original
    /// credential/session ownership and deadline. The exact lifecycle digest
    /// is rechecked atomically; it cannot discard concurrent staged changes.
    pub async fn prepare_netconf_empty_confirmation(
        &self,
        session: &crate::audit_authority::NetconfSessionOwner,
        confirmation: crate::audit_authority::NetconfEmptyConfirmation<'_>,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        lifetime: std::time::Duration,
    ) -> Result<crate::audit_authority::PreparedTargetMutation, AuditAuthorityError> {
        self.require_netconf_target_profile()?;
        if !session.device.worker.belongs_to(&self.inner) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let frozen = confirmation.frozen;
        frozen.verify_session(session)?;
        if lifetime.subsec_nanos() != 0 || !(1..=3600).contains(&lifetime.as_secs()) {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let tenant = opc_types::TenantId::new(event.tenant())
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        let event = ProjectedAuditEvent::project(privacy, event)?;
        let issued_at = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        let expires_at = issued_at
            .checked_add(lifetime.as_secs() as i64)
            .ok_or(AuditAuthorityError::InvalidInput)?;
        let effect = frozen
            .prepare_empty_confirmation(
                session,
                confirmation,
                &tenant,
                &event,
                issued_at..expires_at,
            )
            .await?;
        let digest = effect.digest(self.inner.backend.audit_key())?;
        let binding =
            AuditOperationBinding::project(privacy, &event, frozen.running_base(), &digest)?;
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity: self.inner.identity,
                binding,
                event,
                issued_at,
                expires_at,
                nonce: *uuid::Uuid::new_v4().as_bytes(),
                key_epoch: self.inner.backend.audit_key().epoch(),
                mutation: Some(digest),
            },
            self.inner.backend.audit_key(),
        )?;
        let prepared = crate::audit_authority::PreparedTargetMutation { handle, effect };
        prepared.verify_effect(self.inner.backend.audit_key())?;
        self.preflight_netconf_target(&prepared).await?;
        frozen.verify_session(session)?;
        Ok(prepared)
    }
}
