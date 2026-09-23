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
use crate::consensus::preparation::{PreparationOwnership, SubmissionOwnership};
use crate::consensus::{ConfigMutationIntent, PreparedConfigCommit};
use crate::{AttestedConfigCommit, ManagementAuditEventRecord};
use std::sync::Arc;

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
        self.submit_request(
            request,
            ConfigMutationIntent::ManagementAudit(Box::new(command)),
        )
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
        self.require_commit_capacity(&commit)
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        let binding = self
            .issue_capacity_binding(&commit)
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        let (record, audit, resolution, evidence, reservation) = commit.into_capacity_parts();
        let preparation =
            reservation.map(|reservation| PreparationOwnership::new(reservation, evidence));
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
            match binding {
                Some(binding) => AuditedConfigEffect::BoundedAppend {
                    commit: Box::new(commit),
                    binding,
                    resolution,
                },
                None => AuditedConfigEffect::Append {
                    commit: Box::new(commit),
                    resolution,
                },
            },
            lifetime,
            preparation,
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
            self.reserve_audited_preparation()?,
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
        let preparation = self.reserve_audited_preparation()?;
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
            preparation,
        )
    }

    fn prepare_audited_effect(
        &self,
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
        base: u64,
        effect: AuditedConfigEffect,
        lifetime: std::time::Duration,
        preparation: Option<Arc<PreparationOwnership>>,
    ) -> Result<PreparedAuditedMutation, AuditAuthorityError> {
        effect
            .verify_capacity(
                self.inner.identity,
                self.inner.backend.audit_key(),
                self.capacity_profile(),
            )
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        let digest = effect.digest(self.inner.backend.audit_key())?;
        let event = ProjectedAuditEvent::project(privacy, event)?;
        let binding = AuditOperationBinding::project(privacy, &event, base, &digest)?;
        let prepared = PreparedAuditedMutation::new(
            self.issue_audit_handle(event, binding, Some(digest), lifetime)?,
            effect,
            preparation,
        );
        // The eventual config command must fit before this handle can admit
        // a durable Intent. Preflighting only the much smaller Intent command
        // leaves an unusable audit reservation behind on a later size failure.
        let request =
            derive_durable_request_id(self.inner.identity, b"audit-config", &prepared.handle().mac);
        let command = ConfigMutationIntent::AuditedMutation(prepared.command().clone());
        super::preflight_config_command_replication_budget(self.inner.identity, request, &command)
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        Ok(prepared)
    }

    fn reserve_audited_preparation(
        &self,
    ) -> Result<Option<Arc<PreparationOwnership>>, AuditAuthorityError> {
        self.try_reserve_config_preparation()
            .map(|reservation| {
                reservation.map(|reservation| PreparationOwnership::new(reservation, None))
            })
            .map_err(|_| AuditAuthorityError::Unavailable)
    }

    /// Decode original protected recovery bytes under this store's reservation.
    ///
    /// Reserves before owned decoding, then authenticates the unchanged handle
    /// and effect. This grants neither an Intent receipt nor caller authority.
    /// A bounded append additionally authenticates its exact record size proof
    /// before attaching local preparation ownership. The larger store profile
    /// remains unavailable until retained storage qualification is complete.
    pub fn decode_prepared_audited_mutation(
        &self,
        bytes: &[u8],
    ) -> Result<PreparedAuditedMutation, AuditAuthorityError> {
        let reservation = self
            .try_reserve_config_preparation()
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        let mut prepared = PreparedAuditedMutation::decode(bytes)?;
        prepared.handle().verify(
            self.inner.backend.audit_key(),
            self.inner.identity,
            prepared.handle().body.binding.caller,
        )?;
        prepared.verify_effect(self.inner.backend.audit_key())?;
        let recovered = prepared
            .command()
            .effect
            .verify_capacity(
                self.inner.identity,
                self.inner.backend.audit_key(),
                self.capacity_profile(),
            )
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        let request =
            derive_durable_request_id(self.inner.identity, b"audit-config", &prepared.handle().mac);
        super::preflight_config_command_replication_budget(
            self.inner.identity,
            request,
            &ConfigMutationIntent::AuditedMutation(prepared.command().clone()),
        )
        .map_err(|_| AuditAuthorityError::InvalidInput)?;
        if let Some(reservation) = reservation {
            let preparation = match recovered {
                Some(evidence) => PreparationOwnership::recovered(reservation, evidence),
                None => PreparationOwnership::new(reservation, None),
            };
            prepared.attach_preparation(preparation);
        }
        Ok(prepared)
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
            ConfigMutationIntent::ManagementAudit(Box::new(AuditCommand::Intent(handle.clone()))),
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
        if &admitted.handle != prepared.handle() {
            return AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch);
        }
        let ownership = match prepared
            .begin_submission(&self.inner.preparation_admission, self.capacity_profile())
        {
            Ok(ownership) => ownership,
            Err(error) => return AuditAdmission::Rejected(error),
        };
        if prepared
            .verify_effect(self.inner.backend.audit_key())
            .is_err()
        {
            return AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch);
        }
        self.audit_operation_command_with_route(
            prepared.handle(),
            caller,
            b"audit-config",
            ConfigMutationIntent::AuditedMutation(prepared.command().clone()),
            false,
            ownership,
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
            ConfigMutationIntent::ManagementAudit(Box::new(AuditCommand::Reject(handle.clone()))),
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
            ConfigMutationIntent::ManagementAudit(Box::new(AuditCommand::Terminal(handle.clone()))),
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
        let ownership = match self.reserve_submission() {
            Ok(ownership) => ownership,
            Err(_) => return AuditAdmission::Rejected(AuditAuthorityError::Unavailable),
        };
        self.audit_operation_command_with_route(
            handle,
            caller,
            b"audit-intent",
            ConfigMutationIntent::ManagementAudit(Box::new(AuditCommand::Intent(handle.clone()))),
            true,
            ownership,
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
        if &admitted.handle != prepared.handle() {
            return AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch);
        }
        let ownership = match prepared
            .begin_submission(&self.inner.preparation_admission, self.capacity_profile())
        {
            Ok(ownership) => ownership,
            Err(error) => return AuditAdmission::Rejected(error),
        };
        if prepared
            .verify_effect(self.inner.backend.audit_key())
            .is_err()
        {
            return AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch);
        }
        self.audit_operation_command_with_route(
            prepared.handle(),
            caller,
            b"audit-config",
            ConfigMutationIntent::AuditedMutation(prepared.command().clone()),
            true,
            ownership,
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
        let ownership = match self.reserve_submission() {
            Ok(ownership) => ownership,
            Err(_) => return AuditAdmission::Rejected(AuditAuthorityError::Unavailable),
        };
        self.audit_operation_command_with_route(handle, caller, purpose, command, false, ownership)
            .await
    }

    async fn audit_operation_command_with_route(
        &self,
        handle: &AuditOperationHandle,
        caller: AuditCaller,
        purpose: &[u8],
        command: ConfigMutationIntent,
        local_only: bool,
        ownership: SubmissionOwnership,
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
            self.submit_owned_request_on_local_leader(request, command, ownership)
                .await
        } else {
            self.submit_owned_request(request, command, ownership).await
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
