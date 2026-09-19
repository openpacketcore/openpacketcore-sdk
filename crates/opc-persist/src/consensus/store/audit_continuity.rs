use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use super::{
    derive_durable_request_id, ConfigConsensusOpenError, ConsensusConfigStore,
    SystemConfigConsensusClock, DEFAULT_CONFIG_CONSENSUS_OPERATION_TIMEOUT,
};
use crate::audit_authority::continuity::checkpoint::CheckpointBody;
use crate::audit_authority::continuity::*;
use crate::audit_authority::ledger::LedgerState;
use crate::audit_authority::{AuditAuthorityError, AuditCaller};
use crate::consensus::{audit::AuditCommand, ConfigMutationIntent};
use crate::{ConfigConsensusIdentity, ConfigConsensusTopology, SqliteBackend};
use opc_consensus::{ConsensusNodeId, ConsensusPeer};

async fn load_external(
    policy: &AuditContinuityPolicy,
    identity: ConfigConsensusIdentity,
    timeout: Duration,
) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
    tokio::time::timeout(timeout, policy.checkpoints.load(identity))
        .await
        .map_err(|_| AuditAuthorityError::Unavailable)?
}

fn verify_external(
    ledger: &LedgerState,
    keys: &AuditKeyRing,
    external: Option<&AuditCheckpoint>,
) -> Result<(), AuditAuthorityError> {
    let chain = ledger
        .continuity
        .as_ref()
        .ok_or(AuditAuthorityError::Unavailable)?;
    ledger.validate_continuity(Some(keys))?;
    let checkpoint = external.ok_or(AuditAuthorityError::Unavailable)?;
    checkpoint.verify(keys, ledger.identity)?;
    ledger.matches_checkpoint(checkpoint)?;
    if chain.checkpoint.as_ref().is_some_and(|known| {
        known.sequence() > checkpoint.sequence()
            || (known.sequence() == checkpoint.sequence() && known != checkpoint)
    }) {
        return Err(AuditAuthorityError::RollbackDetected);
    }
    Ok(())
}

pub(super) async fn verify_startup(
    backend: &SqliteBackend,
    policy: Option<&AuditContinuityPolicy>,
    identity: ConfigConsensusIdentity,
    timeout: Duration,
) -> Result<(), AuditAuthorityError> {
    // Key attachment is shared by backend clones. It does not carry the
    // external monotonic authority, so an ordinary open cannot reuse it to
    // bypass the explicitly required continuity profile.
    if policy.is_none() && backend.management_audit_keys().is_some() {
        return Err(AuditAuthorityError::BindingMismatch);
    }
    let cloned = backend.clone();
    let ledger = crate::consensus::run_backend_sqlite_with_timeout(
        backend,
        timeout,
        move |conn, cancellation| {
            cancellation.check_io()?;
            crate::consensus::audit::read_with_keys_sync(
                conn,
                cloned.audit_key(),
                cloned.management_audit_keys().as_deref(),
                identity,
            )
        },
    )
    .await
    .map_err(|_| AuditAuthorityError::Unavailable)?;
    let Some(policy) = policy else {
        return if ledger
            .as_ref()
            .is_some_and(|ledger| ledger.continuity.is_some())
        {
            Err(AuditAuthorityError::BindingMismatch)
        } else {
            Ok(())
        };
    };
    let external = load_external(policy, identity, timeout).await?;
    match ledger {
        None if external.is_none() => Ok(()), // explicit pristine provisioning only
        None => Err(AuditAuthorityError::RollbackDetected),
        Some(ledger) => {
            let chain = ledger
                .continuity
                .as_ref()
                .ok_or(AuditAuthorityError::BindingMismatch)?;
            if ledger.sequence == 0 && chain.checkpoint.is_none() && external.is_none() {
                // A crash before first external CAS may resume provisioning. No
                // traffic/mutation readiness exists until that CAS is read back.
                ledger.validate_continuity(Some(&policy.keys))
            } else {
                verify_external(&ledger, &policy.keys, external.as_ref())?;
                let checkpoint = external.as_ref().ok_or(AuditAuthorityError::Unavailable)?;
                // An authenticated prefix may end at an admitted mutation's
                // intent even though a later configuration result was lost by
                // restoring this database. A newly opened owner cannot prove
                // that the previous process never submitted that effect. Do
                // not start the engine and let expiry invent a rejection.
                // Retained authoritative outcomes remain resumable below the
                // latest checkpoint and do not need a terminal record yet.
                if ledger.operations.iter().any(|operation| {
                    operation.handle.body.mutation.is_some()
                        && operation.state == crate::audit_authority::AuditOperationState::Intent
                        && operation.first_sequence <= checkpoint.sequence()
                }) {
                    return Err(AuditAuthorityError::RecoveryRequired);
                }
                Ok(())
            }
        }
    }
}

impl ConsensusConfigStore {
    // Advancing mutation continuity never acknowledges an export. Retention
    // uses the separately committed export receipt below, even at an equal tail.
    pub(super) async fn checkpoint_audit_tail(&self) -> Result<(), AuditAuthorityError> {
        let policy = self
            .inner
            .audit_continuity
            .as_ref()
            .ok_or(AuditAuthorityError::Unavailable)?;
        let ledger = self.read_audit_ledger().await?;
        let chain = ledger
            .continuity
            .as_ref()
            .ok_or(AuditAuthorityError::Unavailable)?;
        if chain
            .checkpoint
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.sequence() == ledger.sequence)
        {
            return Ok(());
        }
        let next = AuditCheckpoint::issue(
            &policy.keys,
            CheckpointBody {
                version: 1,
                identity: self.inner.identity,
                sequence: ledger.sequence,
                root_anchor: ledger.terminal,
                anchor: chain.terminal,
                epoch_at_sequence: chain.active_epoch,
                signing_epoch: chain.active_epoch,
                acknowledged_export: [0; 32],
            },
        )?;
        let current = load_external(policy, self.inner.identity, self.inner.operation_timeout)
            .await?
            .ok_or(AuditAuthorityError::Unavailable)?;
        verify_external(&ledger, &policy.keys, Some(&current))?;
        let checkpoint = if current.sequence() >= next.sequence() {
            current
        } else {
            self.advance_external(&ledger, Some(current), next).await?
        };
        self.audit_maintenance(AuditCommand::Checkpoint(checkpoint))
            .await
    }

    /// Open with required, separate management signing and external monotonic
    /// checkpoint providers. Existing continuity state cannot be opened through
    /// the ordinary constructor or reset by a different initial epoch. A stale
    /// local restore behind the external mark is refused before the engine starts.
    /// A checkpointed mutation intent without a retained outcome is also refused:
    /// the new owner cannot distinguish an unsubmitted effect from a lost commit
    /// suffix. Recover authoritative state explicitly; expiry cannot repair it.
    pub async fn open_with_audit_continuity(
        topology: ConfigConsensusTopology,
        backend: SqliteBackend,
        snapshot_dir: impl Into<PathBuf>,
        peers: BTreeMap<ConsensusNodeId, Arc<dyn ConsensusPeer>>,
        policy: AuditContinuityPolicy,
    ) -> Result<Self, ConfigConsensusOpenError> {
        Self::open_internal(
            topology,
            backend,
            snapshot_dir.into(),
            peers,
            Arc::new(SystemConfigConsensusClock),
            DEFAULT_CONFIG_CONSENSUS_OPERATION_TIMEOUT,
            None,
            Some(Arc::new(policy)),
        )
        .await
    }

    pub(super) async fn verify_audit_checkpoint(
        &self,
        ledger: &LedgerState,
    ) -> Result<(), AuditAuthorityError> {
        match &self.inner.audit_continuity {
            None if ledger.continuity.is_none() => Ok(()),
            None => Err(AuditAuthorityError::KeyUnavailable),
            Some(policy) => {
                let external =
                    load_external(policy, self.inner.identity, self.inner.operation_timeout)
                        .await?;
                verify_external(ledger, &policy.keys, external.as_ref())
            }
        }
    }

    pub(super) async fn provision_audit_checkpoint(&self) -> Result<(), AuditAuthorityError> {
        let policy = self
            .inner
            .audit_continuity
            .as_ref()
            .ok_or(AuditAuthorityError::Unavailable)?;
        let ledger = self.read_audit_ledger_without_checkpoint().await?;
        let external =
            load_external(policy, self.inner.identity, self.inner.operation_timeout).await?;
        let next = match external {
            Some(checkpoint) => {
                verify_external(&ledger, &policy.keys, Some(&checkpoint))?;
                checkpoint
            }
            None => {
                let chain = ledger
                    .continuity
                    .as_ref()
                    .ok_or(AuditAuthorityError::Unavailable)?;
                if ledger.sequence != 0 || chain.checkpoint.is_some() {
                    return Err(AuditAuthorityError::RollbackDetected);
                }
                let next = AuditCheckpoint::issue(
                    &policy.keys,
                    CheckpointBody {
                        version: 1,
                        identity: ledger.identity,
                        sequence: 0,
                        root_anchor: ledger.terminal,
                        anchor: chain.terminal,
                        epoch_at_sequence: chain.active_epoch,
                        signing_epoch: chain.active_epoch,
                        acknowledged_export: [0; 32],
                    },
                )?;
                self.advance_external(&ledger, None, next).await?
            }
        };
        self.audit_maintenance(AuditCommand::Checkpoint(next)).await
    }

    async fn advance_external(
        &self,
        ledger: &LedgerState,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpoint, AuditAuthorityError> {
        let policy = self
            .inner
            .audit_continuity
            .as_ref()
            .ok_or(AuditAuthorityError::Unavailable)?;
        // Even Applied is independently read back. Timeout, cancellation or a
        // transport error cannot be interpreted as a failed/nonexistent CAS.
        let _outcome = tokio::time::timeout(
            self.inner.operation_timeout,
            policy
                .checkpoints
                .compare_advance(self.inner.identity, expected, next.clone()),
        )
        .await;
        let current = load_external(policy, self.inner.identity, self.inner.operation_timeout)
            .await?
            .ok_or(AuditAuthorityError::Unavailable)?;
        current.verify(&policy.keys, self.inner.identity)?;
        ledger.matches_checkpoint(&current)?;
        if current.sequence() < next.sequence()
            || (current.sequence() == next.sequence() && current != next)
        {
            return Err(AuditAuthorityError::Unavailable);
        }
        Ok(current)
    }

    /// Prepare a cross-signed transition against the exact current prefix. No
    /// state changes here. Mount overlapping keys on every voter before calling.
    pub async fn prepare_audit_key_transition(
        &self,
        next_epoch: u64,
    ) -> Result<AuditKeyTransition, AuditAuthorityError> {
        let ledger = self.read_audit_ledger().await?;
        let policy = self
            .inner
            .audit_continuity
            .as_ref()
            .ok_or(AuditAuthorityError::Unavailable)?;
        let chain = ledger
            .continuity
            .as_ref()
            .ok_or(AuditAuthorityError::Unavailable)?;
        AuditKeyTransition::prepare(
            &policy.keys,
            self.inner.identity,
            ledger.sequence,
            chain.terminal,
            chain.active_epoch,
            next_epoch,
        )
    }

    /// Activate through consensus. An unavailable result after submission is
    /// indeterminate; retain and retry this exact transition. Another entry at
    /// the prepared prefix conflicts, rather than silently rebasing the proof.
    pub async fn activate_audit_key_transition(
        &self,
        transition: &AuditKeyTransition,
    ) -> Result<(), AuditAuthorityError> {
        self.read_audit_ledger().await?;
        self.audit_maintenance(AuditCommand::Transition(transition.clone()))
            .await
    }

    /// Freeze exactly the complete currently retained range for an authorized
    /// recipient. An older expected floor returns `Pruned`; a future floor is
    /// invalid. The SDK never silently advances an old export request.
    pub async fn freeze_audit_export(
        &self,
        recipient: AuditCaller,
        expected_floor: u64,
        lifetime: Duration,
    ) -> Result<AuditExportSession, AuditAuthorityError> {
        if lifetime.subsec_nanos() != 0 {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let policy = self
            .inner
            .audit_continuity
            .as_ref()
            .ok_or(AuditAuthorityError::Unavailable)?;
        let permit = policy
            .exports
            .clone()
            .try_acquire_owned()
            .map_err(|_| AuditAuthorityError::Full)?;
        let ledger = self.read_audit_ledger().await?;
        if expected_floor < ledger.floor {
            return Err(AuditAuthorityError::Pruned);
        }
        if expected_floor > ledger.floor {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let now = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        AuditExportSession::freeze(
            &ledger,
            policy.keys.clone(),
            recipient,
            now,
            lifetime.as_secs(),
            permit,
        )
    }

    /// Acknowledge a fully verified export, advance/read back the external
    /// checkpoint, and record that exact acknowledgement in consensus. Caller
    /// authentication and permission to acknowledge remain application policy.
    /// No pruning authority is returned on an uncertain external or local write.
    pub async fn acknowledge_audit_export(
        &self,
        export: &VerifiedAuditExport,
        recipient: AuditCaller,
    ) -> Result<(), AuditAuthorityError> {
        let policy = self
            .inner
            .audit_continuity
            .as_ref()
            .ok_or(AuditAuthorityError::Unavailable)?;
        let now = self
            .inner
            .clock
            .now_utc()
            .as_offset_datetime()
            .unix_timestamp();
        export
            .manifest
            .verify(&policy.keys, self.inner.identity, recipient, now)?;
        let ledger = self.read_audit_ledger().await?;
        let chain = ledger
            .continuity
            .as_ref()
            .ok_or(AuditAuthorityError::Unavailable)?;
        let manifest = &export.manifest;
        let next = AuditCheckpoint::issue(
            &policy.keys,
            CheckpointBody {
                version: 1,
                identity: self.inner.identity,
                sequence: manifest.body.sequence,
                root_anchor: manifest.body.terminal,
                anchor: manifest.body.anchor,
                epoch_at_sequence: manifest.body.active_epoch,
                signing_epoch: chain.active_epoch,
                acknowledged_export: manifest.mac,
            },
        )?;
        ledger.matches_checkpoint(&next)?;
        let current = load_external(policy, self.inner.identity, self.inner.operation_timeout)
            .await?
            .ok_or(AuditAuthorityError::Unavailable)?;
        verify_external(&ledger, &policy.keys, Some(&current))?;
        let checkpoint = if current.sequence() >= next.sequence() {
            current
        } else {
            self.advance_external(&ledger, Some(current), next.clone())
                .await?
        };
        self.audit_maintenance(AuditCommand::Checkpoint(checkpoint))
            .await?;
        self.audit_maintenance(AuditCommand::AcknowledgeExport(next))
            .await
    }

    /// Remove an exact acknowledged prefix, only when every included operation
    /// is terminal and expired, no operation straddles the cut, and the external
    /// checkpoint is still proven. Exhaustion never triggers automatic data loss.
    pub async fn retain_audit_history_through(
        &self,
        through: u64,
    ) -> Result<(), AuditAuthorityError> {
        let ledger = self.read_audit_ledger().await?;
        let checkpoint = ledger
            .continuity
            .as_ref()
            .and_then(|chain| chain.export_checkpoint.clone())
            .ok_or(AuditAuthorityError::Unavailable)?;
        if through > checkpoint.sequence() {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        self.audit_maintenance(AuditCommand::Prune {
            through,
            checkpoint,
        })
        .await
    }

    async fn audit_maintenance(&self, command: AuditCommand) -> Result<(), AuditAuthorityError> {
        // The operation's exact transition/checkpoint/prefix is its durable
        // idempotency authority in the ledger. Each invocation is a new attempt:
        // a cached rejection (for example, a not-yet-expired retained handle)
        // must not permanently reject the same prefix after it becomes eligible.
        // Unknown outcomes are safe to retry only with that same exact intent;
        // apply validates the current ledger and cannot activate twice, regress a
        // checkpoint or remove anything beyond the requested prefix. This does
        // not change configuration-mutation or operation-handle retry identity.
        let encoded = serde_json::to_vec(&(&command, uuid::Uuid::new_v4()))
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        let request = derive_durable_request_id(self.inner.identity, b"audit-continuity", &encoded);
        self.submit_request(request, ConfigMutationIntent::ManagementAudit(command))
            .await
            .map_err(|_| AuditAuthorityError::Unavailable)?
            .result
            .map_err(crate::consensus::audit::map_failure)
    }
}
