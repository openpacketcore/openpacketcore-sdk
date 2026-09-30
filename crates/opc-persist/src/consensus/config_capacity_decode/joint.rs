//! Exact wire10/native8 writable-Running input. Old decoders stay closed.
//! Fixed management records reuse their canonical types; action-16 fields use
//! the existing strict bounded payload visitors. No decoded value owns a slot.

use crate::audit_authority::continuity::{AuditCheckpoint, AuditKeyTransition};
use crate::audit_authority::{AuditLedgerLimits, AuditOperationHandle, AuditToken};
use crate::consensus::audit::AuditCommand;
use crate::consensus::audit_mutation::{joint_running, TargetAuditCommandV1};
use crate::consensus::ConfigMutationIntent;
use serde::{Deserialize, Deserializer};

// Reject unsupported discriminants before consuming their owned payloads.
#[derive(Debug)]
pub(in crate::consensus) enum Unsupported {}
impl<'de> Deserialize<'de> for Unsupported {
    fn deserialize<D: Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        Err(serde::de::Error::custom(
            "unsupported bounded Running command",
        ))
    }
}

#[derive(Deserialize)]
#[serde(rename = "TargetAuditCommandV1", rename_all = "kebab-case")]
pub(in crate::consensus) enum Target {
    Admit(joint_running::NativeReceived),
    Apply(joint_running::NativeReceived),
    EmptyCommit(Unsupported),
    RetireCleanup(joint_running::NativeReceived),
}
impl From<Target> for TargetAuditCommandV1 {
    fn from(value: Target) -> Self {
        match value {
            Target::Admit(value) => Self::Admit(value.0),
            Target::Apply(value) => Self::Apply(value.0),
            Target::RetireCleanup(value) => Self::RetireCleanup(value.0),
            Target::EmptyCommit(value) => match value {},
        }
    }
}

#[derive(Deserialize)]
#[serde(
    rename = "AuditCommand",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(in crate::consensus) enum Management {
    Initialize {
        projection: AuditToken,
        limits: AuditLedgerLimits,
    },
    Intent(AuditOperationHandle),
    Reject(AuditOperationHandle),
    Terminal(AuditOperationHandle),
    InitializeWithContinuity {
        projection: AuditToken,
        limits: AuditLedgerLimits,
        initial_epoch: u64,
    },
    Transition(AuditKeyTransition),
    Checkpoint(AuditCheckpoint),
    Prune {
        through: u64,
        checkpoint: AuditCheckpoint,
    },
    AcknowledgeExport(AuditCheckpoint),
    NetconfTarget(Box<Target>),
}
impl From<Management> for AuditCommand {
    fn from(value: Management) -> Self {
        match value {
            Management::Initialize { projection, limits } => {
                Self::Initialize { projection, limits }
            }
            Management::Intent(value) => Self::Intent(value),
            Management::Reject(value) => Self::Reject(value),
            Management::Terminal(value) => Self::Terminal(value),
            Management::InitializeWithContinuity {
                projection,
                limits,
                initial_epoch,
            } => Self::InitializeWithContinuity {
                projection,
                limits,
                initial_epoch,
            },
            Management::Transition(value) => Self::Transition(value),
            Management::Checkpoint(value) => Self::Checkpoint(value),
            Management::Prune {
                through,
                checkpoint,
            } => Self::Prune {
                through,
                checkpoint,
            },
            Management::AcknowledgeExport(value) => Self::AcknowledgeExport(value),
            Management::NetconfTarget(value) => Self::NetconfTarget(Box::new((*value).into())),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename = "ConfigMutationIntent")]
pub(in crate::consensus) enum Intent {
    AppendCommit(Unsupported),
    MarkConfirmed(Unsupported),
    CreateRollbackPoint(Unsupported),
    ResolveConfirmedAndAppend(Unsupported),
    ClearRecoveryRequired { tx_id: opc_types::TxId },
    RetainHistory(Unsupported),
    ManagementAudit(Box<Management>),
    AuditedMutation(Unsupported),
    BoundedAppend(Unsupported),
}
impl From<Intent> for ConfigMutationIntent {
    fn from(value: Intent) -> Self {
        match value {
            Intent::ManagementAudit(value) => Self::ManagementAudit(Box::new((*value).into())),
            Intent::ClearRecoveryRequired { tx_id } => Self::ClearRecoveryRequired { tx_id },
            Intent::AppendCommit(value)
            | Intent::MarkConfirmed(value)
            | Intent::CreateRollbackPoint(value)
            | Intent::ResolveConfirmedAndAppend(value)
            | Intent::RetainHistory(value)
            | Intent::AuditedMutation(value)
            | Intent::BoundedAppend(value) => match value {},
        }
    }
}

pub(in crate::consensus) fn allows(intent: &ConfigMutationIntent) -> bool {
    match intent {
        // Publication acknowledgement is checked against the exact retained
        // Running outcome and its completed checkpoint inside native apply.
        ConfigMutationIntent::ClearRecoveryRequired { .. } => true,
        ConfigMutationIntent::ManagementAudit(audit) => match audit.as_ref() {
            AuditCommand::NetconfTarget(target) => match target.as_ref() {
                TargetAuditCommandV1::Admit(command) | TargetAuditCommandV1::Apply(command) => {
                    joint_running::allows_native(command)
                }
                TargetAuditCommandV1::RetireCleanup(command) => {
                    joint_running::allows_native(command)
                        && u8::from(command.effect.action) == 13
                        && matches!(
                            command.effect.resolution,
                            Some(
                                crate::consensus::audit_mutation::TargetResolutionV1::EndSession { .. }
                            )
                        )
                }
                _ => false,
            },
            AuditCommand::Intent(handle) => handle.body.mutation.is_none(),
            _ => true,
        },
        _ => false,
    }
}
