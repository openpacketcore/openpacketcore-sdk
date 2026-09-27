//! Simultaneous command owners admitted before routing or output allocation.
//!
//! This accounts concrete command buffers, including the independent recovery
//! and native JSON outputs. It is a necessary part of the operation bound;
//! parser temporaries and replication/transport occupancy are qualified
//! separately. It does not establish a whole-process RSS bound.

use std::mem::size_of;

use super::{ConfigMutationIntent, EncodingSizes, ForwardMutationRejection};
use crate::consensus::audit_mutation::{AuditedConfigEffect, AuditedMutationFields};
use crate::consensus::PreparedConfigCommit;
use crate::AuditRecord;

pub(super) const OPERATION_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct CommandBuffers {
    resident: usize,
    copied: usize,
    encryption_alias: usize,
    forwarded: usize,
    native_json: usize,
    recovery_json: usize,
}

fn add(total: &mut usize, bytes: usize) -> Result<(), ForwardMutationRejection> {
    *total = total
        .checked_add(bytes)
        .ok_or(ForwardMutationRejection::CommandTooLarge)?;
    Ok(())
}

fn record_owners(
    commit: &PreparedConfigCommit,
    compact_copy: bool,
) -> Result<usize, ForwardMutationRejection> {
    let mut bytes = size_of::<PreparedConfigCommit>();
    let extent = |length, capacity| if compact_copy { length } else { capacity };
    let record = &commit.record;
    add(
        &mut bytes,
        extent(record.principal.len(), record.principal.capacity()),
    )?;
    add(
        &mut bytes,
        extent(
            record.encrypted_blob.len(),
            record.encrypted_blob.capacity(),
        ),
    )?;
    add(
        &mut bytes,
        extent(
            record.plaintext_digest.len(),
            record.plaintext_digest.capacity(),
        ),
    )?;
    add(
        &mut bytes,
        extent(commit.audit.len(), commit.audit.capacity())
            .checked_mul(size_of::<AuditRecord>())
            .ok_or(ForwardMutationRejection::CommandTooLarge)?,
    )?;
    for entry in &commit.audit {
        add(
            &mut bytes,
            extent(entry.yang_path.len(), entry.yang_path.capacity()),
        )?;
        for value in [&entry.previous_value, &entry.new_value]
            .into_iter()
            .flatten()
        {
            add(&mut bytes, extent(value.len(), value.capacity()))?;
        }
    }
    Ok(bytes)
}

impl CommandBuffers {
    pub(super) fn for_command(
        intent: &ConfigMutationIntent,
        sizes: &EncodingSizes,
    ) -> Result<Self, ForwardMutationRejection> {
        let mut buffers = Self {
            resident: size_of::<ConfigMutationIntent>(),
            // The routing request moves its copy into the engine. For audited
            // commands routing shares the Arc; applying the effect can create
            // the one equivalent compact record copy instead.
            copied: size_of::<ConfigMutationIntent>(),
            forwarded: sizes.forwarded,
            native_json: sizes.durable_json,
            recovery_json: sizes.recovery_json,
            ..Self::default()
        };
        let (commit, label) = match intent {
            ConfigMutationIntent::AppendCommit(commit)
            | ConfigMutationIntent::ResolveConfirmedAndAppend { commit, .. }
            | ConfigMutationIntent::BoundedAppend { commit, .. } => (Some(commit.as_ref()), None),
            ConfigMutationIntent::AuditedMutation(prepared) => {
                add(&mut buffers.resident, size_of::<AuditedMutationFields>())?;
                add(&mut buffers.resident, 2 * size_of::<usize>())?;
                match &prepared.effect {
                    AuditedConfigEffect::Append { commit, .. }
                    | AuditedConfigEffect::BoundedAppend { commit, .. } => {
                        (Some(commit.as_ref()), None)
                    }
                    AuditedConfigEffect::RollbackPoint { label, .. } => (None, label.as_ref()),
                    AuditedConfigEffect::Confirm { .. } => (None, None),
                }
            }
            ConfigMutationIntent::CreateRollbackPoint { label, .. } => (None, label.as_ref()),
            ConfigMutationIntent::ManagementAudit(_) => {
                // The closed management command owns fixed-size projected
                // values; its boxed allocation still belongs in the count.
                let bytes = size_of::<crate::consensus::audit::AuditCommand>();
                add(&mut buffers.resident, bytes)?;
                add(&mut buffers.copied, bytes)?;
                (None, None)
            }
            _ => (None, None),
        };
        if let Some(commit) = commit {
            add(&mut buffers.resident, record_owners(commit, false)?)?;
            add(&mut buffers.copied, record_owners(commit, true)?)?;
            // Fresh encryption aliases may outlive claim transfer. They share
            // one exact Arc<[u8]> extent, independently of record Vec capacity.
            buffers.encryption_alias = commit.record.encrypted_blob.len();
            add(&mut buffers.encryption_alias, 2 * size_of::<usize>())?;
        }
        if let Some(label) = label {
            add(&mut buffers.resident, label.0.capacity())?;
            add(&mut buffers.copied, label.0.len())?;
        }
        Ok(buffers)
    }

    pub(super) fn total(&self) -> Result<usize, ForwardMutationRejection> {
        let mut total = 0;
        for bytes in [
            self.resident,
            self.copied,
            self.encryption_alias,
            self.forwarded,
            self.native_json,
            self.recovery_json,
        ] {
            add(&mut total, bytes)?;
        }
        Ok(total)
    }
}

pub(super) fn preflight(
    intent: &ConfigMutationIntent,
    sizes: &EncodingSizes,
) -> Result<(), ForwardMutationRejection> {
    let buffers = CommandBuffers::for_command(intent, sizes)?;
    if buffers.total()? > OPERATION_BYTES {
        return Err(ForwardMutationRejection::CommandTooLarge);
    }
    Ok(())
}
