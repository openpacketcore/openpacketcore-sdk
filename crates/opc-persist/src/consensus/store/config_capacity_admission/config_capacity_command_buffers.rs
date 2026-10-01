//! Simultaneous command owners admitted before routing or output allocation.
//!
//! This accounts concrete command buffers, independent recovery output, and
//! the guarded replication representations. Native JSON and replication have
//! separate phase bounds: a batch reads a log only after its append completes.
//! Parser/validation scratch and additional transport copies remain separately
//! qualified owners. This is a necessary admission check, not an RSS bound.

use std::mem::size_of;

use opc_consensus::{CONSENSUS_MAX_RPC_PAYLOAD_BYTES, DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES};
use opc_crypto::CONFIG_CAPACITY_V1_ENVELOPE_BYTES;

use super::{ConfigMutationIntent, EncodingSizes, ForwardMutationRejection};
use crate::consensus::audit_mutation::{AuditedConfigEffect, AuditedMutationFields};
use crate::consensus::types::{CONFIG_CAPACITY_V1_METADATA_BYTES, CONFIG_CONSENSUS_MAX_MEMBERS};
use crate::consensus::{ConfigRaftTypeConfig, PreparedConfigCommit};
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
    replicated: usize,
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

// Native JSON decoding reserves at most the next bounded quantum. Its large
// canonical ciphertext path can reserve less, but never more than this bound.
// Strings reserve their exact lengths. Charge capacities, including unused
// audit slots, rather than assuming that a freshly decoded DTO is compact.
fn decoded_extent(
    length: usize,
    quantum: usize,
    limit: usize,
) -> Result<usize, ForwardMutationRejection> {
    if length > limit {
        return Err(ForwardMutationRejection::CommandTooLarge);
    }
    length
        .checked_add(quantum - 1)
        .map(|rounded| (rounded / quantum * quantum).min(limit))
        .ok_or(ForwardMutationRejection::CommandTooLarge)
}

fn decoded_record_owners(commit: &PreparedConfigCommit) -> Result<usize, ForwardMutationRejection> {
    let mut bytes = record_owners(commit, true)?;
    for (length, quantum, limit, element_bytes) in [
        (
            commit.record.encrypted_blob.len(),
            4 * 1024,
            CONFIG_CAPACITY_V1_ENVELOPE_BYTES,
            1,
        ),
        (commit.record.plaintext_digest.len(), 4 * 1024, 32, 1),
        (
            commit.audit.len(),
            16,
            CONFIG_CAPACITY_V1_METADATA_BYTES / 64,
            size_of::<AuditRecord>(),
        ),
    ] {
        let spare = decoded_extent(length, quantum, limit)? - length;
        add(
            &mut bytes,
            spare
                .checked_mul(element_bytes)
                .ok_or(ForwardMutationRejection::CommandTooLarge)?,
        )?;
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
            // A limited read starts an empty Vec and returns at most this
            // pinned batch limit. Charge its full descriptor backing even
            // when this operation contributes only one entry to the batch.
            replicated: DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES
                .checked_mul(size_of::<opc_consensus::engine::Entry<ConfigRaftTypeConfig>>())
                .ok_or(ForwardMutationRejection::CommandTooLarge)?,
            ..Self::default()
        };
        let (commit, label) = match intent {
            ConfigMutationIntent::AppendCommit(commit)
            | ConfigMutationIntent::ResolveConfirmedAndAppend { commit, .. }
            | ConfigMutationIntent::BoundedAppend { commit, .. } => (Some(commit.as_ref()), None),
            ConfigMutationIntent::AuditedMutation(prepared) => {
                add(&mut buffers.resident, size_of::<AuditedMutationFields>())?;
                add(&mut buffers.resident, 2 * size_of::<usize>())?;
                add(&mut buffers.replicated, size_of::<AuditedMutationFields>())?;
                add(&mut buffers.replicated, 2 * size_of::<usize>())?;
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
                add(&mut buffers.replicated, bytes)?;
                (None, None)
            }
            _ => (None, None),
        };
        if let Some(commit) = commit {
            add(&mut buffers.resident, record_owners(commit, false)?)?;
            add(&mut buffers.copied, record_owners(commit, true)?)?;
            add(&mut buffers.replicated, decoded_record_owners(commit)?)?;
            // Fresh encryption aliases may outlive claim transfer. They share
            // one exact Arc<[u8]> extent, independently of record Vec capacity.
            buffers.encryption_alias = commit.record.encrypted_blob.len();
            add(&mut buffers.encryption_alias, 2 * size_of::<usize>())?;
        }
        if let Some(label) = label {
            add(&mut buffers.resident, label.0.capacity())?;
            add(&mut buffers.copied, label.0.len())?;
            add(&mut buffers.replicated, label.0.len())?;
        }
        Ok(buffers)
    }

    pub(super) fn total(&self) -> Result<usize, ForwardMutationRejection> {
        let mut shared = 0;
        for bytes in [
            self.resident,
            self.copied,
            self.encryption_alias,
            self.recovery_json,
        ] {
            add(&mut shared, bytes)?;
        }
        let mut native = shared;
        add(&mut native, self.forwarded)?;
        add(&mut native, self.native_json)?;

        // The SDK voter set is immutable within an epoch. In the pinned
        // engine's ordinary lifecycle, each remote has one serial log stream;
        // QuitLeader joins retired streams before later leadership starts.
        // This is that source-scoped phase bound, not an unconditional count
        // for arbitrary engine vote responses or replacement generations.
        // The factory guard independently enforces only one typed/wire pair,
        // across all clients, and unlocks after the typed owner physically drops.
        let peers = CONFIG_CONSENSUS_MAX_MEMBERS - 1;
        let wire = CONSENSUS_MAX_RPC_PAYLOAD_BYTES;
        let mut replication = shared;
        add(
            &mut replication,
            peers
                .checked_mul(self.replicated.max(wire))
                .ok_or(ForwardMutationRejection::CommandTooLarge)?,
        )?;
        add(&mut replication, self.replicated.min(wire))?;
        Ok(native.max(replication))
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
