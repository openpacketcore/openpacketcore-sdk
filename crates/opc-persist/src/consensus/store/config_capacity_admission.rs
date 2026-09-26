//! Allocation-free encoding admission for the opt-in capacity profile.
//!
//! The borrowed shapes below mirror the pinned engine and configuration wire
//! serializers. Tests compare their bytes with the real owned DTOs. This is
//! encoding admission, not permission to open an unqualified store profile or
//! a whole-operation memory bound.

use std::io::{self, Write};

use opc_consensus::engine::{CommittedLeaderId, LogId, Vote};
use opc_consensus::{ConsensusNodeId, CONSENSUS_MAX_RPC_PAYLOAD_BYTES, CONSENSUS_NODE_ID_MAX};
use opc_crypto::ConfigCapacityProfile;
use serde::{Serialize, Serializer};

use super::{
    config_command_encoded_size, config_command_revision, config_wire_revision,
    ConfigConsensusCommandSizeProbe, ConfigMutationIntent, ConfigPeerCompatibility,
    ForwardMutationRejection, ForwardedBudget, MAX_FORWARDED_BUDGET,
};

const CONFIG_CAPACITY_V1_COMMAND_BYTES: usize = 1_966_080;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct EncodingSizes {
    command: usize,
    forwarded: usize,
    singleton: usize,
    durable_json: usize,
    recovery_json: usize,
}

mod config_capacity_command_buffers;

// EntryPayload's pinned Normal variant is index 1. A newtype serializer avoids
// cloning the command merely to wrap it in an owned engine Entry.
struct BorrowedNormal<'a, T>(&'a T);

impl<T: Serialize> Serialize for BorrowedNormal<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_newtype_variant("EntryPayload", 1, "Normal", self.0)
    }
}

#[derive(Serialize)]
struct BorrowedEntry<'a, T: Serialize> {
    log_id: LogId<ConsensusNodeId>,
    payload: BorrowedNormal<'a, T>,
}

#[derive(Serialize)]
struct BorrowedAppend<'a, T: Serialize> {
    vote: Vote<ConsensusNodeId>,
    prev_log_id: Option<LogId<ConsensusNodeId>>,
    entries: &'a [BorrowedEntry<'a, T>],
    leader_commit: Option<LogId<ConsensusNodeId>>,
}

#[derive(Serialize)]
struct BorrowedForward<'a> {
    request_id: opc_consensus::ConsensusRequestId,
    intent: &'a ConfigMutationIntent,
    compatibility: ConfigPeerCompatibility,
    budget: ForwardedBudget,
}

#[derive(Serialize)]
struct BorrowedWire<'a, T> {
    revision: u16,
    value: &'a T,
}

fn postcard_size<T: Serialize>(value: &T, limit: usize) -> Result<usize, ForwardMutationRejection> {
    let bytes =
        config_command_encoded_size(value).map_err(|_| ForwardMutationRejection::InvalidCommand)?;
    if bytes > limit {
        return Err(ForwardMutationRejection::CommandTooLarge);
    }
    Ok(bytes)
}

// A bounded counting sink never retains the rejected JSON output. In
// particular, byte-array expansion and escaped strings are counted by the
// actual serde_json serializer instead of an assumed expansion multiplier.
struct JsonSize {
    bytes: usize,
    limit: usize,
    exceeded: bool,
}

impl Write for JsonSize {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let bytes = self.bytes.checked_add(input.len());
        if let Some(bytes) = bytes.filter(|bytes| *bytes <= self.limit) {
            self.bytes = bytes;
            Ok(input.len())
        } else {
            self.exceeded = true;
            Err(io::Error::from(io::ErrorKind::InvalidInput))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn json_size<T: Serialize>(value: &T, limit: usize) -> Result<usize, ForwardMutationRejection> {
    let mut sink = JsonSize {
        bytes: 0,
        limit,
        exceeded: false,
    };
    match crate::consensus::config_capacity_json::to_writer(&mut sink, value) {
        Ok(()) => Ok(sink.bytes),
        Err(_) if sink.exceeded => Err(ForwardMutationRejection::CommandTooLarge),
        Err(_) => Err(ForwardMutationRejection::InvalidCommand),
    }
}

pub(super) fn preflight(
    command: &ConfigConsensusCommandSizeProbe<'_>,
    profile: ConfigCapacityProfile,
) -> Result<EncodingSizes, ForwardMutationRejection> {
    if profile != ConfigCapacityProfile::BoundedV1 {
        return Err(ForwardMutationRejection::InvalidCommand);
    }
    let command_bytes = postcard_size(command, CONFIG_CAPACITY_V1_COMMAND_BYTES)?;
    if !command.intent.metadata_fits_profile(command_bytes, profile) {
        return Err(ForwardMutationRejection::CommandTooLarge);
    }

    let forward = BorrowedForward {
        request_id: command.request_id,
        intent: command.intent,
        compatibility: ConfigPeerCompatibility {
            wire_version: config_wire_revision(profile),
            command_version: config_command_revision(profile),
            audit_key_epoch: u64::MAX,
            audit_key_fingerprint: [u8::MAX; 32],
        },
        budget: ForwardedBudget {
            remaining_nanos: u64::try_from(MAX_FORWARDED_BUDGET.as_nanos())
                .map_err(|_| ForwardMutationRejection::InvalidCommand)?,
        },
    };
    let forwarded = postcard_size(
        &BorrowedWire {
            revision: config_wire_revision(profile),
            value: &forward,
        },
        CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
    )?;

    let node = ConsensusNodeId::new(CONSENSUS_NODE_ID_MAX)
        .map_err(|_| ForwardMutationRejection::InvalidCommand)?;
    // u64::MAX is a conservative bound for both fields, including storage
    // profiles whose signed SQL representation admits a smaller maximum.
    let log_id = LogId::new(CommittedLeaderId::new(u64::MAX, node), u64::MAX);
    let entries = [BorrowedEntry {
        log_id,
        payload: BorrowedNormal(command),
    }];
    let append = BorrowedAppend {
        vote: Vote::new_committed(u64::MAX, node),
        prev_log_id: Some(log_id),
        entries: &entries,
        leader_commit: Some(log_id),
    };
    let singleton = postcard_size(
        &BorrowedWire {
            revision: config_wire_revision(profile),
            value: &append,
        },
        CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
    )?;
    let durable_json = json_size(
        &entries[0],
        crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES,
    )?;
    // One reserved recovery encoder may run while the same immutable audited
    // value is submitted. Its output and the native JSON output are distinct
    // live allocations; the native entry's limit cannot stand in for both.
    let recovery_json = match command.intent {
        ConfigMutationIntent::AuditedMutation(prepared) => json_size(
            prepared,
            crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES,
        )?,
        _ => 0,
    };
    let sizes = EncodingSizes {
        command: command_bytes,
        forwarded,
        singleton,
        durable_json,
        recovery_json,
    };
    config_capacity_command_buffers::preflight(command.intent, &sizes)?;
    Ok(sizes)
}

#[cfg(test)]
#[path = "config_capacity_encoding_admission_tests.rs"]
mod tests;
